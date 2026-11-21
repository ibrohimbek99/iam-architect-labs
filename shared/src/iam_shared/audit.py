"""Structured audit events shared by every lab.

Every security decision in these labs (a token issued, a tool call allowed or
denied, access elevated, a credential rotated) emits one AuditEvent as a JSON
line. Redaction happens here, centrally, so that no lab can accidentally write
a token or secret to a log.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

REDACTED = "[REDACTED]"

# Values under these keys are never logged. Matched case-insensitively as
# substrings, so "access_token", "client_secret" and "Authorization" all hit.
SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "cookie",
    "assertion",
)

# Shape of a compact JWS/JWT: three base64url segments joined by dots. Matching
# the shape (not just the key name) catches tokens pasted into free text.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

# RFC 8693 lets `act` claims nest without limit. Cap the walk so a hostile token
# can't make audit logging loop or blow the stack.
MAX_ACT_DEPTH = 10


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


class AuditEvent(BaseModel):
    """One security-relevant decision."""

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    action: str  # e.g. "token.exchange", "tool.call", "access.elevate"
    subject: str  # who the action is ultimately for (the `sub` claim)
    actor_chain: list[str] = Field(default_factory=list)  # current actor first
    resource: str
    decision: Decision
    reason: str = ""
    correlation_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    def to_json_line(self) -> str:
        """Serialize as one redacted JSON line, ready for an append-only log."""
        data = self.model_dump(mode="json")
        data["attributes"] = redact(data["attributes"])
        data["reason"] = redact(data["reason"])
        return json.dumps(data, separators=(",", ":"), sort_keys=True)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact(value: Any) -> Any:
    """Return a copy of ``value`` with secrets masked.

    Masks values under sensitive keys (at any depth) and any JWT-shaped string.
    """
    if isinstance(value, Mapping):
        return {k: (REDACTED if _is_sensitive_key(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _JWT_RE.sub(REDACTED, value)
    return value


def actor_chain_from_claims(claims: Mapping[str, Any]) -> list[str]:
    """Flatten nested RFC 8693 ``act`` claims into ``[current actor, previous actor, ...]``.

    The outermost ``act`` is the party acting right now. Each nested ``act`` is an
    earlier hop in the delegation chain (for example, agent → sub-agent).
    """
    chain: list[str] = []
    act = claims.get("act")
    depth = 0
    while isinstance(act, Mapping) and depth < MAX_ACT_DEPTH:
        sub = act.get("sub")
        if isinstance(sub, str):
            chain.append(sub)
        act = act.get("act")
        depth += 1
    return chain
