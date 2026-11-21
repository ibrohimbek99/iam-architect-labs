"""Test-only helpers: a throwaway issuer that signs tokens with a fresh RSA key.

Never import this from application code. The key lives only in memory for one
test run.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DEFAULT_ISSUER = "http://localhost:8080/realms/contoso"


class FakeIssuer:
    """Mints RS256 tokens and publishes the matching JWKS."""

    def __init__(self, issuer: str = DEFAULT_ISSUER, kid: str | None = None) -> None:
        self.issuer = issuer
        self.kid = kid or uuid.uuid4().hex[:8]
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(RSAAlgorithm.to_jwk(self._key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def mint(
        self,
        *,
        audience: str | list[str] = "contoso-accounts-api",
        subject: str = "alice",
        scope: str | None = "accounts:read",
        lifetime: int = 300,
        headers: dict[str, Any] | None = None,
        **claims: Any,
    ) -> str:
        """Return a signed token. Pass ``claim=None`` to omit a default claim."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + lifetime,
            "scope": scope,
            "azp": "contoso-cli",
            "typ": "Bearer",
            "jti": uuid.uuid4().hex,
        }
        if scope is None:
            payload.pop("scope")
        for name, value in claims.items():
            if value is None:
                payload.pop(name, None)
            else:
                payload[name] = value
        header = {"kid": self.kid, **(headers or {})}
        return jwt.encode(payload, self._key, algorithm="RS256", headers=header)
