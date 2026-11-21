import json
from datetime import UTC, datetime

from iam_shared.audit import (
    MAX_ACT_DEPTH,
    REDACTED,
    AuditEvent,
    Decision,
    actor_chain_from_claims,
    redact,
)


def _fake_jwt() -> str:
    # Built at runtime so no JWT-shaped literal sits in the repo for secret scanners to flag.
    return ".".join(["eyJ" + "a" * 12, "b" * 12, "c" * 12])


def test_redacts_sensitive_keys_at_any_depth() -> None:
    data = {
        "client_id": "contoso-agent-7",
        "Authorization": "Bearer abc",
        "nested": {"refresh_token": "r1", "scopes": ["accounts:read"]},
        "items": [{"client_secret": "s1"}],
    }
    out = redact(data)
    assert out["client_id"] == "contoso-agent-7"
    assert out["Authorization"] == REDACTED
    assert out["nested"]["refresh_token"] == REDACTED
    assert out["nested"]["scopes"] == ["accounts:read"]
    assert out["items"][0]["client_secret"] == REDACTED


def test_redacts_jwt_shaped_strings_in_free_text() -> None:
    text = f"upstream rejected {_fake_jwt()} as expired"
    assert redact(text) == f"upstream rejected {REDACTED} as expired"


def test_leaves_ordinary_values_alone() -> None:
    assert redact({"amount": 500, "ok": True, "note": "eyJ is not a token"}) == {
        "amount": 500,
        "ok": True,
        "note": "eyJ is not a token",
    }


def test_json_line_is_redacted_and_utc() -> None:
    event = AuditEvent(
        action="tool.call",
        subject="alice@contoso.example",
        actor_chain=["agent:dispute-helper"],
        resource="mcp:get_account_summary",
        decision=Decision.DENY,
        reason=f"token {_fake_jwt()} missing scope",
        attributes={"access_token": "x", "scope": "accounts:read"},
    )
    data = json.loads(event.to_json_line())
    assert data["decision"] == "deny"
    assert data["attributes"] == {"access_token": REDACTED, "scope": "accounts:read"}
    assert REDACTED in data["reason"]
    parsed = datetime.fromisoformat(data["timestamp"])
    assert parsed.utcoffset() == UTC.utcoffset(None)


def test_actor_chain_follows_nested_act() -> None:
    claims = {
        "sub": "alice@contoso.example",
        "act": {"sub": "agent:sub-agent", "act": {"sub": "agent:dispute-helper"}},
    }
    assert actor_chain_from_claims(claims) == ["agent:sub-agent", "agent:dispute-helper"]


def test_actor_chain_without_act_is_empty() -> None:
    assert actor_chain_from_claims({"sub": "alice@contoso.example"}) == []


def test_actor_chain_depth_is_capped() -> None:
    act: dict[str, object] = {"sub": "agent:last"}
    for i in range(MAX_ACT_DEPTH + 5):
        act = {"sub": f"agent:{i}", "act": act}
    assert len(actor_chain_from_claims({"act": act})) == MAX_ACT_DEPTH
