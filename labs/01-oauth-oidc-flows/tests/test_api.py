import json
import logging

import pytest
from fastapi.testclient import TestClient
from iam_shared import JwksCache, TokenValidator
from iam_shared.testing import FakeIssuer
from lab01.api import create_app

API = "contoso-accounts-api"


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer()


@pytest.fixture
def client(issuer: FakeIssuer) -> TestClient:
    validator = TokenValidator(issuer=issuer.issuer, audience=API, jwks=JwksCache(issuer.jwks))
    return TestClient(create_app(validator))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_needs_no_token(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_token_is_401_with_challenge(client: TestClient) -> None:
    response = client.get("/accounts/summary")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_invalid_token_is_401_and_reason_not_leaked(client: TestClient, issuer: FakeIssuer) -> None:
    response = client.get("/accounts/summary", headers=_auth(issuer.mint(audience="other-api")))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert "audience" not in response.text  # detailed reason goes to the audit log only


def test_missing_scope_is_403_insufficient_scope(client: TestClient, issuer: FakeIssuer) -> None:
    response = client.post(
        "/transfers",
        headers=_auth(issuer.mint(scope="accounts:read")),
        json={"from_account": "CHK-0001", "to_account": "SAV-0002", "amount": "50.00"},
    )
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]
    assert 'scope="transfers:write"' in response.headers["www-authenticate"]


def test_scoped_token_reads_accounts(client: TestClient, issuer: FakeIssuer) -> None:
    token = issuer.mint(scope="accounts:read", preferred_username="alice")
    response = client.get("/accounts/summary", headers=_auth(token))
    assert response.status_code == 200
    assert response.json()["owner"] == "alice"
    assert len(response.json()["accounts"]) == 2


def test_transfer_with_write_scope_is_accepted(client: TestClient, issuer: FakeIssuer) -> None:
    response = client.post(
        "/transfers",
        headers=_auth(issuer.mint(scope="transfers:write")),
        json={"from_account": "CHK-0001", "to_account": "SAV-0002", "amount": "50.00"},
    )
    assert response.status_code == 202


def test_whoami_shows_delegation_chain(client: TestClient, issuer: FakeIssuer) -> None:
    token = issuer.mint(azp="contoso-gateway", act={"sub": "contoso-gateway"})
    body = client.get("/whoami", headers=_auth(token)).json()
    assert body["sub"] == "alice"
    assert body["client_id"] == "contoso-gateway"
    assert body["actor_chain"] == ["contoso-gateway"]


def test_audit_log_records_decisions_without_tokens(
    client: TestClient, issuer: FakeIssuer, caplog: pytest.LogCaptureFixture
) -> None:
    token = issuer.mint(scope="accounts:read")
    with caplog.at_level(logging.INFO, logger="lab01.audit"):
        client.get("/accounts/summary", headers=_auth(token))
        client.get("/accounts/summary", headers=_auth(issuer.mint(audience="other-api")))
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "lab01.audit"]
    assert [e["decision"] for e in events] == ["allow", "deny"]
    assert events[1]["reason"] == "wrong audience"
    assert all(token not in r.getMessage() for r in caplog.records)
