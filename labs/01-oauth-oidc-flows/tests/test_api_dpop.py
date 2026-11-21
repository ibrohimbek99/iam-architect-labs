import pytest
from fastapi.testclient import TestClient
from iam_shared import JwksCache, TokenValidator
from iam_shared.dpop import DpopKey
from iam_shared.testing import FakeIssuer
from lab01.api import create_app

API = "contoso-accounts-api"
URL = "http://testserver/accounts/summary"


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer()


@pytest.fixture
def client(issuer: FakeIssuer) -> TestClient:
    validator = TokenValidator(issuer=issuer.issuer, audience=API, jwks=JwksCache(issuer.jwks))
    return TestClient(create_app(validator))


@pytest.fixture
def key() -> DpopKey:
    return DpopKey()


def _bound_token(issuer: FakeIssuer, key: DpopKey) -> str:
    return issuer.mint(cnf={"jkt": key.thumbprint})


def test_dpop_bound_token_with_valid_proof(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = _bound_token(issuer, key)
    headers = {"Authorization": f"DPoP {token}", "DPoP": key.proof("GET", URL, access_token=token)}
    assert client.get("/accounts/summary", headers=headers).status_code == 200


def test_bound_token_downgraded_to_bearer_is_rejected(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = _bound_token(issuer, key)
    response = client.get("/accounts/summary", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'DPoP error="invalid_token"'


def test_bound_token_without_proof_is_rejected(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = _bound_token(issuer, key)
    response = client.get("/accounts/summary", headers={"Authorization": f"DPoP {token}"})
    assert response.status_code == 401
    assert 'error="invalid_dpop_proof"' in response.headers["www-authenticate"]


def test_stolen_token_with_thiefs_key_is_rejected(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = _bound_token(issuer, key)
    thief = DpopKey()
    headers = {
        "Authorization": f"DPoP {token}",
        "DPoP": thief.proof("GET", URL, access_token=token),
    }
    assert client.get("/accounts/summary", headers=headers).status_code == 401


def test_replayed_request_is_rejected(client: TestClient, issuer: FakeIssuer, key: DpopKey) -> None:
    token = _bound_token(issuer, key)
    headers = {"Authorization": f"DPoP {token}", "DPoP": key.proof("GET", URL, access_token=token)}
    assert client.get("/accounts/summary", headers=headers).status_code == 200
    assert client.get("/accounts/summary", headers=headers).status_code == 401


def test_proof_for_another_endpoint_is_rejected(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = _bound_token(issuer, key)
    proof = key.proof("GET", "http://testserver/whoami", access_token=token)
    headers = {"Authorization": f"DPoP {token}", "DPoP": proof}
    assert client.get("/accounts/summary", headers=headers).status_code == 401


def test_dpop_scheme_with_unbound_token_is_rejected(
    client: TestClient, issuer: FakeIssuer, key: DpopKey
) -> None:
    token = issuer.mint()  # no cnf.jkt
    headers = {"Authorization": f"DPoP {token}", "DPoP": key.proof("GET", URL, access_token=token)}
    assert client.get("/accounts/summary", headers=headers).status_code == 401


def test_plain_bearer_tokens_still_work(client: TestClient, issuer: FakeIssuer) -> None:
    response = client.get("/accounts/summary", headers={"Authorization": f"Bearer {issuer.mint()}"})
    assert response.status_code == 200
