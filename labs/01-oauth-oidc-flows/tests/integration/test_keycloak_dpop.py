"""DPoP end-to-end against Keycloak (DPoP fully supported since 26.4)."""

import httpx
import pytest
from fastapi.testclient import TestClient
from iam_shared import JwksCache, TokenValidator, http_jwks_fetcher
from iam_shared.dpop import DpopKey
from lab01.api import create_app
from lab01.flows.common import peek_claims
from lab01.settings import Settings, require_env

pytestmark = pytest.mark.integration
API_URL = "http://testserver/accounts/summary"


@pytest.fixture(scope="module")
def settings() -> Settings:
    s = Settings.from_env()
    try:
        httpx.get(f"{s.issuer}/.well-known/openid-configuration", timeout=3).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("Keycloak isn't running: `make up` first")
    return s


@pytest.fixture(scope="module")
def api(settings: Settings) -> TestClient:
    validator = TokenValidator(
        issuer=settings.issuer,
        audience=settings.api_audience,
        jwks=JwksCache(http_jwks_fetcher(settings.jwks_uri)),
    )
    return TestClient(create_app(validator))


def _token_request(settings: Settings, dpop_header: str | None) -> httpx.Response:
    headers = {"DPoP": dpop_header} if dpop_header else {}
    return httpx.post(
        settings.token_endpoint,
        data={"grant_type": "client_credentials", "scope": "accounts:read"},
        auth=("contoso-batch-dpop", require_env("LAB01_DPOP_CLIENT_SECRET")),
        headers=headers,
        timeout=10,
    )


def test_discovery_advertises_dpop(settings: Settings) -> None:
    meta = httpx.get(f"{settings.issuer}/.well-known/openid-configuration", timeout=5).json()
    assert "ES256" in meta.get("dpop_signing_alg_values_supported", [])


def test_client_requiring_dpop_refuses_token_without_proof(settings: Settings) -> None:
    assert _token_request(settings, None).status_code == 400


def test_dpop_token_is_bound_to_client_key(settings: Settings, api: TestClient) -> None:
    key = DpopKey()
    response = _token_request(settings, key.proof("POST", settings.token_endpoint))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"].lower() == "dpop"
    token = body["access_token"]
    assert peek_claims(token)["cnf"]["jkt"] == key.thumbprint

    ok = {"Authorization": f"DPoP {token}", "DPoP": key.proof("GET", API_URL, access_token=token)}
    assert api.get("/accounts/summary", headers=ok).status_code == 200
    assert api.get("/accounts/summary", headers=ok).status_code == 401  # replay
    downgraded = {"Authorization": f"Bearer {token}"}
    assert api.get("/accounts/summary", headers=downgraded).status_code == 401
