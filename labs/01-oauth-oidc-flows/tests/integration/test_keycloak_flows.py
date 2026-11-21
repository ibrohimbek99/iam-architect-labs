"""End-to-end checks against the local Keycloak. Run `make up`, then `make test-integration`."""

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from iam_shared import JwksCache, TokenValidator, http_jwks_fetcher
from lab01.api import create_app
from lab01.flows.common import (
    ACCESS_TOKEN_TYPE,
    GRANT_TOKEN_EXCHANGE,
    TokenEndpointError,
    peek_claims,
    post_token,
)
from lab01.settings import Settings, require_env

pytestmark = pytest.mark.integration


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


def _audiences(claims: dict[str, Any]) -> set[str]:
    aud = claims.get("aud", [])
    return {aud} if isinstance(aud, str) else set(aud)


def _batch_token(settings: Settings, scope: str) -> str:
    response = post_token(
        settings,
        {"grant_type": "client_credentials", "scope": scope},
        auth=("contoso-batch", require_env("LAB01_BATCH_CLIENT_SECRET")),
    )
    return str(response["access_token"])


def _exchange(settings: Settings, subject_token: str) -> dict[str, Any]:
    return post_token(
        settings,
        {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": settings.api_audience,
            "scope": "accounts:read",
        },
        auth=("contoso-gateway", require_env("LAB01_GATEWAY_CLIENT_SECRET")),
    )


def test_discovery_advertises_pkce_and_token_exchange(settings: Settings) -> None:
    meta = httpx.get(f"{settings.issuer}/.well-known/openid-configuration", timeout=5).json()
    assert "S256" in meta["code_challenge_methods_supported"]
    assert GRANT_TOKEN_EXCHANGE in meta["grant_types_supported"]


def test_client_credentials_token_is_accepted_by_api(settings: Settings, api: TestClient) -> None:
    token = _batch_token(settings, "accounts:read")
    claims = peek_claims(token)
    assert "contoso-accounts-api" in _audiences(claims)
    assert claims["azp"] == "contoso-batch"
    response = api.get("/accounts/summary", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_token_for_another_audience_is_rejected_by_api(settings: Settings, api: TestClient) -> None:
    token = _batch_token(settings, "gateway:call")  # aud = gateway only
    assert "contoso-accounts-api" not in _audiences(peek_claims(token))
    response = api.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_token_exchange_narrows_audience_and_scope(settings: Settings, api: TestClient) -> None:
    subject = _batch_token(settings, "gateway:call accounts:read")
    exchanged = _exchange(settings, subject)["access_token"]
    claims = peek_claims(exchanged)
    assert claims["azp"] == "contoso-gateway"
    assert _audiences(claims) == {"contoso-accounts-api"}
    assert "gateway:call" not in claims.get("scope", "").split()
    response = api.get("/whoami", headers={"Authorization": f"Bearer {exchanged}"})
    assert response.status_code == 200


def test_keycloak_exchange_scopes_are_bounded_by_requester_not_subject(settings: Settings) -> None:
    # Architecture note, verified against Keycloak 26.8.2: the subject token has NO accounts:read,
    # yet the exchanged token does, because Keycloak bounds exchanged scopes by what the
    # *requesting client* may get. Enforcing downscope-only needs a client policy (see LEARN.md).
    subject = _batch_token(settings, "gateway:call")
    assert "accounts:read" not in peek_claims(subject).get("scope", "").split()
    exchanged = peek_claims(_exchange(settings, subject)["access_token"])
    assert "accounts:read" in exchanged["scope"].split()


def test_exchange_rejected_when_requester_not_in_subject_audience(settings: Settings) -> None:
    subject = _batch_token(settings, "accounts:read")  # gateway is NOT in aud
    with pytest.raises(TokenEndpointError):
        _exchange(settings, subject)


def test_public_client_must_use_pkce(settings: Settings) -> None:
    response = httpx.get(
        settings.authorization_endpoint,
        params={
            "client_id": "contoso-cli",
            "response_type": "code",
            "redirect_uri": "http://127.0.0.1:8765/callback",
            "scope": "openid",
            "state": "x",
        },
        follow_redirects=False,
        timeout=5,
    )
    # Keycloak bounces the request back to the redirect URI with an OAuth error.
    assert response.status_code in (302, 303)
    assert "error=invalid_request" in response.headers["location"]


def test_unknown_redirect_uri_is_refused(settings: Settings) -> None:
    response = httpx.get(
        settings.authorization_endpoint,
        params={
            "client_id": "contoso-cli",
            "response_type": "code",
            "redirect_uri": "http://127.0.0.1:9999/evil",
            "scope": "openid",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
        timeout=5,
    )
    # Never redirects to an unregistered URI: Keycloak shows an error page instead.
    assert response.status_code == 400
