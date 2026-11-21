"""Helpers shared by the flow scripts.

The scripts print token *claims* so you can see what changed between flows.
They never print raw tokens: even in a lab, tokens don't belong in terminals or logs.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import jwt

from lab01.settings import Settings

# RFC 8693 URNs. They contain the word "token", which is why ruff's secret check fires on them.
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105

# Claims worth comparing between flows. Everything else is noise for learning purposes.
INTERESTING = ("iss", "sub", "preferred_username", "aud", "azp", "scope", "act", "exp", "typ")


class TokenEndpointError(RuntimeError):
    pass


def post_token(
    settings: Settings, form: dict[str, str], auth: tuple[str, str] | None = None
) -> dict[str, Any]:
    """POST to the token endpoint. Client secrets travel in HTTP Basic auth, not the form."""
    response = httpx.post(settings.token_endpoint, data=form, auth=auth, timeout=10.0)
    if response.status_code != 200:
        # The OAuth error body (error / error_description) never contains secrets, so show it.
        raise TokenEndpointError(f"{response.status_code}: {response.text}")
    data: dict[str, Any] = response.json()
    return data


def peek_claims(token: str) -> dict[str, Any]:
    """Decode WITHOUT verifying, for display only. The API is what verifies."""
    claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
    return claims


def show(title: str, token_response: dict[str, Any]) -> dict[str, Any]:
    claims = peek_claims(token_response["access_token"])
    summary = {k: claims[k] for k in INTERESTING if k in claims}
    summary["expires_in"] = token_response.get("expires_in")
    summary["refresh_token_issued"] = "refresh_token" in token_response
    print(f"\n== {title}")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return claims


def call_api(settings: Settings, path: str, access_token: str) -> None:
    try:
        response = httpx.get(
            f"{settings.api_url}{path}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5.0,
        )
    except httpx.ConnectError:
        print(f"(API not running at {settings.api_url}; start it with `make lab-01`)")
        return
    print(f"GET {path} -> {response.status_code} {response.text}")
