"""DPoP (RFC 9449): sender-constrained access tokens.

1. Generate an in-memory EC P-256 key. It never leaves this process.
2. Ask Keycloak for a token with a DPoP proof. The token comes back with
   token_type=DPoP and cnf.jkt = this key's thumbprint.
3. Call the API with `Authorization: DPoP <token>` and a fresh proof → 200.
4. Show what an attacker can't do with the stolen token:
   - send it as a plain Bearer token
   - replay a captured request
   - use their own key

Run: `uv run python -m lab01.flows.dpop` (with `make up` and the API running)
"""

from __future__ import annotations

import httpx
from iam_shared.dpop import DpopKey

from lab01.flows.common import show
from lab01.settings import Settings, require_env


def _get(settings: Settings, path: str, headers: dict[str, str]) -> int:
    response = httpx.get(f"{settings.api_url}{path}", headers=headers, timeout=5.0)
    return response.status_code


def main() -> None:
    settings = Settings.from_env()
    key = DpopKey()
    response = httpx.post(
        settings.token_endpoint,
        data={"grant_type": "client_credentials", "scope": "accounts:read"},
        auth=("contoso-batch-dpop", require_env("LAB01_DPOP_CLIENT_SECRET")),
        headers={"DPoP": key.proof("POST", settings.token_endpoint)},
        timeout=10.0,
    )
    response.raise_for_status()
    tokens = response.json()
    claims = show("client_credentials with DPoP", tokens)
    print(f"token_type: {tokens.get('token_type')}")
    print(f"cnf.jkt matches our key: {claims.get('cnf', {}).get('jkt') == key.thumbprint}")

    token = tokens["access_token"]
    url = f"{settings.api_url}/accounts/summary"
    try:
        legit = {
            "Authorization": f"DPoP {token}",
            "DPoP": key.proof("GET", url, access_token=token),
        }
        thief = DpopKey()
        attempts = [
            ("legit request (DPoP + fresh proof)", legit),
            ("replay of that exact request", legit),
            ("stolen token sent as Bearer", {"Authorization": f"Bearer {token}"}),
            (
                "stolen token + attacker's own proof",
                {
                    "Authorization": f"DPoP {token}",
                    "DPoP": thief.proof("GET", url, access_token=token),
                },
            ),
        ]
        print()
        for label, headers in attempts:
            print(f"{label:<38} -> {_get(settings, '/accounts/summary', headers)}")
    except httpx.ConnectError:
        print(f"(API not running at {settings.api_url}; start it with `make run`)")


if __name__ == "__main__":
    main()
