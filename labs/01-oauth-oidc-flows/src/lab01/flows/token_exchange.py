"""RFC 8693 token exchange with Keycloak's standard token exchange (V2).

Scenario: contoso-batch holds a token whose audience is the gateway
(`aud=contoso-gateway`). The gateway must call the Accounts API, so it trades
that token for a new one:
  - audience narrowed to contoso-accounts-api only
  - scope narrowed to accounts:read only
  - issued to the gateway (`azp=contoso-gateway`)

That's least privilege per hop. The incoming token can't be replayed at the
Accounts API (wrong `aud`), and the outgoing one can't be replayed anywhere else.

Run: `uv run python -m lab01.flows.token_exchange`
"""

from __future__ import annotations

from lab01.flows.common import (
    ACCESS_TOKEN_TYPE,
    GRANT_TOKEN_EXCHANGE,
    call_api,
    post_token,
    show,
)
from lab01.settings import Settings, require_env


def main() -> None:
    settings = Settings.from_env()

    # 1. The caller's token, aimed ONLY at the gateway (not at the Accounts API).
    subject = post_token(
        settings,
        {"grant_type": "client_credentials", "scope": "gateway:call"},
        auth=("contoso-batch", require_env("LAB01_BATCH_CLIENT_SECRET")),
    )
    before = show("1. subject token (held by contoso-batch, aud = gateway only)", subject)

    # 2. The gateway exchanges it for a narrower token for the Accounts API.
    exchanged = post_token(
        settings,
        {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": subject["access_token"],
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": settings.api_audience,
            "scope": "accounts:read",
        },
        auth=("contoso-gateway", require_env("LAB01_GATEWAY_CLIENT_SECRET")),
    )
    after = show("2. exchanged token (issued to contoso-gateway for the Accounts API)", exchanged)

    print("\n== What changed")
    for claim in ("aud", "azp", "scope", "sub"):
        print(f"{claim:>6}: {before.get(claim)!r}  ->  {after.get(claim)!r}")

    call_api(settings, "/whoami", exchanged["access_token"])
    call_api(settings, "/whoami", subject["access_token"])  # expect 401: wrong audience


if __name__ == "__main__":
    main()
