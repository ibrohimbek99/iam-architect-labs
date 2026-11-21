"""Client credentials: a workload gets a token for itself. There's no user.

Run: `uv run python -m lab01.flows.client_credentials`
"""

from __future__ import annotations

from lab01.flows.common import call_api, post_token, show
from lab01.settings import Settings, require_env


def main() -> None:
    settings = Settings.from_env()
    secret = require_env("LAB01_BATCH_CLIENT_SECRET")
    response = post_token(
        settings,
        {"grant_type": "client_credentials", "scope": "accounts:read"},
        auth=("contoso-batch", secret),
    )
    claims = show("client_credentials as contoso-batch", response)
    # Note: `sub` is the client's *service account*, not a person, and no refresh token is issued.
    print(f"sub is a service account: {claims.get('preferred_username')}")
    # The token carries only accounts:read, so POST /transfers would get 403 insufficient_scope.
    call_api(settings, "/accounts/summary", response["access_token"])


if __name__ == "__main__":
    main()
