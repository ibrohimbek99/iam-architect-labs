"""Configuration from environment variables (see the repo's .env.example).

Secrets are only ever read from the environment, never from source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]


def load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    """Minimal .env loader: KEY=VALUE lines. Variables already set in the environment win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class Settings:
    keycloak_url: str
    realm: str
    api_audience: str
    api_url: str

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_url}/realms/{self.realm}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        return cls(
            # Use exactly the same host for getting tokens and validating them:
            # Keycloak's `iss` is derived from the request host (localhost != 127.0.0.1).
            keycloak_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/"),
            realm=os.environ.get("KEYCLOAK_REALM", "contoso"),
            api_audience=os.environ.get("LAB01_API_AUDIENCE", "contoso-accounts-api"),
            api_url=os.environ.get("LAB01_API_URL", "http://127.0.0.1:8001").rstrip("/"),
        )


def require_env(name: str) -> str:
    """Read a required secret from the environment with a helpful error."""
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set. Copy .env.example to .env at the repo root.")
    return value
