"""Access-token validation for resource servers.

These are the checks an attacker probes and an auditor asks about:

1. The algorithm is on an explicit allow-list (asymmetric only).
2. The signature verifies against the issuer's published keys (JWKS), with a
   cache that refreshes on key rotation but can't be abused to flood the IdP.
3. ``iss`` and ``aud`` match this API exactly.
4. ``exp`` / ``nbf`` hold, within a small, bounded clock skew.
5. The token really is an *access* token, not an ID or refresh token.
6. The caller has the scopes the endpoint needs (403, not 401, if not).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from iam_shared.audit import actor_chain_from_claims

# Asymmetric algorithms only. If a resource server that verifies with a *public*
# key also accepted HS256, an attacker could sign a token using that public key
# as the HMAC secret (the classic "algorithm confusion" attack). "none" means
# no signature at all.
DEFAULT_ALGORITHMS: tuple[str, ...] = ("RS256", "PS256", "ES256")

# Keycloak marks token kinds in a `typ` claim. Rejecting these stops an ID token
# or refresh token from being replayed against an API as if it were an access token.
NON_ACCESS_TOKEN_TYPES = frozenset({"ID", "Refresh", "Logout", "Offline"})

JwksFetcher = Callable[[], Mapping[str, Any]]


class TokenValidationError(Exception):
    """The token must be rejected: respond 401 with ``error="invalid_token"``."""


class InsufficientScopeError(Exception):
    """The token is valid but lacks scopes: respond 403 with ``error="insufficient_scope"``."""

    def __init__(self, missing: Iterable[str]) -> None:
        self.missing = frozenset(missing)
        super().__init__("missing scopes: " + " ".join(sorted(self.missing)))


def http_jwks_fetcher(jwks_uri: str, timeout: float = 5.0) -> JwksFetcher:
    """Fetch a JWKS document over HTTP(S)."""

    def fetch() -> Mapping[str, Any]:
        response = httpx.get(jwks_uri, timeout=timeout)
        response.raise_for_status()
        data: Mapping[str, Any] = response.json()
        return data

    return fetch


class JwksCache:
    """Caches an issuer's signing keys.

    - Keys are reused for ``ttl`` seconds.
    - A token with an unknown ``kid`` triggers one refresh, because the IdP may
      have rotated its keys. Refreshes are rate-limited by ``min_refresh_interval``
      so a flood of tokens with random ``kid`` values can't turn this API into a
      denial-of-service amplifier against the IdP.
    - If the keys can't be fetched, validation fails closed.
    """

    def __init__(
        self,
        fetch: JwksFetcher,
        ttl: float = 300.0,
        min_refresh_interval: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._ttl = ttl
        self._min_refresh_interval = min_refresh_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, PyJWK] | None = None
        self._fetched_at = 0.0
        self.refresh_count = 0

    def get_key(self, kid: str) -> PyJWK:
        with self._lock:
            now = self._clock()
            if self._keys is None or now - self._fetched_at > self._ttl:
                self._refresh(now)
            assert self._keys is not None  # noqa: S101 - set by _refresh or it raised
            key = self._keys.get(kid)
            if key is None and now - self._fetched_at >= self._min_refresh_interval:
                self._refresh(now)
                key = self._keys.get(kid)
        if key is None:
            raise TokenValidationError("unknown signing key")
        return key

    def _refresh(self, now: float) -> None:
        try:
            document = self._fetch()
        except Exception as exc:  # network, HTTP or JSON errors: fail closed
            raise TokenValidationError("signing keys unavailable") from exc
        keys: dict[str, PyJWK] = {}
        for jwk in document.get("keys", []):
            # Only signing keys with an id. Encryption keys must never verify signatures.
            if jwk.get("use", "sig") != "sig" or not isinstance(jwk.get("kid"), str):
                continue
            try:
                keys[jwk["kid"]] = PyJWK(dict(jwk))
            except jwt.PyJWKError:
                continue  # unsupported key type or algorithm: skip it, don't crash
        self._keys = keys
        self._fetched_at = now
        self.refresh_count += 1


@dataclass(frozen=True)
class ValidatedToken:
    """Claims of a token that passed every check."""

    claims: Mapping[str, Any]

    @property
    def subject(self) -> str:
        return str(self.claims["sub"])

    @property
    def client_id(self) -> str | None:
        # `azp` (OIDC) or `client_id` (RFC 9068): the client the token was issued to.
        value = self.claims.get("client_id") or self.claims.get("azp")
        return str(value) if value else None

    @property
    def scopes(self) -> frozenset[str]:
        # Keycloak and RFC 9068 use `scope`; Microsoft Entra uses `scp`. Both are space-delimited.
        # Ignore anything that isn't a string, so a null or numeric claim can't become a "scope".
        parts: list[str] = []
        for name in ("scope", "scp"):
            value = self.claims.get(name)
            if isinstance(value, str):
                parts.extend(value.split())
        return frozenset(parts)

    @property
    def actor_chain(self) -> list[str]:
        return actor_chain_from_claims(self.claims)


@dataclass
class TokenValidator:
    """Validates bearer access tokens for exactly one API (``audience``)."""

    issuer: str
    audience: str
    jwks: JwksCache
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    leeway_seconds: int = 30  # tolerate small clock drift, never minutes
    required_claims: tuple[str, ...] = field(default=("exp", "iat", "iss", "aud", "sub"))

    def validate(self, token: str) -> ValidatedToken:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise TokenValidationError("malformed token") from exc

        # Decide the algorithm from OUR allow-list before touching any key.
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise TokenValidationError(f"algorithm not allowed: {alg}")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise TokenValidationError("missing kid")

        key = self.jwks.get_key(kid)
        if key.algorithm_name and key.algorithm_name != alg:
            raise TokenValidationError("algorithm does not match signing key")

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": list(self.required_claims)},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("token expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenValidationError("token not yet valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenValidationError("wrong audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenValidationError("wrong issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenValidationError(f"missing claim: {exc.claim}") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError("invalid token") from exc

        if claims.get("typ") in NON_ACCESS_TOKEN_TYPES:
            raise TokenValidationError("not an access token")
        return ValidatedToken(claims)


def require_scopes(token: ValidatedToken, required: Iterable[str]) -> None:
    """Raise InsufficientScopeError unless ``token`` carries every scope in ``required``."""
    missing = set(required) - token.scopes
    if missing:
        raise InsufficientScopeError(missing)
