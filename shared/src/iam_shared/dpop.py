"""DPoP: Demonstrating Proof-of-Possession (RFC 9449).

A DPoP-bound access token carries ``cnf.jkt``, the thumbprint of a public key the
client holds. With every request the client sends a fresh, signed *proof* JWT.
The proof is bound to this HTTP method, this URL and this exact access token
(``ath``). Someone who steals the token can't use it without the private key.

The resource server checks:
1. the proof's header: ``typ=dpop+jwt``, asymmetric ``alg``, a public ``jwk`` only
2. the signature, using that embedded key
3. ``htm`` / ``htu``, which must match this request
4. ``iat``, which must be fresh
5. ``jti``, which must not have been seen before (replay)
6. ``ath``, which must hash the presented token
7. the key thumbprint, which must equal the token's ``cnf.jkt``
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import PyJWK
from jwt.algorithms import ECAlgorithm

DPOP_ALGORITHMS: tuple[str, ...] = ("ES256", "RS256", "PS256")
PROOF_TYPE = "dpop+jwt"

# Members of each key type that RFC 7638 includes in the thumbprint, in lexical order.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}
# Private-key members that must never appear in a proof's header.
_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}


class DpopError(Exception):
    """The DPoP proof must be rejected: 401 with ``error="invalid_dpop_proof"``."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of a public JWK."""
    members = _THUMBPRINT_MEMBERS.get(str(jwk.get("kty")))
    if members is None:
        raise DpopError("unsupported key type")
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def access_token_hash(access_token: str) -> str:
    """The ``ath`` claim: base64url(SHA-256(token))."""
    return b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def normalize_htu(url: str) -> str:
    """Compare URLs without query or fragment (RFC 9449 §4.3)."""
    return url.split("#", 1)[0].split("?", 1)[0]


class DpopKey:
    """A client-side EC P-256 key pair used to sign proofs. Keep it in memory, never on disk."""

    def __init__(self) -> None:
        self._private = ec.generate_private_key(ec.SECP256R1())
        self.public_jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(self._private.public_key()))

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk)

    def proof(
        self,
        method: str,
        url: str,
        access_token: str | None = None,
        nonce: str | None = None,
        iat: int | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            "jti": uuid.uuid4().hex,
            "htm": method.upper(),
            "htu": normalize_htu(url),
            "iat": iat if iat is not None else int(time.time()),
        }
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        if nonce is not None:
            claims["nonce"] = nonce
        headers = {"typ": PROOF_TYPE, "jwk": self.public_jwk}
        return jwt.encode(claims, self._private, algorithm="ES256", headers=headers)


class ReplayCache:
    """Remembers proof ``jti`` values until they are too old to be accepted anyway."""

    def __init__(self, ttl: float, clock: Callable[[], float] = time.time) -> None:
        self._ttl = ttl
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, jti: str) -> bool:
        """True if ``jti`` is new (and now recorded); False if it's a replay."""
        with self._lock:
            now = self._clock()
            for old in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[old]
            if jti in self._seen:
                return False
            self._seen[jti] = now + self._ttl
            return True


class DpopVerifier:
    """Server-side proof verification for one resource server (or token endpoint)."""

    def __init__(
        self,
        max_age_seconds: int = 60,
        future_skew_seconds: int = 5,
        algorithms: tuple[str, ...] = DPOP_ALGORITHMS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._max_age = max_age_seconds
        self._future_skew = future_skew_seconds
        self._algorithms = algorithms
        self._clock = clock
        self._replay = ReplayCache(ttl=max_age_seconds + future_skew_seconds, clock=clock)

    def verify(
        self, proof: str, *, method: str, url: str, access_token: str, expected_jkt: str
    ) -> None:
        try:
            header = jwt.get_unverified_header(proof)
        except jwt.DecodeError as exc:
            raise DpopError("malformed proof") from exc

        if header.get("typ") != PROOF_TYPE:
            raise DpopError("wrong proof typ")
        alg = header.get("alg")
        if alg not in self._algorithms:
            raise DpopError(f"proof algorithm not allowed: {alg}")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            raise DpopError("proof has no jwk")
        if _PRIVATE_MEMBERS & jwk.keys():
            raise DpopError("proof jwk contains private key material")

        try:
            key = PyJWK(dict(jwk), algorithm=alg)
            claims: dict[str, Any] = jwt.decode(
                proof,
                key=key.key,
                algorithms=[alg],
                # iat freshness is checked below with DPoP's own window, not PyJWT's.
                options={
                    "require": ["jti", "htm", "htu", "iat"],
                    "verify_aud": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWKError as exc:
            raise DpopError("proof jwk unusable") from exc
        except jwt.InvalidSignatureError as exc:
            raise DpopError("proof signature invalid") from exc
        except jwt.InvalidTokenError as exc:
            raise DpopError("invalid proof") from exc

        if claims["htm"] != method.upper():
            raise DpopError("htm mismatch")
        if normalize_htu(str(claims["htu"])) != normalize_htu(url):
            raise DpopError("htu mismatch")

        now = self._clock()
        iat = claims["iat"]
        if not isinstance(iat, int | float) or iat > now + self._future_skew:
            raise DpopError("proof issued in the future")
        if now - iat > self._max_age:
            raise DpopError("proof too old")

        if claims.get("ath") != access_token_hash(access_token):
            raise DpopError("ath does not match the access token")
        # The binding check: the key that signed this proof is the key the token was issued to.
        if jwk_thumbprint(jwk) != expected_jkt:
            raise DpopError("proof key does not match the token's cnf.jkt")

        # Last, so failed proofs don't fill the cache.
        if not self._replay.check_and_add(str(claims["jti"])):
            raise DpopError("proof replayed")
