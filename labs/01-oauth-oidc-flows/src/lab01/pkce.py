"""PKCE (RFC 7636) and the other one-time values a public client needs."""

from __future__ import annotations

import base64
import hashlib
import secrets


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def new_code_verifier() -> str:
    """A 43-character verifier from 32 bytes of CSPRNG output (RFC 7636 §4.1 allows 43–128)."""
    return _b64url(secrets.token_bytes(32))


def code_challenge_s256(verifier: str) -> str:
    """BASE64URL(SHA256(ASCII(verifier))). Never use the `plain` method."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def new_state() -> str:
    """Opaque value bound to this login attempt. It stops CSRF / login injection on the callback."""
    return secrets.token_urlsafe(24)


def new_nonce() -> str:
    """Bound into the ID token. It stops an ID token from being replayed into a different login."""
    return secrets.token_urlsafe(24)
