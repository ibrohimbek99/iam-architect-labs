"""Shared building blocks for the IAM Architect Labs."""

from iam_shared.audit import AuditEvent, Decision, actor_chain_from_claims, redact
from iam_shared.jwt_validation import (
    InsufficientScopeError,
    JwksCache,
    TokenValidationError,
    TokenValidator,
    ValidatedToken,
    http_jwks_fetcher,
    require_scopes,
)

__all__ = [
    "AuditEvent",
    "Decision",
    "InsufficientScopeError",
    "JwksCache",
    "TokenValidationError",
    "TokenValidator",
    "ValidatedToken",
    "actor_chain_from_claims",
    "http_jwks_fetcher",
    "redact",
    "require_scopes",
]
