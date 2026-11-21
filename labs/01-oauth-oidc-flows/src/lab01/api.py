"""Contoso Accounts API: the resource server for Lab 01.

Every request goes through the same pipeline:
bearer token → TokenValidator (signature, iss, aud, exp, typ) → scope check → handler.
Each decision is written as a redacted audit event. Clients only ever get a
generic error. The detailed reason goes to the audit log, never back to the caller.

No `from __future__ import annotations` here: FastAPI resolves dependency type hints at
runtime, and string annotations would hide the dependencies defined inside create_app().
"""

import logging
from collections.abc import Callable
from typing import Annotated, Any, NoReturn

from fastapi import Depends, FastAPI, HTTPException, Request
from iam_shared import (
    AuditEvent,
    Decision,
    InsufficientScopeError,
    JwksCache,
    TokenValidationError,
    TokenValidator,
    ValidatedToken,
    http_jwks_fetcher,
    require_scopes,
)
from iam_shared.dpop import DPOP_ALGORITHMS, DpopError, DpopVerifier
from pydantic import BaseModel, Field

from lab01.settings import Settings

audit_log = logging.getLogger("lab01.audit")
_DPOP_CHALLENGE = f'DPoP algs="{" ".join(DPOP_ALGORITHMS)}"'

# Fictional data only.
_ACCOUNTS = {
    "alice": [
        {"id": "CHK-0001", "type": "checking", "balance": "2450.10", "currency": "USD"},
        {"id": "SAV-0002", "type": "savings", "balance": "18200.00", "currency": "USD"},
    ],
}


class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: str = Field(pattern=r"^\d+(\.\d{1,2})?$")


def _audit(request: Request, decision: Decision, reason: str, token: ValidatedToken | None) -> None:
    event = AuditEvent(
        action=f"http.{request.method.lower()}",
        subject=token.subject if token else "anonymous",
        actor_chain=token.actor_chain if token else [],
        resource=request.url.path,
        decision=decision,
        reason=reason,
        attributes={"client_id": token.client_id if token else None},
    )
    audit_log.info(event.to_json_line())


def _reject(
    request: Request, reason: str, challenge: str, detail: str = "invalid token"
) -> NoReturn:
    _audit(request, Decision.DENY, reason, None)
    # Deliberately vague to the caller (RFC 6750 §3.1); the reason is in the audit log.
    raise HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": challenge})


def _request_htu(request: Request) -> str:
    # The URL the client targeted, without query. Behind a reverse proxy, derive this from
    # trusted forwarding headers instead, or every proof will fail the htu check.
    return f"{request.url.scheme}://{request.url.netloc}{request.url.path}"


def create_app(validator: TokenValidator, dpop: DpopVerifier | None = None) -> FastAPI:
    app = FastAPI(title="Contoso Accounts API (Lab 01)", version="0.2.0")
    dpop_verifier = dpop or DpopVerifier()

    def authenticate(request: Request) -> ValidatedToken:
        header = request.headers.get("authorization", "")
        scheme, _, raw_token = header.partition(" ")
        scheme = scheme.lower()
        if scheme not in ("bearer", "dpop") or not raw_token:
            _reject(
                request,
                "no access token",
                f'Bearer realm="contoso-accounts-api", {_DPOP_CHALLENGE}',
                detail="authentication required",
            )
        try:
            token = validator.validate(raw_token.strip())
        except TokenValidationError as exc:
            _reject(request, str(exc), 'Bearer error="invalid_token"')

        jkt = token.confirmation_jkt
        if jkt is None and scheme == "dpop":
            _reject(request, "DPoP scheme used with an unbound token", 'DPoP error="invalid_token"')
        if jkt is not None:
            # A DPoP-bound token sent as plain Bearer is a downgrade attempt (RFC 9449 §7.1):
            # whoever is sending it can't prove they hold the key.
            if scheme != "dpop":
                _reject(
                    request, "DPoP-bound token presented as Bearer", 'DPoP error="invalid_token"'
                )
            proofs = request.headers.getlist("dpop")
            if len(proofs) != 1:
                _reject(
                    request, "exactly one DPoP proof required", 'DPoP error="invalid_dpop_proof"'
                )
            try:
                dpop_verifier.verify(
                    proofs[0],
                    method=request.method,
                    url=_request_htu(request),
                    access_token=raw_token.strip(),
                    expected_jkt=jkt,
                )
            except DpopError as exc:
                _reject(request, f"dpop: {exc}", 'DPoP error="invalid_dpop_proof"')
        request.state.token = token
        return token

    def require(*scopes: str) -> Callable[..., ValidatedToken]:
        def dependency(
            request: Request, token: Annotated[ValidatedToken, Depends(authenticate)]
        ) -> ValidatedToken:
            try:
                require_scopes(token, scopes)
            except InsufficientScopeError as exc:
                _audit(request, Decision.DENY, str(exc), token)
                raise HTTPException(
                    status_code=403,
                    detail="insufficient scope",
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer error="insufficient_scope", scope="{" ".join(scopes)}"'
                        )
                    },
                ) from exc
            _audit(request, Decision.ALLOW, "scopes satisfied", token)
            return token

        return dependency

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/whoami")
    def whoami(token: Annotated[ValidatedToken, Depends(authenticate)]) -> dict[str, Any]:
        return {
            "sub": token.subject,
            "client_id": token.client_id,
            "scopes": sorted(token.scopes),
            "actor_chain": token.actor_chain,
            "aud": token.claims.get("aud"),
        }

    @app.get("/accounts/summary")
    def accounts_summary(
        token: Annotated[ValidatedToken, Depends(require("accounts:read"))],
    ) -> dict[str, Any]:
        username = str(token.claims.get("preferred_username", token.subject))
        return {"owner": username, "accounts": _ACCOUNTS.get(username, [])}

    @app.post("/transfers", status_code=202)
    def create_transfer(
        body: TransferRequest,
        token: Annotated[ValidatedToken, Depends(require("transfers:write"))],
    ) -> dict[str, Any]:
        return {"status": "accepted", "from": body.from_account, "amount": body.amount}

    return app


def create_app_from_env() -> FastAPI:
    settings = Settings.from_env()
    validator = TokenValidator(
        issuer=settings.issuer,
        audience=settings.api_audience,
        jwks=JwksCache(http_jwks_fetcher(settings.jwks_uri)),
    )
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return create_app(validator)
