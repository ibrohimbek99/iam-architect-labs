# Lab 01: OAuth 2.x / OIDC flows

> **Status: core + DPoP done (2026-11-21).** Entra on-behalf-of track: W5 (needs a personal free tenant). Spring Boot resource server: Phase 8. See [PROGRESS.md](../../PROGRESS.md).

## What it proves

| Capability | Where | Proven by |
|---|---|---|
| A resource server that validates JWTs **correctly**: algorithm allow-list, JWKS cache with rate-limited refresh on rotation, `iss`/`aud`/`exp`/`nbf`, bounded clock skew, ID tokens rejected as access tokens, 401 vs 403 | [`iam_shared/jwt_validation.py`](../../shared/src/iam_shared/jwt_validation.py), [`lab01/api.py`](src/lab01/api.py) | 21 validator tests + 8 API tests |
| Authorization code + **PKCE (S256)** for a public client, with `state`, `nonce` and RFC 9207 `iss` checks and a loopback redirect | [`flows/auth_code_pkce.py`](src/lab01/flows/auth_code_pkce.py) | Run end to end against Keycloak; RFC 7636 test vector |
| **Refresh-token rotation with reuse detection** | same script; realm `revokeRefreshToken=true`, `refreshTokenMaxReuse=0` | Reusing the old token returned `invalid_grant: Maximum allowed refresh token reuse exceeded` |
| **Client credentials** for a workload (service account, no refresh token) | [`flows/client_credentials.py`](src/lab01/flows/client_credentials.py) | Integration test |
| **RFC 8693 token exchange**: audience and client re-binding per hop | [`flows/token_exchange.py`](src/lab01/flows/token_exchange.py) | Integration tests, including the negative case |
| **DPoP (RFC 9449) sender-constrained tokens**: proof verification (`typ`, alg, `htm`/`htu`, `iat` window, `jti` replay cache, `ath`, `cnf.jkt` binding), Bearer-downgrade rejection | [`iam_shared/dpop.py`](../../shared/src/iam_shared/dpop.py), [`flows/dpop.py`](src/lab01/flows/dpop.py) | 14 proof tests (incl. the RFC 7638 vector) + 8 API tests + 3 Keycloak integration tests |
| Redacted audit trail of every allow/deny | [`iam_shared/audit.py`](../../shared/src/iam_shared/audit.py) | Test asserts no token ever reaches the log |

**Job-market signal:** OAuth/OIDC appears in 54% of 101 analyzed $180K+ IAM postings, and 61% of those with a $200K+ midpoint.

## Run it

```bash
make up                                        # repo root: Keycloak 26.8.2 on http://localhost:8080
cd labs/01-oauth-oidc-flows
make run                                       # terminal 1: Accounts API on http://127.0.0.1:8001
make client-credentials                        # terminal 2
make token-exchange
make dpop                                      # sender-constrained tokens and the attacks they stop
make login                                     # browser: sign in as alice (password in .env.example)
make test-integration
```

Admin console: http://localhost:8080/admin (credentials in `.env`). Everything binds to 127.0.0.1. `make down` (repo root) removes it all.

Bruno: open [`bruno/`](bruno/) as a collection, choose the `local` environment, and paste the two client secrets from `.env.example` into the environment's secret fields. Secrets never go into the committed files.

## What the runs showed (Keycloak 26.8.2, 2026-11-21)

```
== token exchange: what changed
   aud: 'contoso-gateway'        ->  'contoso-accounts-api'
   azp: 'contoso-batch'          ->  'contoso-gateway'
 scope: 'gateway:call profile'   ->  'accounts:read'
GET /whoami with the exchanged token -> 200
GET /whoami with the original token  -> 401 invalid_token   (wrong audience)
```

```
== DPoP (make dpop): token_type=DPoP, cnf.jkt = our key's thumbprint
legit request (DPoP + fresh proof)     -> 200
replay of that exact request           -> 401
stolen token sent as Bearer            -> 401
stolen token + attacker's own proof    -> 401
```

Three things I didn't expect, all now pinned by tests and explained in [LEARN.md](LEARN.md#keycloak-behaviors-worth-knowing):
1. **Keycloak's exchanged scopes are bounded by the *requesting* client, not by the subject token.** The subject token had no `accounts:read`, yet the exchanged token did. Downscope-only needs a client policy.
2. Without the **`basic`** client scope, Keycloak 25+ issues tokens with **no `sub`**.
3. `iss` follows the request host: `localhost` ≠ `127.0.0.1`.

## Layout

```
keycloak/realm-contoso.json   Contoso realm: 4 clients, 5 client scopes, 1 test user (fictional)
src/lab01/api.py              Contoso Accounts API (FastAPI) on iam_shared's TokenValidator
src/lab01/flows/              runnable flows; they print claims, never raw tokens
tests/                        unit tests (no services) + integration/ (needs `make up`)
bruno/                        API collection
docs/                         ADR, threat model, diagrams
LEARN.md                      concepts, pitfalls, 10 interview Q&As
```

## Specs and versions (verified 2026-11-21)
Keycloak **26.8.2**: standard token exchange V2 is supported and on by default; delegation (`act`) is a 26.8 *preview*; impersonation exists only in deprecated V1; DPoP is fully supported since 26.4. RFCs: 6749, 6750, 7636, 8693, 9068, 9207, 9700.

## Teardown
`make down` at the repo root stops Keycloak and deletes its volume. Nothing is created outside Docker.
