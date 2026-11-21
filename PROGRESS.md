# Progress

Updated at the end of every phase.

| Phase | Work | Weeks | Status |
|---|---|---|---|
| 0 | Setup: questions, tooling | W1 | ✅ Done 2026-11-20 |
| 1 | Scaffold, CI, Terraform skeleton | W1 | ✅ Done 2026-11-20 (CI green after PR #1) |
| 2 | Lab 01: OAuth 2.x / OIDC flows | W2–W5 · Dec 7 – Jan 3 | 🟡 Core done 2026-11-21 · Entra OBO track (W5) and DPoP to go |
| 3 | Lab 04: NHI, workload identity, secrets | W6–W9 · Jan | Planned |
| 4 | Lab 02: AI-agent identity + tokens for agents | W10–W14 · Feb – Mar 7 | Planned |
| 5 | Lab 03: PBAC + JIT | W15, W18–W19 | Planned |
| 6 | Lab 09: SailPoint machine & agent governance | W20–W21 · Apr | Planned |
| 7 | Lab 08: Secure RAG + agent security | W22–W25 · Apr – May | Planned |
| 8 | Lab 05: Cloud-IAM baseline + Spring Boot service | W26–W27 | Planned |
| 9 | Lab 07: Okta & PingOne federation | W28–W29 · Jun | Planned |
| 10 | Polish, zero-trust map, final scan | W30 · Jun 21–27 | Planned |
| — | Lab 06: Zero trust & Shared Signals | optional | Optional |

## Done

**Phase 2: Lab 01 core (2026-11-21)**
- `iam_shared.jwt_validation`: a TokenValidator with an algorithm allow-list, a JWKS cache with TTL and rate-limited refresh on unknown `kid`, fail-closed on JWKS outage, `iss`/`aud`/`exp`/`nbf` with 30 s leeway, ID/refresh tokens rejected, and `scope`/`scp` parsing. 21 tests. `iam_shared.testing.FakeIssuer` mints tokens for tests.
- Contoso Accounts API (FastAPI): 401 vs 403 with RFC 6750 challenges, generic errors to callers, redacted audit event per decision. 8 tests.
- Keycloak **26.8.2** in `docker-compose.yml` (127.0.0.1 only, health-checked). Contoso realm: public PKCE client, batch (client credentials), gateway (standard token exchange), API audience, 5 client scopes, test user `alice`.
- Flows: auth code + PKCE (+ `state`/`nonce`/RFC 9207 `iss`), refresh rotation with reuse detection, client credentials, token exchange. Bruno collection (5 requests).
- Docs: README, LEARN.md (concepts, pitfalls, 10 Q&As), ADR, STRIDE threat model (16 threats mapped to tests), Mermaid diagrams.
- Results:
  - `make lint typecheck` green (mypy over 14 files); 39 unit tests pass.
  - **8/8 integration tests** pass against Keycloak.
  - Browser login as alice → API 200; reusing the old refresh token → `invalid_grant`.
  - Bruno CLI: 5/5 requests and tests pass.
  - pre-commit (including gitleaks) passes.

**Phase 1 (2026-11-20)**
- Monorepo scaffold, `iam_shared.audit`, CI (python, gitleaks, terraform), plan-only Terraform. The first CI run failed only on an unresolvable `setup-uv@v10` tag. That was fixed in PR #1, and all three jobs then passed.

## Next
- Lab 01 / W5: Entra on-behalf-of + app roles vs scopes, in a **personal free Entra tenant** (create it in W4).
- Lab 01: DPoP. Keycloak supports it fully since 26.4. Add a DPoP-bound client and teach the validator to check `cnf.jkt` plus the proof.
- Phase 3 (Lab 04, Jan): Vault + Postgres in compose.

## Blockers
- None. Docker Desktop 29.9.3 on WSL2 is working (2026-11-21).

## What I learned
- **Keycloak token exchange can upscope.** Exchanged scopes are bounded by the *requesting* client, not the subject token. That's pinned by an integration test, and LEARN.md explains why to add a downscope client policy.
- A Keycloak realm import that lists `clientScopes` replaces the defaults, and **without the `basic` scope tokens have no `sub`**.
- `from __future__ import annotations` breaks FastAPI dependencies defined inside a factory function: the endpoints returned 422 instead of 401.
- A `null` scope claim became the scope `"None"` because of string formatting. The validator now ignores non-string scope claims (covered by a test).
- `astral-sh/setup-uv` doesn't publish floating major tags, so pin the full version.
- On Windows, checkov ships a `.cmd` launcher, so the Makefile uses `uvx --from checkov checkov.cmd`.
- An AWS provider with the `skip_*` flags lets `validate`/`plan` run with no account.
