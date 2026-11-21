# Lab 01: OAuth 2.x / OIDC flows

> **Status: planned** · Phase 2 · Dec 2026. See [PROGRESS.md](../../PROGRESS.md).

## What it will prove
- A FastAPI resource server that validates JWTs correctly: JWKS caching, iss/aud/exp/nbf, alg pinning, clock skew
- Auth code + PKCE, client credentials, refresh-token rotation (Keycloak, version pinned)
- RFC 8693 token exchange: delegation (`act`) vs impersonation
- Entra on-behalf-of and app roles vs scopes, in a personal free tenant
- A small Spring Boot (Java 21) resource server doing the same validation

## Job-market signal
OAuth/OIDC appears in 54% of postings (61% of $200K+ roles). (Source: 101 US IAM postings with a top-of-range base of $180K+, Nov 2026.)

## Ships with
README · `LEARN.md` (concepts, pitfalls, 10 interview Q&As) · Mermaid C4 diagram · ADR · STRIDE threat model · tests · Bruno collection · teardown path.

All data is fictional (Contoso Bank).
