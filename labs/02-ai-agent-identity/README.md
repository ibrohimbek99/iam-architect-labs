# Lab 02: AI-agent identity & tokens for agents (flagship)

> **Status: planned** · Phase 4 · Feb – early Mar 2027. See [PROGRESS.md](../../PROGRESS.md).

## What it will prove
- An agent registry: accountable human owner, purpose, allowed tools/scopes, status
- Tokens at every hop: `private_key_jwt` clients, token exchange with `sub` + nested `act`, RFC 8707 audience binding, DPoP
- An MCP server on the current MCP authorization spec (verified when built)
- A PEP with per-tool scopes and rate limits; CIBA-style approval + RAR for high-risk tools; break-glass; revocation
- A token-vault broker so agents never hold users' long-lived tokens; no token passthrough
- Per-agent audit, plus a vendor mapping to Entra Agent ID, Okta Cross App Access and SailPoint Agentic Fabric
- A 2-page reference architecture: AI-agent identity for a regulated bank

## Job-market signal
Agent identity appears in 36% of postings (52% of $200K+ roles); AI in identity in 36% (45%). (Source: 101 US IAM postings with a top-of-range base of $180K+, Nov 2026.)

## Ships with
README · `LEARN.md` (concepts, pitfalls, 10 interview Q&As) · Mermaid C4 diagram · ADR · STRIDE threat model · tests · Bruno collection · teardown path.

All data is fictional (Contoso Bank).
