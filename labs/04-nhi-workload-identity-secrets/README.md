# Lab 04: Non-human identity, workload identity & secrets

> **Status: planned** · Phase 3 · Jan 2027. See [PROGRESS.md](../../PROGRESS.md).

## What it will prove
- Vault dev mode: dynamic Postgres credentials, leases and revocation, AppRole vs JWT/OIDC auth
- GitHub Actions → AWS OIDC federation in Terraform (plan-only), with trust scoped to repo and branch
- A service-account governance model: inventory schema, orphan/stale detection, KPIs
- Certificate lifecycle with a local CA
- Write-up: an NHI program blueprint

## Job-market signal
NHI appears in 43% of postings; Secrets/Vault in 24%. (Source: 101 US IAM postings with a top-of-range base of $180K+, Nov 2026.)

## Ships with
README · `LEARN.md` (concepts, pitfalls, 10 interview Q&As) · Mermaid C4 diagram · ADR · STRIDE threat model · tests · Bruno collection · teardown path.

All data is fictional (Contoso Bank).
