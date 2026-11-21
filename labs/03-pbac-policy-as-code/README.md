# Lab 03: Policy-based access & JIT

> **Status: planned** · Phase 5 · Mar – Apr 2027. See [PROGRESS.md](../../PROGRESS.md).

## What it will prove
- A Contoso Loan Origination Portal with role, branch, region, loan-limit, SoD and time-bound rules
- The same model four ways: IGA-style role JSON, OPA/Rego (`opa test`), Cedar, optional OpenFGA
- A PDP behind an AuthZEN-style evaluation API, with a FastAPI PEP middleware
- JIT elevation with approval and expiry; a zero-standing-privilege demo

## Job-market signal
Policy-based authz appears in 27% of postings (48% of identity-engineering roles). (Source: 101 US IAM postings with a top-of-range base of $180K+, Nov 2026.)

## Ships with
README · `LEARN.md` (concepts, pitfalls, 10 interview Q&As) · Mermaid C4 diagram · ADR · STRIDE threat model · tests · Bruno collection · teardown path.

All data is fictional (Contoso Bank).
