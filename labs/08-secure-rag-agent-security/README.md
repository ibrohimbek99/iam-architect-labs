# Lab 08: Secure RAG & agent security

> **Status: planned** · Phase 7 · Apr – May 2027. See [PROGRESS.md](../../PROGRESS.md).

## What it will prove
- A Contoso policy assistant: RAG over fictional documents with classification labels and ACLs
- Permission-aware retrieval: the user's token flows in, and retrieval is pre-filtered by the Lab 03 PDP
- Agent mode calling Lab 02 MCP tools with exchanged, narrowly scoped tokens
- An attack suite in CI (promptfoo/garak): indirect prompt injection, exfiltration, ACL bypass
- Retrieval and groundedness evals; a 2-page Secure RAG reference architecture

## Job-market signal
AI in identity/security appears in 36% of postings (45% of $200K+ roles). (Source: 101 US IAM postings with a top-of-range base of $180K+, Nov 2026.)

## Ships with
README · `LEARN.md` (concepts, pitfalls, 10 interview Q&As) · Mermaid C4 diagram · ADR · STRIDE threat model · tests · Bruno collection · teardown path.

All data is fictional (Contoso Bank).
