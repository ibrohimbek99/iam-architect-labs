# Diagrams

Diagrams are written in **Mermaid** so they render on GitHub and can be reviewed in diffs. Each lab has at least:

- a **C4 context or container** diagram (`docs/c4.md`)
- a **sequence diagram** for its main token or decision flow

Conventions:
- Trust boundaries are drawn as `subgraph` boxes and labeled.
- Every arrow that carries a credential names it, for example `access token (aud=mcp-accounts, 5 min, DPoP-bound)`.
- Only fictional names are used (Contoso Bank, `*.contoso.example`).
