# Threat models

Each lab ships a STRIDE threat model as `labs/NN-*/docs/threat-model.md`, using the template below. Cross-lab models (for example, the whole agent → MCP → API path) live in this folder.

## Template

```markdown
# Threat model: <lab or flow>

- Scope / data-flow diagram: <link to Mermaid diagram>
- Assets: <tokens, secrets, PII, decisions>
- Trust boundaries: <browser ↔ API, agent ↔ MCP server, CI ↔ cloud, ...>

| # | STRIDE | Threat | Where | Mitigation in this lab | Test that proves it | Residual risk |
|---|---|---|---|---|---|---|
| 1 | Spoofing | Forged JWT accepted | Resource server | Signature + iss/aud/exp checks, alg pinning | `test_rejects_wrong_aud` | Key compromise at IdP |
| 2 | Tampering | | | | | |
| 3 | Repudiation | | | | | |
| 4 | Information disclosure | | | | | |
| 5 | Denial of service | | | | | |
| 6 | Elevation of privilege | | | | | |

AI labs (02, 08) also map each threat to an OWASP Top 10 for LLM Applications category.
```
