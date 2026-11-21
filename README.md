# IAM Architect Labs

Hands-on, runnable labs for modern identity architecture. They cover OAuth/OIDC depth, AI-agent identity, non-human identity and secrets, policy-based authorization, secure RAG, and governance for machines and agents.

Everything runs **locally by default** (Docker + Python). Cloud tracks are optional and plan-only, and CI never needs them. Every example uses the fictional **Contoso Bank**: no real organization's data, names or configuration appears anywhere in this repo.

## Why these labs

The labs are mapped to an analysis of **101 US IAM job postings (Nov 2026)** whose posted base range tops out at $180K or more. The percentages are the share of those postings that ask for each skill.

| Lab | What it proves | Postings asking for it |
|---|---|---|
| [01 · OAuth 2.x / OIDC flows](labs/01-oauth-oidc-flows/) | JWT validation done right, PKCE, token exchange (delegation vs impersonation), on-behalf-of | OAuth/OIDC **54%** (61% of $200K+ roles) |
| [02 · AI-agent identity](labs/02-ai-agent-identity/) ⭐ flagship | Agents as first-class identities, tokens for agents at every hop, MCP authorization, HITL, revocation, audit | Agent identity **36%** (52% of $200K+) |
| [03 · Policy as code](labs/03-pbac-policy-as-code/) | OPA + Cedar behind an AuthZEN-style PDP; JIT elevation; zero standing privilege | Policy-based authz **27%** |
| [04 · NHI, workload identity & secrets](labs/04-nhi-workload-identity-secrets/) | Vault dynamic secrets, keyless CI → cloud federation, service-account governance | NHI **43%** · Secrets/Vault **24%** |
| [05 · Cloud-IAM baseline](labs/05-cloud-iam-baseline-terraform/) | AWS organization guardrails in Terraform, policy-checked in CI | Terraform/IaC **27%** · AWS **36%** |
| [06 · Zero trust & Shared Signals](labs/06-zero-trust-shared-signals/) *(optional)* | CAEP events cutting live sessions; NIST SP 800-207 map | Zero trust **25%** |
| [07 · Federation: Okta & Ping](labs/07-federation-okta-ping/) | OIDC + SAML in Okta and PingOne, compared with Entra and Keycloak | Okta **28%** · Ping **17%** |
| [08 · Secure RAG & agent security](labs/08-secure-rag-agent-security/) | Permission-aware retrieval, prompt-injection test suite in CI | AI in identity/security **36%** (45% of $200K+) |
| [09 · SailPoint machine & agent governance](labs/09-sailpoint-machine-agent-governance/) | A SaaS Connectivity connector that brings agents and service accounts under governance | SailPoint **23%** · NHI **43%** |

Build status is tracked in [PROGRESS.md](PROGRESS.md). Design decisions are recorded in [docs/adr/](docs/adr/).

## Quick start

You need Python 3.12, [uv](https://docs.astral.sh/uv/), GNU Make and Terraform ≥ 1.6. Labs that run services also need Docker. On Windows, run `make` from **Git Bash** (see [ADR-0002](docs/adr/0002-task-runner-and-toolchain.md)).

```bash
make setup   # install Python deps + git hooks (gitleaks, ruff)
make check   # lint, type-check, tests, terraform fmt + validate
make help    # list every target
```

## Repo layout

```
docs/            adr/, diagrams/, threat-models/, zero-trust-map.md, glossary.md
labs/            01–09, each self-contained with README, LEARN.md, tests, Bruno collection
shared/          iam_shared: audit events today; JWT validation and config arrive with Lab 01
infra/terraform/ reusable modules + plan-only root modules
.github/         CI: lint, type-check, tests, gitleaks, terraform fmt/validate, tflint, checkov
```

## Guardrails

- **Fictional data only** (Contoso Bank). No real tenant IDs, hostnames or screenshots, and nothing from any employer's environments ([ADR-0003](docs/adr/0003-local-first-cloud-policy.md)).
- **No secrets in git.** Only `.env.example` is committed. gitleaks runs in pre-commit and in CI over the full history.
- **Local-first and free.** Terraform is plan-only and there is no `apply` target.
- **Pinned versions.** Each lab README records when its specs and versions were last verified.

Portfolio: [ibrokhimbek.com](https://ibrokhimbek.com)
