# Progress

Updated at the end of every phase.

| Phase | Work | Weeks | Status |
|---|---|---|---|
| 0 | Setup: questions, tooling | W1 | ✅ Done 2026-11-20 |
| 1 | Scaffold, CI, Terraform skeleton | W1 | ✅ Done 2026-11-20 (not yet committed or pushed) |
| 2 | Lab 01: OAuth 2.x / OIDC flows | W2–W5 · Dec 7 – Jan 3 | Next |
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

**Phase 1 (2026-11-20)**
- Monorepo scaffold: uv workspace, `iam_shared` package, docs (3 ADRs, threat-model and diagram conventions, glossary, zero-trust map), 9 lab placeholders, Makefile.
- `iam_shared.audit`: structured audit events with central redaction of secrets and JWTs, and RFC 8693 `act`-chain flattening with a depth cap. 7 tests.
- CI (`.github/workflows/ci.yml`): ruff, mypy, pytest; gitleaks over the full history; Terraform fmt/validate, tflint, checkov. Least-privilege `contents: read`.
- Terraform skeleton: `infra/terraform/live/plan-only`, with an AWS provider that runs without credentials.
- Local results: `make check` green (ruff, ruff format, mypy, 7/7 tests, terraform fmt + validate). `make checkov`: 1 passed, 0 failed. `pre-commit validate-config` OK.

## Next
- `git init`, run `make setup` (installs hooks), run gitleaks over all files, first commit, create the public GitHub repo and push, then watch the first CI run.
- Phase 2: Lab 01. Verify the current Keycloak version and its standard token-exchange support first.

## Blockers
- **Docker Desktop + WSL2 not installed yet** (needed from Lab 01, W2). This is a manual step: it needs admin rights and a reboot.
- **GitHub CLI not logged in.** Run `gh auth login` before the first push.
- gitleaks hasn't run locally yet. It needs a git repo, so it runs at first commit.

## What I learned
- On Windows, `uvx checkov` fails because checkov ships a `.cmd` launcher, not an `.exe`. The Makefile switches to `uvx --from checkov checkov.cmd` when `OS=Windows_NT`.
- An AWS provider with `skip_credentials_validation`, `skip_requesting_account_id` and `skip_metadata_api_check` lets `validate`/`plan` run with no account, which is a cheap guardrail against an accidental apply.
