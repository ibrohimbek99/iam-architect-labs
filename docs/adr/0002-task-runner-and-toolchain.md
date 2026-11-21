# 0002. GNU Make as the task runner, run from Git Bash on Windows

- Status: Accepted
- Date: 2026-11-20

## Context
The labs need one-command entry points (`make up / down / test / lab-NN`) that behave the same on the author's Windows 11 laptop and on Linux CI runners. Windows doesn't ship `make`, and PowerShell and bash quoting differ.

## Options
1. **GNU Make with `SHELL := bash`.** It's universally recognized, and CI runners have it preinstalled. On Windows it needs GNU Make (`winget install ezwinports.make`) and has to be run from Git Bash so recipes get a POSIX shell.
2. **`just`.** Cleaner syntax and native on Windows. But it's one more tool for reviewers to install, and it's less familiar to enterprise reviewers.
3. **A Python task runner (poethepoet via `uv run`).** Nothing extra to install beyond uv. But Docker and Terraform calls get wrapped in Python strings, and it's a less conventional entry point.

## Decision
Option 1. `make test` is the convention reviewers already expect. Recipes stay thin: each one calls `uv run`, `docker compose` or `terraform`, so the logic lives in those tools, not in the Makefile.

## Consequences
- Windows contributors run `make` from Git Bash, not from PowerShell or cmd.
- Recipes must stay POSIX-sh compatible. No PowerShell-isms.
- `.gitattributes` forces LF line endings so the Makefile isn't corrupted by CRLF on Windows checkouts.

### Toolchain pinned on 2026-11-20

| Tool | Version | Where it's pinned |
|---|---|---|
| Python | 3.12 | `.python-version` |
| uv | 0.13.9 (local) | `astral-sh/setup-uv@v10.4.0` in CI (no floating major tag exists) |
| Terraform | 1.17.1 | `.github/workflows/ci.yml` |
| tflint | v0.66.0 | CI |
| gitleaks | v8.30.1 | `.pre-commit-config.yaml` and CI |
| ruff (pre-commit) | v0.17.6 | `.pre-commit-config.yaml` |
| pre-commit-hooks | v6.0.0 | `.pre-commit-config.yaml` |
| GitHub Actions | checkout v7, setup-terraform v4, setup-tflint v6, checkov-action v12 | CI |

Follow-up: pin GitHub Actions to commit SHAs (and let Dependabot bump them) before any lab handles real cloud credentials.
