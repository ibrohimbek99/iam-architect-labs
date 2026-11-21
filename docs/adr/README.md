# Architecture Decision Records

Each significant design choice gets one ADR. An ADR lists 2–3 options with their trade-offs, states the decision, and records its consequences. Lab-specific ADRs live in each lab's `docs/` folder; repo-wide ADRs live here.

| # | Decision | Status |
|---|---|---|
| [0001](0001-monorepo-layout.md) | One monorepo with a uv workspace and a shared package | Accepted |
| [0002](0002-task-runner-and-toolchain.md) | GNU Make as the task runner, run from Git Bash on Windows | Accepted |
| [0003](0003-local-first-cloud-policy.md) | Local-first; cloud is optional, personal-account-only, plan-only | Accepted |

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context
What forces are at play? What requirement or constraint triggers this decision?

## Options
1. **Option A**: pros / cons
2. **Option B**: pros / cons
3. **Option C**: pros / cons

## Decision
The option chosen, and why it beats the others *here*.

## Consequences
What gets easier, what gets harder, and what we must now do.
```
