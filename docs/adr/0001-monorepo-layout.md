# 0001. One monorepo with a uv workspace and a shared package

- Status: Accepted
- Date: 2026-11-20

## Context
Nine labs share a lot of plumbing: JWT validation, audit events, the Contoso Bank test data, Terraform modules and CI. A reviewer such as a hiring manager should be able to clone one thing, run one command, and see every lab. Each lab must also stand on its own so it can be linked from a case study.

## Options
1. **Repo per lab.** Each lab is linkable in isolation. But shared code gets copied, CI is duplicated nine times, and a reviewer has to visit nine repos.
2. **Monorepo, labs fully independent.** One clone and one CI pipeline. But JWT validation and audit code would still be duplicated and would drift apart.
3. **Monorepo with a uv workspace and a shared package (`iam_shared`).** One clone, one lockfile, one CI pipeline. Security-critical code (token validation, redaction) is written and tested once. Labs depend on `iam_shared` the same way an internal platform library would be consumed.

## Decision
Option 3. Security code that exists in exactly one place can be reviewed and tested properly. That's the same argument you'd make at a bank for a shared identity SDK instead of every team writing its own token validation.

## Consequences
- `uv.lock` pins every Python dependency for every lab. `uv sync --locked` in CI fails if the lockfile drifts.
- A lab joins the workspace (`[tool.uv.workspace].members`) once it has Python code.
- A breaking change to `iam_shared` runs every lab's tests, which is intended.
