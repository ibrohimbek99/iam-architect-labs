# 0003. Local-first; cloud is optional, personal-account-only, plan-only

- Status: Accepted
- Date: 2026-11-20

## Context
The labs demonstrate cloud IAM (AWS, Entra) and SaaS federation (Okta, PingOne). Cloud resources cost money and can leak data if misconfigured. A public portfolio must never contain anything from an employer's environment: tenant IDs, domains, app names, screenshots or configuration. It also has to keep working after the author changes jobs.

## Options
1. **Use whatever cloud is at hand, including employer test environments.** Gives instant access to premium features. But it risks exposing employer data, the work may count as the employer's IP, it may breach acceptable-use policy, and the portfolio breaks once that access ends.
2. **Personal cloud accounts for everything.** Clean ownership. But it costs money, and someone has to remember to tear things down.
3. **Local-first, with optional personal-account cloud tracks.**
   - The core of every lab runs on Docker (Keycloak, Vault, Postgres, an OPA/Cedar PDP, a local LLM).
   - Terraform runs `fmt / validate / tflint / checkov / plan` with no credentials.
   - Real cloud steps live behind a feature flag, use the author's **personal** free-tier accounts and tenants, and each comes with a cost estimate and a teardown script.

## Decision
Option 3. CI and `make check` never need a cloud credential. Any `terraform apply` or cloud account creation is a deliberate, approved and budgeted step. **No work devices, work accounts or work tenants are used for anything in this repo.**

## Consequences
- The AWS provider is configured with `skip_credentials_validation` / `skip_requesting_account_id` / `skip_metadata_api_check`, so `plan` can't reach a real account by accident.
- The Makefile has no `apply` target.
- Entra steps (app roles, on-behalf-of) use a personal free Entra tenant. Features that need P2 are described, with their licensing called out, rather than required.
- Okta and PingOne steps use free developer or trial tenants created only when Lab 07 starts, because trials expire.
