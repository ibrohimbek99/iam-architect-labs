# infra/terraform

| Path | Purpose |
|---|---|
| `modules/` | Reusable modules (GitHub OIDC role, SCP guardrails, permission sets), added by Labs 04 and 05 |
| `live/plan-only/` | Root module that wires modules together. Its provider runs with **no credentials** |
| `.tflint.hcl` | Lint rules (Terraform ruleset today; the AWS ruleset is added in Lab 05) |

**Plan-only by default** ([ADR-0003](../../docs/adr/0003-local-first-cloud-policy.md)): `make tf-validate`, `tflint`, `checkov` and `terraform plan` work without an AWS account. There is no `apply` target. Any real apply happens in a personal account, after an explicit go-ahead, with a cost estimate and a teardown script.
