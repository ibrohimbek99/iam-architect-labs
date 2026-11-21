# Modules

Each module has `variables.tf`, `outputs.tf`, a README with inputs and outputs, and least-privilege defaults. Planned:

- `github-oidc-role`: keyless GitHub Actions → AWS federation, with trust scoped to repo and branch (Lab 04)
- `org-guardrails`: SCPs and resource control policies (Lab 05)
- `identity-center-permission-sets`: role-based permission sets with permission boundaries (Lab 05)
