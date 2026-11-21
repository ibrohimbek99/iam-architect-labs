# Zero-trust map (NIST SP 800-207)

This document maps each NIST SP 800-207 zero-trust tenet (paraphrased) to the lab that demonstrates it. It gets filled in as each lab ships; final pass in Phase 10.

| # | Tenet (paraphrased) | Demonstrated in | How |
|---|---|---|---|
| 1 | Every data source and service is a resource | 01, 02, 04 | APIs, MCP tools and databases each have their own audience and policy |
| 2 | All communication is secured regardless of network location | _tbd_ | |
| 3 | Access is granted per session, with least privilege | 02, 03 | Short-lived, narrowly scoped tokens; JIT elevation |
| 4 | Access is decided by dynamic policy (identity, device, context) | 03, 08 | PDP evaluates attributes per request; permission-aware retrieval |
| 5 | The posture of every asset is monitored | _tbd_ | |
| 6 | Authentication and authorization are dynamic and enforced before access | 01, 02, 06 | Token validation at every PEP; CAEP revocation |
| 7 | Telemetry is collected to improve posture | all | `iam_shared` audit events |
