# Lab 01 ADR-0001. Keycloak standard token exchange (V2) for per-hop audience narrowing

- Status: Accepted
- Date: 2026-11-21

## Context
Lab 01 must show RFC 8693 token exchange the way a bank would run it: an intermediary (the gateway) trades the token it received for one scoped to the next API. Keycloak 26.8.2 offers three mechanisms with different maturity levels, and Lab 02 will need a delegation chain (`act`, nested) for AI agents.

## Options
1. **Standard token exchange V2.** Supported and enabled by default.
   - Gives internal-to-internal exchange with audience filtering and client re-binding.
   - No impersonation, and delegation isn't part of it.
   - Scopes are bounded by the requesting client (it can upscope unless a policy blocks that).
2. **Legacy token exchange V1.** Preview and deprecated.
   - Adds impersonation (`requested_subject`) and external exchange.
   - Depends on fine-grained admin permissions V1.
   - Building on a deprecated feature is a poor architectural signal.
3. **Delegation preview (26.8: `token-exchange-delegation` + `parameterized-scopes`).**
   - Emits `act`, which is exactly the right shape.
   - But it's preview, needs fine-grained admin permissions V2 and consent, and chain nesting isn't documented.
4. **A minimal STS written for the labs.**
   - Full control over nested `act`, `may_act` and DPoP binding.
   - But it isn't what enterprises deploy, and it's easy to get subtly wrong.

## Decision
- **Lab 01 uses option 1.** It's the supported path and it demonstrates the key control: the requester must be in the subject's `aud`, and the output is bound to one audience and re-bound to the gateway.
- **Lab 02 uses option 4** for agent delegation chains, where nested `act` and DPoP must be demonstrable and tested.
- **Option 3 is an optional experiment** once it leaves preview.
- **Option 2 is not used.**

## Consequences
- Lab 01 tests pin Keycloak's *upscoping* behavior so that a future change (or adding the downscope policy) is visible.
- Impersonation is taught as a concept and an anti-pattern, not as a demo.
- Lab 02 has to show the minimal STS is safe: tests for chain depth, `may_act`, audience binding and expiry.
