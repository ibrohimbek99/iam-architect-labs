# Glossary

Short definitions. Each term's lab LEARN.md goes deeper.

| Term | Meaning |
|---|---|
| **ABAC / PBAC / ReBAC** | Attribute-, policy- and relationship-based access control. Access is decided at request time from attributes, policies or a relationship graph, instead of only from static roles |
| **`act` claim** | RFC 8693 claim naming who is acting on behalf of the token's `sub`. Nested `act` claims record a delegation chain |
| **AuthZEN** | OpenID Foundation API between a policy enforcement point (PEP) and a policy decision point (PDP) |
| **CAEP / RISC / SSF** | OpenID Shared Signals: event streams that tell relying parties a session was revoked, credentials changed, or an account is at risk |
| **CIBA** | Client-Initiated Backchannel Authentication: a client asks for a user's approval out-of-band (for example, a push on their phone) |
| **DPoP** | RFC 9449: binds a token to a client-held key, so a stolen token is useless without that key |
| **ID-JAG** | Identity Assertion JWT Authorization Grant: an IdP-issued assertion an agent or app trades for an access token at another app. The basis of enterprise-managed MCP authorization and Okta Cross App Access |
| **IGA** | Identity governance and administration: lifecycle, access requests, certifications, SoD |
| **ITDR** | Identity threat detection and response |
| **JIT / ZSP** | Just-in-time access and zero standing privilege: elevated access is granted for a bounded time on request, and nothing privileged is held by default |
| **MCP** | Model Context Protocol: how AI clients discover and call tools. Its authorization model makes the MCP server an OAuth resource server |
| **NHI** | Non-human identity: service accounts, API keys, OAuth clients, workloads, bots and AI agents |
| **OBO** | On-behalf-of: Microsoft's flow for a middle-tier API to call a downstream API as the signed-in user |
| **PEP / PDP / PIP / PAP** | Enforcement, decision, information and administration points of an authorization system |
| **PKCE** | RFC 7636 proof key that stops authorization-code interception |
| **Prompt injection** | Instructions hidden in input (direct) or in retrieved content and tool output (indirect) that hijack a model |
| **RAG** | Retrieval-augmented generation: fetch relevant documents, then have the model answer from them |
| **RAR** | RFC 9396 Rich Authorization Requests: structured, fine-grained authorization details, such as approving one specific payment |
| **Resource indicators** | RFC 8707 `resource` parameter that binds a token to one API (audience) |
| **SPIFFE / SVID** | A workload identity standard and its short-lived identity documents |
| **Token exchange** | RFC 8693: trade one token for another, for delegation (`act`) or impersonation |
| **Token vault** | A broker that holds users' long-lived third-party tokens so agents only ever get short-lived ones |
