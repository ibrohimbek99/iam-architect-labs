# Lab 01: LEARN

## Concepts in plain words

**Access token vs ID token vs refresh token.**
- The **ID token** tells the *client* who logged in (audience = the client).
- The **access token** tells an *API* what the caller may do (audience = the API).
- The **refresh token** lets the client get new access tokens without a new login.

Each has exactly one consumer. Using one in place of another is a bug and often a vulnerability: for example, an API that accepts ID tokens trusts tokens minted for someone else.

**Validation is the API's job, every time.** The gateway or the IdP being "trusted" doesn't change that. The resource server checks:
1. the signature against the issuer's JWKS
2. the algorithm, against *its own* allow-list
3. `iss`, which must equal the expected issuer exactly
4. `aud`, which must contain *this* API
5. `exp` / `nbf`, with seconds of skew, not minutes
6. the token type
7. the scopes for the endpoint

A failure in checks 1–6 gives **401 `invalid_token`**. Missing scopes give **403 `insufficient_scope`** (RFC 6750 §3.1).

**PKCE.** The client invents a random `code_verifier` and sends its SHA-256 hash (`code_challenge`) with the login request. To redeem the code it must present the verifier itself. A code stolen from a redirect (by a malicious app on the same device, or through logs or a referrer) is useless without the verifier. OAuth 2.1 and RFC 9700 require PKCE for *all* clients, not just public ones.

**`state`, `nonce`, `iss`** are three different defenses:
- `state` binds the callback to the browser session that started the login (CSRF / login injection).
- `nonce` binds the ID token to that login (stops ID-token replay).
- `iss` in the redirect (RFC 9207) tells you which authorization server answered (stops IdP mix-up attacks).

**Refresh-token rotation.** Every refresh returns a new refresh token, and the old one dies. If the old one is ever presented again, someone has a copy. A good AS then revokes the whole session ("reuse detection"). In this lab, reuse is rejected with `invalid_grant`.

**Client credentials.** A workload authenticates as itself. There's no user and no refresh token, because the workload can always re-authenticate. The `sub` is the client's *service account*. Govern it like any other non-human identity: an owner, rotation, least privilege (Lab 04).

**Token exchange (RFC 8693).** A service trades the token it received for one aimed at the next hop: a different audience, fewer scopes, and its own client as `azp`.
- **Delegation:** the new token says "the gateway acting for X" and carries `act`.
- **Impersonation:** the new token just says "X", with no trace of the gateway.

Delegation keeps the audit trail honest. Impersonation erases it.

## Keycloak behaviors worth knowing
Verified against Keycloak 26.8.2 and pinned by tests in [`tests/integration/`](tests/integration/).

1. **Exchanged scopes are bounded by the requesting client, not the subject token.** `contoso-batch` held a token with only `gateway:call`. The gateway exchanged it and got `accounts:read`, because the gateway client is allowed that scope. That's *upscoping*. If your threat model needs "exchange can only narrow", add the client-policy executor that enforces downscoping, which Keycloak's token-exchange docs describe. Treat that as the bank default.
2. **The requester must be in the subject token's `aud`.** A token without `contoso-gateway` in `aud` can't be exchanged by the gateway. That's the control that stops any random client from exchanging tokens it intercepted.
3. **No `basic` client scope means no `sub` claim** (Keycloak 25+). If a realm import lists `clientScopes`, Keycloak doesn't create its defaults, so include `basic` yourself.
4. **`iss` follows the request host.** Getting tokens from `http://127.0.0.1:8080` and validating against `http://localhost:8080` fails with "wrong issuer". In production, pin `KC_HOSTNAME`.
5. **Impersonation isn't in standard token exchange V2.** It exists only in the deprecated legacy V1 (preview). **Delegation with `act`** arrived as a *preview* in 26.8. Lab 02 builds the agent delegation chain in its own small STS, where nested `act` is under our control.
6. **Typ claim.** Keycloak marks tokens with `typ` (`Bearer`, `ID`, `Refresh`). The validator rejects anything that isn't an access token.

## Pitfalls (each one has broken a real system)

| Pitfall | Why it's dangerous | Fix in this lab |
|---|---|---|
| Accepting the algorithm named in the token header | `alg: none` or HS256-with-public-key forgeries | Allow-list `RS256/PS256/ES256`, checked before key lookup |
| Fetching the JWKS on every unknown `kid` | An attacker floods random kids and your API DoSes the IdP | One refresh per 30 s at most |
| Skipping `aud` | A token for API A works at API B | `aud` must contain this API exactly |
| Generous clock skew ("5 minutes is fine") | Stretches every token's life, and revocation lags | 30 s leeway |
| Error bodies that explain *why* | Gives attackers an oracle | Generic `invalid token`; the reason goes to the audit log |
| Logging tokens "for debugging" | Logs become a credential store | Central redaction; the flows print claims only |
| `plain` PKCE or no PKCE | Code interception | S256 required in the realm (test proves it) |
| Redirect URI wildcards | Codes delivered to attacker URLs | One exact loopback URI (test proves others are refused) |
| Refresh tokens that never rotate | One theft = indefinite access | Rotation with reuse detection |

## 10 interview Q&As

1. **How does a resource server validate a JWT access token?**
   Pin the algorithms, then fetch and cache the issuer's JWKS and pick the key by `kid`. Verify the signature, then check `iss`, `aud`, `exp`/`nbf` (small skew), and the token type. Then authorize on scopes or roles. A failure before authorization is 401; missing scope is 403.
2. **Why PKCE if the client has a secret?**
   PKCE protects the *code in transit*, which a client secret doesn't. It also stops authorization-code injection. OAuth 2.1 / RFC 9700 make it mandatory for every client.
3. **`state` vs `nonce`?**
   `state` protects the redirect (CSRF / login injection) and is checked by the client on callback. `nonce` protects the ID token (replay) and is checked inside the ID token.
4. **What does refresh-token rotation buy you, and what's reuse detection?**
   Rotation shrinks a stolen refresh token's window to one use. Reuse detection treats a second use of the same token as a breach signal and kills the session.
5. **Delegation vs impersonation in token exchange?**
   Delegation keeps both identities: `sub` = the user, `act` = the service acting for them. APIs can authorize and audit both. Impersonation produces a token indistinguishable from the user's. Prefer delegation, and restrict impersonation to break-glass with heavy audit.
6. **Why must the requester be in the subject token's `aud` for exchange?**
   Otherwise any client that intercepts a token could launder it into a token for a new audience. Audience scoping is what makes the token's *intended recipient* the only one who can exchange it.
7. **An API team asks you to accept ID tokens because "they already have them". Answer?**
   No. The ID token's audience is the client, not the API, and it isn't meant for authorization. Issue access tokens with the API in `aud`. Check the `typ` / RFC 9068 `at+jwt` header to make the mistake impossible.
8. **How do you handle IdP signing-key rotation without downtime?**
   The IdP publishes the new key in its JWKS before it starts signing with it. Resource servers cache the JWKS with a TTL and refresh on an unknown `kid`, rate-limited. Old keys stay published until tokens signed with them have expired.
9. **Client credentials for 200 batch jobs: what governance do you put around it?**
   - one client per workload (never shared)
   - an accountable owner
   - private_key_jwt or workload federation instead of shared secrets
   - least-privilege scopes
   - rotation, and alerts on unused clients
   - inventory in IGA (Lab 04 / Lab 09)
10. **How would you prevent token exchange from *escalating* privilege?**
    Allow-list which clients may exchange and for which audiences, and require the requester in the subject's `aud`. Enforce downscope-only (in Keycloak, a client-policy executor). Prefer delegation so `act` is auditable. Keep exchanged tokens short-lived and audience-bound. Lab 01 shows Keycloak *permits* upscoping by default, which is exactly why this question matters.

## Try it yourself
- Set `refreshTokenMaxReuse` to `1` in the realm and watch rotation become weaker.
- Remove `pkce.code.challenge.method` from `contoso-cli` and see whether `test_public_client_must_use_pkce` still passes.
- Add the downscope-enforcing client policy and make `test_keycloak_exchange_scopes_are_bounded_by_requester_not_subject` fail, which is the goal.
