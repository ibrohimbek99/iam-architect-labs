# Threat model: Lab 01 (Contoso Accounts API + Keycloak flows)

- **Diagram:** [c4.md](c4.md)
- **Assets:** access, refresh and ID tokens; client secrets; authorization codes; account data; audit log.
- **Trust boundaries:**
  - browser ↔ Keycloak
  - loopback redirect ↔ CLI
  - clients ↔ Keycloak token endpoint
  - gateway ↔ Accounts API
  - API ↔ JWKS endpoint

| # | STRIDE | Threat | Where | Mitigation in this lab | Test that proves it | Residual risk |
|---|---|---|---|---|---|---|
| 1 | Spoofing | Forged token with `alg: none` / HS256-with-public-key | API | Algorithm allow-list checked before key lookup | `test_alg_none_rejected`, `test_hmac_token_rejected_before_key_lookup` | — |
| 2 | Spoofing | Token signed by an attacker's key that reuses a valid `kid` | API | Signature verified against the issuer's JWKS only | `test_token_signed_by_another_key_rejected` | IdP key compromise |
| 3 | Spoofing | Token minted for another API replayed here | API | Exact `aud` check | `test_wrong_audience_rejected`, `test_token_for_another_audience_is_rejected_by_api` | — |
| 4 | Spoofing | ID token presented as an access token | API | `typ` check + `aud` | `test_id_token_cannot_be_used_as_access_token` | IdPs that don't set `typ` (use RFC 9068 `at+jwt`) |
| 5 | Tampering | Authorization code intercepted and redeemed | Redirect | PKCE S256 required by the realm | `test_public_client_must_use_pkce`, RFC 7636 vector | — |
| 6 | Tampering | Code delivered to an attacker-controlled redirect | Keycloak | One exact loopback redirect URI | `test_unknown_redirect_uri_is_refused` | Malware on the device |
| 7 | Spoofing | CSRF / login injection on the callback; IdP mix-up | CLI | `state`, `nonce`, RFC 9207 `iss` checks | Manual run (`make login`) | — |
| 8 | Elevation of privilege | Stolen refresh token used indefinitely | Keycloak | Rotation + reuse detection (`maxReuse=0`) | Manual run: reuse → `invalid_grant` | Theft before first use |
| 9 | Elevation of privilege | Intercepted token exchanged for a new audience | Keycloak | Requester must be in subject `aud` | `test_exchange_rejected_when_requester_not_in_subject_audience` | — |
| 10 | Elevation of privilege | **Exchange upscopes** beyond the subject token | Keycloak | *Not mitigated by default.* Documented and pinned by test | `test_keycloak_exchange_scopes_are_bounded_by_requester_not_subject` | **Open:** add the downscope client policy |
| 11 | Elevation of privilege | Valid token missing scope calls a write endpoint | API | Per-endpoint scope check → 403 | `test_missing_scope_is_403_insufficient_scope` | — |
| 12 | Information disclosure | Tokens in logs or terminals | API, flows | Central redaction; flows print claims only | `test_audit_log_records_decisions_without_tokens`, redaction tests | Developer debug prints |
| 13 | Information disclosure | Error messages reveal why validation failed | API | Generic body; reason only in the audit log | `test_invalid_token_is_401_and_reason_not_leaked` | — |
| 14 | Denial of service | Random-`kid` flood makes the API hammer the IdP | API | JWKS refresh rate limit (30 s) | `test_unknown_kid_triggers_one_rate_limited_refresh` | Volumetric DoS (out of scope) |
| 15 | Denial of service | JWKS endpoint down | API | Fail closed (401), cached keys reused within TTL | `test_jwks_outage_fails_closed` | Availability during long outages |
| 17 | Spoofing | Stolen access token replayed from an attacker's machine | API | **DPoP**: proof signed by the key in `cnf.jkt`; Bearer downgrade refused | `test_stolen_token_with_thiefs_key_is_rejected`, `test_bound_token_downgraded_to_bearer_is_rejected`, `test_dpop_token_is_bound_to_client_key` | Client key theft (keep keys non-exportable) |
| 18 | Tampering | Captured DPoP request replayed, or proof reused at another endpoint | API | `jti` replay cache, `iat` window, `htm`/`htu`/`ath` binding | `test_replayed_request_is_rejected`, `test_proof_for_another_endpoint_is_rejected` | Replay cache is per-process (use a shared cache when scaled out) |
| 16 | Repudiation | No record of who was allowed or denied | API | Audit event per decision, with subject + actor chain | `test_audit_log_records_decisions_without_tokens` | Log integrity (append-only storage in Lab 02) |
