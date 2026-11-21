import time

import jwt
import pytest
from iam_shared.jwt_validation import (
    InsufficientScopeError,
    JwksCache,
    TokenValidationError,
    TokenValidator,
    require_scopes,
)
from iam_shared.testing import FakeIssuer

API = "contoso-accounts-api"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer()


@pytest.fixture
def validator(issuer: FakeIssuer) -> TokenValidator:
    return TokenValidator(issuer=issuer.issuer, audience=API, jwks=JwksCache(issuer.jwks))


def _rejects(validator: TokenValidator, token: str, reason: str) -> None:
    with pytest.raises(TokenValidationError, match=reason):
        validator.validate(token)


def test_valid_token_exposes_subject_client_scopes(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    token = validator.validate(issuer.mint(scope="openid accounts:read"))
    assert token.subject == "alice"
    assert token.client_id == "contoso-cli"
    assert token.scopes == {"openid", "accounts:read"}


def test_entra_style_scp_claim_is_understood(validator: TokenValidator, issuer: FakeIssuer) -> None:
    token = validator.validate(issuer.mint(scope=None, scp="Accounts.Read"))
    assert token.scopes == {"Accounts.Read"}


def test_non_string_scope_claim_grants_nothing(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    assert validator.validate(issuer.mint(scope=None)).scopes == frozenset()


def test_audience_may_be_a_list(validator: TokenValidator, issuer: FakeIssuer) -> None:
    assert validator.validate(issuer.mint(audience=["contoso-gateway", API])).subject == "alice"


def test_wrong_audience_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    _rejects(validator, issuer.mint(audience="contoso-payments-api"), "wrong audience")


def test_wrong_issuer_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    _rejects(validator, issuer.mint(iss="http://evil.example/realms/contoso"), "wrong issuer")


def test_expired_beyond_leeway_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    _rejects(validator, issuer.mint(exp=int(time.time()) - 120), "expired")


def test_expired_within_leeway_accepted(validator: TokenValidator, issuer: FakeIssuer) -> None:
    assert validator.validate(issuer.mint(exp=int(time.time()) - 5)).subject == "alice"


def test_not_yet_valid_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    _rejects(validator, issuer.mint(nbf=int(time.time()) + 600), "not yet valid")


def test_missing_exp_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    _rejects(validator, issuer.mint(exp=None), "missing claim: exp")


def test_id_token_cannot_be_used_as_access_token(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    _rejects(validator, issuer.mint(typ="ID"), "not an access token")


def test_alg_none_rejected(validator: TokenValidator, issuer: FakeIssuer) -> None:
    unsigned = jwt.encode(
        {"sub": "alice", "aud": API}, None, algorithm="none", headers={"kid": issuer.kid}
    )
    _rejects(validator, unsigned, "algorithm not allowed")


def test_hmac_token_rejected_before_key_lookup(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    # Algorithm-confusion attempt: attacker signs with HS256 and hopes we verify with our key.
    forged = jwt.encode(
        {"iss": issuer.issuer, "sub": "mallory", "aud": API},
        "attacker-controlled-hmac-key-0123456789",
        algorithm="HS256",
        headers={"kid": issuer.kid},
    )
    _rejects(validator, forged, "algorithm not allowed")


def test_token_signed_by_another_key_rejected(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    imposter = FakeIssuer(issuer=issuer.issuer, kid=issuer.kid)  # same kid, different key
    _rejects(validator, imposter.mint(), "invalid token")


def test_malformed_token_rejected(validator: TokenValidator) -> None:
    _rejects(validator, "not-a-jwt", "malformed")


def test_unknown_kid_triggers_one_rate_limited_refresh(issuer: FakeIssuer) -> None:
    clock = FakeClock()
    rotated = FakeIssuer(issuer=issuer.issuer)
    current = {"jwks": issuer.jwks()}
    cache = JwksCache(lambda: current["jwks"], min_refresh_interval=30, clock=clock)
    validator = TokenValidator(issuer=issuer.issuer, audience=API, jwks=cache)

    assert validator.validate(issuer.mint()).subject == "alice"
    assert cache.refresh_count == 1

    # The IdP rotates its key. Straight away, a new kid can't force another fetch...
    current["jwks"] = rotated.jwks()
    clock.now += 5
    _rejects(validator, rotated.mint(), "unknown signing key")
    assert cache.refresh_count == 1

    # ...but once the rate-limit window passes, one refresh picks up the new key.
    clock.now += 30
    assert validator.validate(rotated.mint()).subject == "alice"
    assert cache.refresh_count == 2


def test_cache_refreshes_after_ttl(issuer: FakeIssuer) -> None:
    clock = FakeClock()
    cache = JwksCache(issuer.jwks, ttl=300, clock=clock)
    cache.get_key(issuer.kid)
    clock.now += 301
    cache.get_key(issuer.kid)
    assert cache.refresh_count == 2


def test_encryption_keys_are_ignored(issuer: FakeIssuer) -> None:
    jwks = issuer.jwks()
    jwks["keys"][0]["use"] = "enc"
    cache = JwksCache(lambda: jwks)
    with pytest.raises(TokenValidationError, match="unknown signing key"):
        cache.get_key(issuer.kid)


def test_jwks_outage_fails_closed(issuer: FakeIssuer) -> None:
    def broken() -> dict[str, object]:
        raise ConnectionError("IdP down")

    validator = TokenValidator(issuer=issuer.issuer, audience=API, jwks=JwksCache(broken))
    _rejects(validator, issuer.mint(), "signing keys unavailable")


def test_require_scopes_reports_what_is_missing(
    validator: TokenValidator, issuer: FakeIssuer
) -> None:
    token = validator.validate(issuer.mint(scope="accounts:read"))
    require_scopes(token, ["accounts:read"])
    with pytest.raises(InsufficientScopeError) as excinfo:
        require_scopes(token, ["accounts:read", "transfers:write"])
    assert excinfo.value.missing == {"transfers:write"}


def test_actor_chain_from_exchanged_token(validator: TokenValidator, issuer: FakeIssuer) -> None:
    token = validator.validate(issuer.mint(act={"sub": "contoso-gateway"}))
    assert token.actor_chain == ["contoso-gateway"]
