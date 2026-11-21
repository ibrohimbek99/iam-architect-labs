import time

import jwt
import pytest
from iam_shared.dpop import (
    DpopError,
    DpopKey,
    DpopVerifier,
    access_token_hash,
    jwk_thumbprint,
)

URL = "https://api.contoso.example/accounts/summary"
TOKEN = "access-token-under-test"


@pytest.fixture
def key() -> DpopKey:
    return DpopKey()


@pytest.fixture
def verifier() -> DpopVerifier:
    return DpopVerifier()


def _verify(verifier: DpopVerifier, proof: str, key: DpopKey, **overrides: str) -> None:
    args = {"method": "GET", "url": URL, "access_token": TOKEN, "expected_jkt": key.thumbprint}
    args.update(overrides)
    verifier.verify(proof, **args)


def test_rfc7638_thumbprint_example() -> None:
    # The RSA example key from RFC 7638 §3.1, and its published thumbprint.
    jwk = {
        "kty": "RSA",
        "e": "AQAB",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
            "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
            "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
            "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
    }
    assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_valid_proof_accepted(key: DpopKey, verifier: DpopVerifier) -> None:
    _verify(verifier, key.proof("GET", URL, access_token=TOKEN), key)


def test_query_string_is_ignored_for_htu(key: DpopKey, verifier: DpopVerifier) -> None:
    _verify(verifier, key.proof("GET", URL + "?page=2", access_token=TOKEN), key, url=URL + "?x=1")


def test_replayed_proof_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    proof = key.proof("GET", URL, access_token=TOKEN)
    _verify(verifier, proof, key)
    with pytest.raises(DpopError, match="replayed"):
        _verify(verifier, proof, key)


def test_proof_from_another_key_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    thief = DpopKey()  # has the stolen token, but not the client's private key
    with pytest.raises(DpopError, match="cnf.jkt"):
        _verify(verifier, thief.proof("GET", URL, access_token=TOKEN), key)


def test_wrong_method_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    with pytest.raises(DpopError, match="htm"):
        _verify(verifier, key.proof("POST", URL, access_token=TOKEN), key)


def test_wrong_url_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    other = "https://api.contoso.example/transfers"
    with pytest.raises(DpopError, match="htu"):
        _verify(verifier, key.proof("GET", other, access_token=TOKEN), key)


def test_proof_for_another_token_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    with pytest.raises(DpopError, match="ath"):
        _verify(verifier, key.proof("GET", URL, access_token="some-other-token"), key)


def test_proof_without_ath_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    with pytest.raises(DpopError, match="ath"):
        _verify(verifier, key.proof("GET", URL), key)


def test_old_proof_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    stale = key.proof("GET", URL, access_token=TOKEN, iat=int(time.time()) - 600)
    with pytest.raises(DpopError, match="too old"):
        _verify(verifier, stale, key)


def test_future_proof_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    future = key.proof("GET", URL, access_token=TOKEN, iat=int(time.time()) + 600)
    with pytest.raises(DpopError, match="future"):
        _verify(verifier, future, key)


def test_wrong_typ_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    # A normal JWT (typ=JWT) must not be accepted as a DPoP proof.
    forged = jwt.encode(
        {
            "jti": "1",
            "htm": "GET",
            "htu": URL,
            "iat": int(time.time()),
            "ath": access_token_hash(TOKEN),
        },
        key._private,  # noqa: SLF001 - test reaches into the key on purpose
        algorithm="ES256",
        headers={"typ": "JWT", "jwk": key.public_jwk},
    )
    with pytest.raises(DpopError, match="typ"):
        _verify(verifier, forged, key)


def test_private_key_in_header_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    leaky = dict(key.public_jwk, d="private-part")
    forged = jwt.encode(
        {
            "jti": "2",
            "htm": "GET",
            "htu": URL,
            "iat": int(time.time()),
            "ath": access_token_hash(TOKEN),
        },
        key._private,  # noqa: SLF001
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": leaky},
    )
    with pytest.raises(DpopError, match="private key"):
        _verify(verifier, forged, key)


def test_symmetric_alg_rejected(key: DpopKey, verifier: DpopVerifier) -> None:
    forged = jwt.encode(
        {"jti": "3", "htm": "GET", "htu": URL, "iat": int(time.time())},
        "hmac-secret-that-is-long-enough-0123456789",
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
    )
    with pytest.raises(DpopError, match="algorithm"):
        _verify(verifier, forged, key)
