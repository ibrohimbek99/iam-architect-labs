import re

from lab01.pkce import code_challenge_s256, new_code_verifier, new_state


def test_rfc7636_appendix_b_vector() -> None:
    # The worked example from RFC 7636 Appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_verifier_is_valid_length_and_charset() -> None:
    verifier = new_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert re.fullmatch(r"[A-Za-z0-9\-._~]+", verifier)


def test_values_are_unique_per_attempt() -> None:
    assert new_code_verifier() != new_code_verifier()
    assert new_state() != new_state()
