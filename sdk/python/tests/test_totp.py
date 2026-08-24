import json
import os

import pytest

from u2auth import generate_secret, generate_totp, validate_totp

VECTORS = json.load(
    open(os.path.join(os.path.dirname(__file__), "..", "..", "testvectors", "totp.json"))
)


# The same vectors the backend asserts itself against — this is what stops
# local validation answering differently from the server.
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_validate_totp_matches_shared_vectors(case):
    got = validate_totp(
        case["secret"], case["code"], case["time"], VECTORS["digits"], VECTORS["period_sec"]
    )
    assert got is case["valid"]


def test_round_trip():
    secret = generate_secret()
    now = 1700000000.0
    assert validate_totp(secret, generate_totp(secret, now), now) is True


@pytest.mark.parametrize("code", ["", "12345", "abcdef"])
def test_malformed_code_is_rejected(code):
    assert validate_totp(generate_secret(), code, 1700000000.0) is False


def test_whitespace_around_the_typed_code_is_tolerated():
    secret = generate_secret()
    now = 1700000000.0
    assert validate_totp(secret, f"  {generate_totp(secret, now)} ", now) is True
