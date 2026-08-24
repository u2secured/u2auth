"""Tests for u2auth.helpers."""

import base64
import string
import pytest
from u2auth.helpers import generate_secret, generate_qr_code_uri, generate_recovery_codes


class TestGenerateSecret:
    def test_returns_string(self):
        assert isinstance(generate_secret(), str)

    def test_is_valid_base32(self):
        secret = generate_secret(20)
        # Pad to multiple of 8 and decode
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        decoded = base64.b32decode(padded)
        assert len(decoded) == 20

    def test_default_length_is_nonzero(self):
        assert len(generate_secret()) > 0

    def test_uniqueness(self):
        secrets = {generate_secret() for _ in range(20)}
        assert len(secrets) == 20

    def test_custom_byte_len(self):
        short = generate_secret(10)
        long_ = generate_secret(40)
        assert len(long_) > len(short)


class TestGenerateQRCodeURI:
    def test_starts_with_prefix(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "SECRET")
        assert uri.startswith("otpauth://totp/")

    def test_contains_secret(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "MYSECRET")
        assert "secret=MYSECRET" in uri

    def test_contains_issuer(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "SECRET")
        assert "issuer=MyApp" in uri

    def test_default_algorithm(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "SECRET")
        assert "algorithm=SHA1" in uri

    def test_default_digits(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "SECRET")
        assert "digits=6" in uri

    def test_default_period(self):
        uri = generate_qr_code_uri("MyApp", "user@example.com", "SECRET")
        assert "period=30" in uri

    def test_custom_options(self):
        uri = generate_qr_code_uri(
            "MyApp", "user@example.com", "SECRET",
            algorithm="SHA256", digits=8, period=60
        )
        assert "algorithm=SHA256" in uri
        assert "digits=8" in uri
        assert "period=60" in uri


class TestGenerateRecoveryCodes:
    def test_default_count(self):
        codes = generate_recovery_codes()
        assert len(codes) == 10

    def test_custom_count(self):
        codes = generate_recovery_codes(5)
        assert len(codes) == 5

    def test_each_code_is_8_chars(self):
        for code in generate_recovery_codes(10):
            assert len(code) == 8, f"code {code!r} is not 8 chars"

    def test_codes_are_alphanumeric(self):
        charset = set(string.ascii_uppercase + string.digits)
        for code in generate_recovery_codes(10):
            for ch in code:
                assert ch in charset, f"invalid char {ch!r} in {code!r}"

    def test_uniqueness(self):
        codes = generate_recovery_codes(20)
        assert len(set(codes)) == 20
