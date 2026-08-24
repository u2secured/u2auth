"""Local TOTP helpers — no network calls."""

import base64
import hashlib
import hmac
import os
import secrets
import string
import struct
import time
from typing import Optional
from urllib.parse import urlencode, quote


def generate_secret(byte_len: int = 20) -> str:
    """Generate a cryptographically random base32-encoded TOTP secret."""
    raw = os.urandom(byte_len)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def generate_qr_code_uri(
    issuer: str,
    account: str,
    secret: str,
    *,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
) -> str:
    """Build an otpauth://totp/... URI suitable for QR code display."""
    label = f"{quote(issuer)}:{quote(account)}"
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Generate count random 8-character alphanumeric recovery codes."""
    charset = string.ascii_uppercase + string.digits
    return [
        "".join(secrets.choice(charset) for _ in range(8))
        for _ in range(count)
    ]


def _decode_totp_secret(secret: str) -> bytes:
    """Accept padded and unpadded base32, in either case."""
    s = secret.strip().upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def generate_totp(
    secret: str,
    at: Optional[float] = None,
    digits: int = 6,
    period_sec: int = 30,
) -> str:
    """Compute the RFC 6238 code for a secret at a Unix instant.

    Exposed mainly so tests can drive a fixed clock; most callers want
    :func:`validate_totp`.
    """
    at = time.time() if at is None else at
    counter = int(at // period_sec)
    mac = hmac.new(
        _decode_totp_secret(secret), struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def validate_totp(
    secret: str,
    code: str,
    at: Optional[float] = None,
    digits: int = 6,
    period_sec: int = 30,
) -> bool:
    """Verify a TOTP code locally, without a network call.

    Runs the same RFC 6238 check the U2 Secured Authenticator backend runs,
    including the +/-1 window tolerance for clock drift, and returns the same
    answer -- the shared vectors in ``sdk/testvectors/totp.json`` are asserted
    against the backend's own implementation to keep the two from drifting.
    Prefer this when a login must not depend on a third party being reachable:
    the developer's backend already holds the secret, so no round trip is
    required to check a code.

    What it does NOT provide, and ``client.verify_totp()`` does:

    * the shared brute-force lockout, which spans all your backend instances
    * an entry in the Activity feed of the developer portal

    Neither call protects against replay on its own -- a code stays valid for
    its whole window. Bind a successful check to a single login attempt.
    """
    at = time.time() if at is None else at
    supplied = code.strip()
    ok = False
    for delta in (-1, 0, 1):
        candidate = generate_totp(secret, at + delta * period_sec, digits, period_sec)
        # Compare every window with no early return, so neither the matching
        # window nor the number of correct digits leaks through timing.
        if hmac.compare_digest(candidate, supplied):
            ok = True
    return ok
