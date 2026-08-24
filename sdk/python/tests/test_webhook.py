import json
from pathlib import Path

import pytest

from u2auth import verify_webhook
from u2auth.client import U2AuthError

VECTOR = json.loads((Path(__file__).resolve().parents[2] / "testvectors" / "webhook.json").read_text())
BIG = 10 ** 12  # huge tolerance so the 2023 vector timestamp doesn't trip the check


def test_valid_signature_returns_event():
    ev = verify_webhook(VECTOR["body"], VECTOR["signature_header"], VECTOR["secret"], tolerance=BIG)
    assert ev.approval_id == "ap_test123"
    assert ev.status == "approved"
    assert ev.reason == "user_approved"


def test_tampered_body_raises():
    with pytest.raises(U2AuthError):
        verify_webhook(VECTOR["body"] + " ", VECTOR["signature_header"], VECTOR["secret"], tolerance=BIG)


def test_wrong_secret_raises():
    with pytest.raises(U2AuthError):
        verify_webhook(VECTOR["body"], VECTOR["signature_header"], "wrong", tolerance=BIG)


def test_expired_timestamp_raises():
    with pytest.raises(U2AuthError):
        verify_webhook(VECTOR["body"], VECTOR["signature_header"], VECTOR["secret"])  # default 300s
