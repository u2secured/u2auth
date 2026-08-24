"""Webhook signature verification for RK Auth."""
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Optional, Union

from .client import U2AuthError


@dataclass
class WebhookEvent:
    approval_id: str
    status: str
    reason: Optional[str] = None
    resolved_at: Optional[str] = None


def verify_webhook(
    payload: Union[bytes, str],
    sig_header: str,
    secret: str,
    tolerance: int = 300,
) -> WebhookEvent:
    """Verify the X-U2Auth-Signature over the RAW payload; return the parsed event or raise U2AuthError."""
    body = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload
    t, v1 = _parse_sig_header(sig_header)
    expected = hmac.new(secret.encode("utf-8"), f"{t}.{body}".encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise U2AuthError(0, "INVALID_SIGNATURE", "invalid webhook signature")
    if abs(int(time.time()) - t) > tolerance:
        raise U2AuthError(0, "TIMESTAMP_OUT_OF_TOLERANCE", "webhook timestamp out of tolerance")
    data = json.loads(body)
    return WebhookEvent(
        approval_id=data["approval_id"],
        status=data["status"],
        reason=data.get("reason"),
        resolved_at=data.get("resolved_at"),
    )


def _parse_sig_header(h: str):
    t = None
    v1 = None
    for part in h.split(","):
        kv = part.strip().split("=", 1)
        if len(kv) != 2:
            continue
        if kv[0] == "t":
            t = int(kv[1])
        elif kv[0] == "v1":
            v1 = kv[1]
    if t is None or v1 is None:
        raise U2AuthError(0, "INVALID_SIGNATURE", "malformed signature header")
    return t, v1
