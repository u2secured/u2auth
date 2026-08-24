# u2auth

Python SDK for the U2Auth platform — TOTP verification, push approvals, and local TOTP helpers.

## Install

```bash
pip install u2auth
```

## Quick Start

```python
from u2auth import Client, generate_secret, generate_qr_code_uri

client = Client("rka_your_api_key")
result = client.verify_totp("BASE32SECRET", "123456")
push = client.request_push("user@example.com", "Login from Chrome")
status = client.get_push_status(push["approval_id"])
secret = generate_secret()
uri = generate_qr_code_uri("MyApp", "user@example.com", secret)
```

## API Reference

### `Client(api_key, *, base_url?)`

Sync API client. `base_url` defaults to `https://app.u2secured.io`.

### `client.verify_totp(secret, code) -> dict`

Calls `POST /api/v1/sdk/totp/verify`. Returns `{"valid": bool}`.

### `client.request_push(user_identifier, context, *, webhook_url?, ttl?) -> dict`

Calls `POST /api/v1/sdk/push/request`. Returns `{approval_id, status, expires_at}`.

`user_identifier` matching is case-sensitive and otherwise unnormalised — it's your own key into
your system, not ours, so folding case could silently merge two genuinely different users. Pass
the exact same string here as the one given to `create_pairing_code`. A mismatch (most often a
casing difference) raises `U2AuthError` with code `ENROLMENT_NOT_FOUND` — no enrolment at all for
that identifier — which is distinct from `NO_DEVICE` (enrolled, but no confirmed device yet).

### `client.get_push_status(approval_id) -> dict`

Calls `GET /api/v1/sdk/push/{id}/status`. Returns `{approval_id, status}`.

### `client.delete_enrolment(user_identifier) -> None`

Calls `DELETE /api/v1/sdk/enrolments`. Raises `U2AuthError` with code `ENROLMENT_NOT_FOUND` if there was none.

### `client.list_enrolments(*, limit=25, cursor="", sort="created_at", order="desc") -> dict`

Calls `GET /api/v1/sdk/enrolments`. The app is resolved from the API key — there is no `app_id` parameter. Returns `{"items": [...], "next_cursor": "..."}`.

`sort` is one of `"created_at"`, `"user_identifier"`, `"last_auth_at"`; `order` is `"asc"` or `"desc"`. `next_cursor` is opaque and bound to the `sort`/`order` that minted it — pass it back verbatim on the next call. Replaying it under a different `sort`/`order` raises `U2AuthError` with code `INVALID_CURSOR`. `limit <= 0` is treated as unset and omitted from the query, same as an empty `cursor`; a `limit` outside `1..100` raises code `INVALID_LIMIT`.

For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both `None` rather than a zero time / empty string.

### `client.list_enrolment_events(enrolment_id, *, limit=25, cursor="") -> dict`

Calls `GET /api/v1/sdk/enrolments/{enrolment_id}/events`. Returns `{"items": [...], "next_cursor": "..."}`.

`limit <= 0` is treated as unset and omitted from the query, same as an empty `cursor`. Raises `U2AuthError` with code `ENROLMENT_NOT_FOUND` if there is no such enrolment, `INVALID_LIMIT` if `limit` is outside `1..100`, or `INVALID_CURSOR` if `cursor` is malformed or was minted for a different enrolment. Each event's `place` is a coarse, city-level location (`{"city", "region", "country"}` — never a coordinate) or `None` when no fix was captured; `region` can legitimately be an empty string, which is distinct from a `None` place.

```python
cursor = ""
while True:
    page = client.list_enrolments(limit=50, cursor=cursor)
    for enrolment in page["items"]:
        print(enrolment["user_identifier"], enrolment["last_auth_at"])
    if not page["next_cursor"]:
        break
    cursor = page["next_cursor"]
```

### Helpers (no API call)

```python
generate_secret(byte_len=20) -> str
generate_qr_code_uri(issuer, account, secret, *, algorithm="SHA1", digits=6, period=30) -> str
generate_recovery_codes(count=10) -> list[str]
```

### Error Handling

API errors raise `U2AuthError` with `.status_code` and `.code` attributes.

## Verifying webhooks

```python
from u2auth import verify_webhook, U2AuthError

try:
    event = verify_webhook(raw_body, request.headers["X-U2Auth-Signature"], webhook_secret)
except U2AuthError:
    ...  # reject: bad signature or stale timestamp
# event.approval_id, event.status, event.reason, event.resolved_at
```

Pass the **raw request body** (bytes/str), not a re-serialized dict. Handlers should dedupe on `event.approval_id`.

The push-request response includes `match_number` (the 2-digit number to show on your login page); `get_push_status` returns `status` plus `reason`/`resolved_at` once resolved.
