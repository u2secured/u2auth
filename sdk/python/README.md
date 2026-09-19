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

## Linked approvals

"Linked approvals" is link-then-push: a user links their phone to *your* account once (via a
pairing code), and afterwards you call `request_push` directly against their `user_identifier` —
no code re-entry required.

```python
# 1. Mint a code and show it to the signed-in user (e.g. as text + a QR code).
pairing = client.create_pairing_code("user@example.com")
# {"code": "af17-b500", "expires_at": "2026-09-15T10:10:00Z"}

# 2. The user opens the U2 Secured app and redeems the code there. Meanwhile,
#    poll its status from the BROWSER, not from a blocking Python call --
#    see the wait_for_link warning below.
status = client.get_pairing_code_status(pairing["code"])
# {"status": "pending" | "redeemed" | "expired", "enrolment_id": "en_1"}

# 3. Once redeemed, the identifier is linked. From then on, request push
#    directly -- no pairing code involved.
push = client.request_push("user@example.com", "Login from Chrome")
```

### `client.get_enrolment(user_identifier) -> dict | None`

Looks up this app's enrolment for one user identifier. **Returns `None` when the user is not
linked — it never raises.** At login, "this user has not linked a phone" is the normal answer,
not an error; forcing every caller into try/except on the common path is how integrations end up
wrapping everything in a broad `except` and swallowing real errors too. This is deliberately
unlike `delete_enrolment`, where the absence genuinely is the anomaly and it raises
`ENROLMENT_NOT_FOUND`.

```python
enrolment = client.get_enrolment("user@example.com")
if enrolment is None:
    ...  # show a "link your phone" prompt
elif enrolment["push_ready"]:
    push = client.request_push("user@example.com", "Login from Chrome")
```

Returns a dict with `id`, `user_identifier`, `created_at`, `last_auth_at`, `last_auth_outcome`,
`push_ready`. For an enrolment that has never authenticated, `last_auth_at` and
`last_auth_outcome` are both `None` rather than a zero time / empty string.

### `client.get_pairing_code_status(code) -> dict`

Reads where a pairing code is in its lifecycle. Returns `{"status": ..., "enrolment_id": ...}`,
where `status` is `"pending"`, `"redeemed"` or `"expired"`. A code that never existed, and one
belonging to another app, both read as `"expired"` — distinguishing them would make this endpoint
a probing oracle.

### `client.wait_for_link(code, *, user_identifier, interval=2.0, timeout=120.0) -> dict`

Blocking convenience helper that mirrors `wait_for_approval` — same shape, same polling
structure — so a developer who has used one can use the other without re-reading the docs. Polls
`get_pairing_code_status` until the code is redeemed, then fetches and returns the resulting
**enrolment** (not just the status — that's why `user_identifier` is required: the status
response alone doesn't carry enough to look the enrolment up).

`user_identifier` is a required keyword argument — a type hint is not a runtime check in Python,
so an empty string is rejected explicitly, raising `U2AuthError` with code
`MISSING_USER_IDENTIFIER`, rather than silently dropping itself out of the eventual
`get_enrolment` lookup and risking an unrelated result.

Raises `U2AuthError` with code `PAIRING_CODE_EXPIRED` if the code lapses before redemption,
`LINK_TIMEOUT` if the deadline passes while it's still pending — mirroring `wait_for_approval`'s
`WAIT_TIMEOUT` — or `ENROLMENT_NOT_FOUND` if the code comes back `redeemed` but no matching
enrolment can be found for `user_identifier`. That last one is rare but reachable: redemption and
the enrolment lookup are two separate backend calls, and they can disagree.

```python
enrolment = client.wait_for_link(pairing["code"], user_identifier="user@example.com")
```

> **This blocks the calling process, exactly like `wait_for_approval`.** A site that calls
> `wait_for_link` from inside a request a user's browser is waiting on will tie up that worker for
> the entire timeout — 120 seconds by default. Poll `get_pairing_code_status` from the browser on
> an interval instead, and reserve `wait_for_link` for a background worker.

## API Reference

### `Client(api_key, *, base_url?)`

Sync API client. `base_url` defaults to `https://app.u2secured.io`.

### `client.verify_totp(secret, code) -> dict`

Calls `POST /api/v1/sdk/totp/verify`. Returns `{"valid": bool}`.

### `client.request_push(user_identifier, context, *, webhook_url?, ttl?, idempotency_key?) -> dict`

Calls `POST /api/v1/sdk/push/request`. Returns `{approval_id, status, expires_at}`.

`user_identifier` matching is case-sensitive and otherwise unnormalised — it's your own key into
your system, not ours, so folding case could silently merge two genuinely different users. Pass
the exact same string here as the one given to `create_pairing_code`. A mismatch (most often a
casing difference) raises `U2AuthError` with code `ENROLMENT_NOT_FOUND` — no enrolment at all for
that identifier — which is distinct from `NO_DEVICE` (enrolled, but no confirmed device yet).

Pass `idempotency_key` to suppress duplicate requests. While the approval is
still pending, repeating the call with the same key returns the original —
same `approval_id`, same `match_number`, and no second notification:

```python
push = client.request_push("user@example.com", "Login from Chrome", idempotency_key=form_nonce)
```

The key frees itself once the approval is approved, denied or expired, so a
genuine retry after that mints a new request. This is **not** Stripe-style
idempotency: there is no fixed replay window and no stored-response replay.

Reusing a live key for a different request raises `U2AuthError` with code
`IDEMPOTENCY_KEY_REUSED`. A key longer than 255 characters raises
`U2AuthError` with code `INVALID_IDEMPOTENCY_KEY`.

The SDK never generates this key for you — a key invented per call would not
be stable across a retry, so derive it from whatever identifies the attempt
in your own system (e.g. a nonce rendered into the login form).

### `client.get_push_status(approval_id) -> dict`

Calls `GET /api/v1/sdk/push/{id}/status`. Returns `{approval_id, status}`.

### `client.create_pairing_code(user_identifier) -> dict`

Calls `POST /api/v1/sdk/pairing-codes`. Mints a code binding `user_identifier` to whichever
account redeems it in the U2 Secured app. Returns `{"code": ..., "expires_at": ...}`. See
[Linked approvals](#linked-approvals) above.

### `client.delete_enrolment(user_identifier) -> None`

Calls `DELETE /api/v1/sdk/enrolments`. Raises `U2AuthError` with code `ENROLMENT_NOT_FOUND` if there was none.

### `client.list_enrolments(*, limit=25, cursor="", sort="created_at", order="desc", user_identifier="") -> dict`

Calls `GET /api/v1/sdk/enrolments`. The app is resolved from the API key — there is no `app_id` parameter. Returns `{"items": [...], "next_cursor": "..."}`.

`sort` is one of `"created_at"`, `"user_identifier"`, `"last_auth_at"`; `order` is `"asc"` or `"desc"`. `next_cursor` is opaque and bound to the `sort`/`order` that minted it — pass it back verbatim on the next call. Replaying it under a different `sort`/`order` raises `U2AuthError` with code `INVALID_CURSOR`. `limit <= 0` is treated as unset and omitted from the query, same as an empty `cursor`; a `limit` outside `1..100` raises code `INVALID_LIMIT`. `user_identifier`, when given, filters to that one identifier — only `""` is treated as unset, so a developer-chosen identifier that happens to be the literal string `"0"` is not silently dropped.

For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both `None` rather than a zero time / empty string. Each item also carries `push_ready` (`bool`): whether the enrolment has a confirmed device that can currently receive a push, distinct from being linked at all.

### `client.get_enrolment(user_identifier) -> dict | None`

See [Linked approvals](#linked-approvals) above.

### `client.get_pairing_code_status(code) -> dict`

See [Linked approvals](#linked-approvals) above.

### `client.wait_for_link(code, *, user_identifier, interval=2.0, timeout=120.0) -> dict`

See [Linked approvals](#linked-approvals) above.

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
