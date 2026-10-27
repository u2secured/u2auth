# @u2secured/u2auth

Node.js/TypeScript SDK for the U2Auth platform — TOTP verification, push approvals, and local TOTP helpers.

Part of [U2 Secured Authenticator](https://u2secured.com/authenticator) · [Documentation](https://auth.u2secured.com/developer/docs)

## Install

```bash
npm install @u2secured/u2auth
```

## Quick Start

```typescript
import { U2Auth, generateSecret, generateQRCodeURI } from "@u2secured/u2auth";

const client = new U2Auth("rka_your_api_key");
const result = await client.verifyTOTP("BASE32SECRET", "123456");
const push = await client.requestPush("user@example.com", "Login from Chrome");
const status = await client.getPushStatus(push.approval_id);
const secret = generateSecret();
const uri = generateQRCodeURI("MyApp", "user@example.com", secret);
```

## API Reference

### `new U2Auth(apiKey, opts?)`

`ClientOptions`:
- `baseURL?: string` — override API base URL (default: `https://auth.u2secured.com`)

### `client.verifyTOTP(secret, code): Promise<VerifyResult>`

Calls `POST /api/v1/sdk/totp/verify`. Returns `{ valid: boolean }`.

### `client.requestPush(userIdentifier, context, opts?): Promise<PushResult>`

Calls `POST /api/v1/sdk/push/request`. `PushOptions`: `webhook_url?`, `ttl?`, `idempotency_key?`.
Returns `{ approval_id, status, expires_at }`.

`userIdentifier` matching is case-sensitive and otherwise unnormalised — it's your own key into
your system, not ours, so folding case could silently merge two genuinely different users. Pass
the exact same string here as the one given to `createPairingCode`. A mismatch (most often a
casing difference) throws a `U2AuthError` with code `"ENROLMENT_NOT_FOUND"` — no enrolment at all
for that identifier — which is distinct from `"NO_DEVICE"` (enrolled, but no confirmed device yet).

### `client.getPushStatus(approvalId): Promise<PushStatus>`

Calls `GET /api/v1/sdk/push/{id}/status`. Returns `{ approval_id, status }`.

### `client.listEnrolments(opts?): Promise<Page<Enrolment>>`

Calls `GET /api/v1/sdk/enrolments`. The app is resolved from the API key — there is no `app_id` parameter.

`ListEnrolmentsOptions`: `limit?`, `cursor?`, `sort?` (`"created_at"` | `"user_identifier"` | `"last_auth_at"`), `order?` (`"asc"` | `"desc"`), `user_identifier?`. Omitted options are left off the query entirely, so the request carries only what the caller asked for; `limit <= 0` is treated as unset for this purpose too. A `limit` outside `1..100` throws a `U2AuthError` with code `"INVALID_LIMIT"`. A page's `next_cursor` is opaque and bound to the `sort`/`order` that minted it; pass it back verbatim — replaying it under a different `sort`/`order` throws a `U2AuthError` with code `"INVALID_CURSOR"`.

For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both `null` rather than a zero time / empty string. `push_ready` indicates whether the enrolment has a confirmed device that can receive `requestPush` (see [Linked approvals](#linked-approvals) below).

```typescript
let cursor: string | undefined;
for (;;) {
  const page = await client.listEnrolments({ limit: 50, cursor });
  for (const e of page.items) console.log(e.user_identifier, e.last_auth_at);
  if (!page.next_cursor) break;
  cursor = page.next_cursor;
}
```

### `client.listEnrolmentEvents(enrolmentId, opts?): Promise<Page<EnrolmentEvent>>`

Calls `GET /api/v1/sdk/enrolments/{enrolmentId}/events`. Lists the authentication events recorded for one enrolment.

`opts`: `limit?`, `cursor?` — same omit-if-unset rules as `listEnrolments` (`limit <= 0` is treated as unset too), and the same opaque-cursor handling. Throws a `U2AuthError` with code `"ENROLMENT_NOT_FOUND"` if there is no such enrolment, `"INVALID_LIMIT"` if `limit` is outside `1..100`, or `"INVALID_CURSOR"` if `cursor` is malformed or was minted for a different enrolment. An `EnrolmentEvent`'s `place` is a coarse, city-level location (`{ city, region, country }`, never a coordinate) or `null` when no fix was captured; `region` can legitimately be an empty string, which is distinct from a `null` place.

```typescript
let cursor: string | undefined;
for (;;) {
  const page = await client.listEnrolmentEvents(enrolmentId, { limit: 50, cursor });
  for (const ev of page.items) console.log(ev.kind, ev.outcome, ev.place);
  if (!page.next_cursor) break;
  cursor = page.next_cursor;
}
```

### Linked approvals

"Linked approvals" is link-then-push: a user links their phone to *your* account once (via a
pairing code), and afterwards you call `requestPush` directly against their `user_identifier` —
no code re-entry required.

```typescript
// 1. Mint a code and show it to the signed-in user (e.g. as text + a QR code).
const pairing = await client.createPairingCode("user@example.com");
// { code: "af17-b500", expires_at: "2026-09-15T10:10:00Z" }

// 2. The user opens the U2 Secured app and redeems the code there. From a
//    request handler, poll its status yourself on an interval:
const status = await client.getPairingCodeStatus(pairing.code);
// { status: "pending" | "redeemed" | "expired", enrolment_id?: "en_1" }

// ...or, from something that already owns a dedicated process or long timeout
// budget (a worker, a CLI script — never a request handler), block until it
// resolves:
const enrolment = await client.waitForLink(pairing.code, {
  userIdentifier: "user@example.com",
});

// 3. Once linked, request push directly — no pairing code involved.
const push = await client.requestPush("user@example.com", "Login from Chrome");
```

### `client.getEnrolment(userIdentifier): Promise<Enrolment | null>`

Looks up this app's enrolment for one user identifier. **Resolves to `null` when the user is not
linked — it does not reject.** At login, "this user has not linked a phone" is the normal answer,
not an error; forcing every caller into try/catch on the common path is how integrations end up
swallowing real errors too. This is deliberately unlike `deleteEnrolment`, where the absence
genuinely is the anomaly and it rejects with `ENROLMENT_NOT_FOUND`.

```typescript
const enrolment = await client.getEnrolment("user@example.com");
if (enrolment === null) {
  // show a "link your phone" prompt
} else if (enrolment.push_ready) {
  const push = await client.requestPush("user@example.com", "Login from Chrome");
}
```

Returns an `Enrolment`: `{ id, user_identifier, created_at, last_auth_at, last_auth_outcome, push_ready }`.
For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both
`null` rather than a zero time / empty string.

### `client.getPairingCodeStatus(code): Promise<PairingCodeStatus>`

Reads where a pairing code is in its lifecycle. Returns `{ status, enrolment_id? }`, where `status`
is `"pending"`, `"redeemed"` or `"expired"`. A code that never existed, and one belonging to another
app, both read as `"expired"`.

### `client.waitForLink(code, opts): Promise<Enrolment>`

Blocking convenience helper that mirrors `waitForApproval` — same options shape, same polling
structure — so a caller familiar with one can use the other without re-reading the docs. Polls
`getPairingCodeStatus` until the code is redeemed, then fetches and returns the resulting
**enrolment** (not just the status — that's why `userIdentifier` is required: the status response
alone doesn't carry enough to look the enrolment up).

`WaitForLinkOptions`:
- `userIdentifier: string` — **required.** The identifier the code was minted for. Rejects with
  `U2AuthError` code `"MISSING_USER_IDENTIFIER"` if omitted or empty, before any request is made —
  never silently defaulted, matching all five other SDKs.
- `intervalMs?: number` — poll interval (default `2000`)
- `timeoutMs?: number` — give up after this long (default `120000`)
- `signal?: AbortSignal` — abort early; rejects with code `"ABORTED"`

The type says `userIdentifier` is required, but the check is a runtime one too, and deliberately so:
TypeScript types are erased at compile time and this package is published to npm. A
plain-JavaScript caller, a TypeScript caller with `strictNullChecks` off, or anyone passing an
`any`-typed or JSON-sourced options object reaches `waitForLink` with `userIdentifier` undefined.
Without the check that undefined would drop the `user_identifier` filter out of the underlying
`listEnrolments` query and resolve with the app's *first* enrolment — another user's — silently, on
a login path.

Otherwise rejects with a `U2AuthError`, code `"PAIRING_CODE_EXPIRED"` if the code lapses before redemption,
`"LINK_TIMEOUT"` if the deadline passes while it's still pending — mirroring `waitForApproval`'s
`"WAIT_TIMEOUT"` — or `"ENROLMENT_NOT_FOUND"` if the code comes back redeemed but no matching
enrolment can be found for `userIdentifier`. That last one is rare but reachable: redemption and the
enrolment lookup are two separate backend calls, and they can disagree.

> **`waitForLink` blocks the calling process, exactly like `waitForApproval`.** It belongs in a
> worker or a script with its own timeout budget — never in a request handler a user's browser is
> waiting on. Blocking there for up to `timeoutMs` (120 seconds by default) ties up that request for
> the whole wait and, under load, can exhaust your server's request-handling capacity. Poll
> `getPairingCodeStatus` on an interval from the browser instead.

### `client.createPairingCode(userIdentifier): Promise<PairingCode>`

Calls `POST /api/v1/sdk/pairing-codes`. Mints a code binding `userIdentifier` to whichever account
redeems it in the U2 Secured app. Returns `{ code, expires_at }`.

### Helpers (no API call)

```typescript
generateSecret(byteLen?: number): string
generateQRCodeURI(issuer, account, secret, opts?: QRCodeOptions): string
generateRecoveryCodes(count?: number): string[]
```

`QRCodeOptions`: `algorithm?` (default SHA1), `digits?` (default 6), `period?` (default 30).

### Error Handling

API errors throw `U2AuthError` with `.statusCode` and `.code` properties.

Pass the idempotency option to suppress duplicate requests. While the approval is
still pending, repeating the call with the same key returns the original — same
`approval_id`, same `match_number`, and no second notification:

```ts
const push = await client.requestPush("user@example.com", "Login from Chrome", {
  idempotency_key: formNonce,
});
```

The key frees itself once the approval is approved, denied or expired, so a
genuine retry after that mints a new request. This is **not** Stripe-style
idempotency: there is no fixed replay window and no stored-response replay.

The key must be stable across the retry, so the SDK cannot invent one for you: a
key minted inside the call is a new key every call and protects nothing. Mint a
nonce when the login form is rendered and carry it in a hidden field — a
double-click and a back-then-resubmit both send the same one, while a fresh page
load mints a new one.

Reusing a live key for a different request raises `U2AuthError` with code `IDEMPOTENCY_KEY_REUSED`; a key over
255 characters raises `INVALID_IDEMPOTENCY_KEY`.

## Verifying webhooks

```ts
import { verifyWebhook } from "@u2secured/u2auth";

const event = verifyWebhook(rawBody, req.headers["x-u2auth-signature"], webhookSecret);
// throws U2AuthError on a bad signature or stale timestamp
// event.approval_id, event.status, event.reason, event.resolved_at
```

Pass the **raw request body** (string/Buffer), not a parsed object. Handlers should dedupe on `event.approval_id`.
