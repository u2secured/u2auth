# @u2secured/u2auth

Node.js/TypeScript SDK for the U2Auth platform — TOTP verification, push approvals, and local TOTP helpers.

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
- `baseURL?: string` — override API base URL (default: `https://app.u2secured.io`)

### `client.verifyTOTP(secret, code): Promise<VerifyResult>`

Calls `POST /api/v1/sdk/totp/verify`. Returns `{ valid: boolean }`.

### `client.requestPush(userIdentifier, context, opts?): Promise<PushResult>`

Calls `POST /api/v1/sdk/push/request`. `PushOptions`: `webhook_url?`, `ttl?`.
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

`ListEnrolmentsOptions`: `limit?`, `cursor?`, `sort?` (`"created_at"` | `"user_identifier"` | `"last_auth_at"`), `order?` (`"asc"` | `"desc"`). Omitted options are left off the query entirely, so the request carries only what the caller asked for; `limit <= 0` is treated as unset for this purpose too. A `limit` outside `1..100` throws a `U2AuthError` with code `"INVALID_LIMIT"`. A page's `next_cursor` is opaque and bound to the `sort`/`order` that minted it; pass it back verbatim — replaying it under a different `sort`/`order` throws a `U2AuthError` with code `"INVALID_CURSOR"`.

For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both `null` rather than a zero time / empty string.

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

### Helpers (no API call)

```typescript
generateSecret(byteLen?: number): string
generateQRCodeURI(issuer, account, secret, opts?: QRCodeOptions): string
generateRecoveryCodes(count?: number): string[]
```

`QRCodeOptions`: `algorithm?` (default SHA1), `digits?` (default 6), `period?` (default 30).

### Error Handling

API errors throw `U2AuthError` with `.statusCode` and `.code` properties.

## Verifying webhooks

```ts
import { verifyWebhook } from "@u2secured/u2auth";

const event = verifyWebhook(rawBody, req.headers["x-u2auth-signature"], webhookSecret);
// throws U2AuthError on a bad signature or stale timestamp
// event.approval_id, event.status, event.reason, event.resolved_at
```

Pass the **raw request body** (string/Buffer), not a parsed object. Handlers should dedupe on `event.approval_id`.
