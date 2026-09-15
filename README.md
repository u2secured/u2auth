# U2 Secured Authenticator SDKs

Client libraries for [U2 Secured Authenticator](https://auth.u2secured.com) — push
tap-to-approve two-factor auth, TOTP, and signed webhooks.

**[Documentation](https://auth.u2secured.com/developer/docs)** ·
**[Get an API key](https://auth.u2secured.com/developer/register)**

## Packages

| Language | Package | Install |
| --- | --- | --- |
| Node.js / TypeScript | [`@u2secured/u2auth`](https://www.npmjs.com/package/@u2secured/u2auth) | `npm install @u2secured/u2auth` |
| Python | [`u2auth`](https://pypi.org/project/u2auth/) | `pip install u2auth` |
| Go | [`u2auth-go`](https://github.com/u2secured/u2auth-go) | `go get github.com/u2secured/u2auth-go` |
| Browser | [`@u2secured/authenticator-client`](https://www.npmjs.com/package/@u2secured/authenticator-client) | `npm install @u2secured/authenticator-client` |
| React Native | [`@u2secured/authenticator-client-react-native`](https://www.npmjs.com/package/@u2secured/authenticator-client-react-native) | `npm install @u2secured/authenticator-client-react-native` |
| C# / .NET | `U2Secured.U2Auth` | not yet published |
| Java | `com.u2secured:u2auth` | not yet published |

The Go SDK lives in its own repository, because a Go module path is its URL and
the module has to sit at the repository root.

Each package directory has its own README with the full API surface.

## Three lines to two-factor

```ts
import { U2Auth, verifyWebhook } from "@u2secured/u2auth";

const client = new U2Auth(process.env.U2_API_KEY);

// Ask the user's phone to approve, and wait for the tap.
const push = await client.requestPush("ada@example.com", "Login from Chrome on macOS");
const result = await client.waitForApproval(push.approval_id);
```

TOTP is validated **locally**, with no round trip to us:

```ts
import { validateTOTP } from "@u2secured/u2auth";

const ok = validateTOTP(secret, userCode);
```

## Verifying webhooks

When a push resolves, U2 Secured POSTs a signed event to your endpoint. Verify it
against the **raw** request body — re-serializing parsed JSON changes the bytes and
breaks the signature:

```ts
const event = verifyWebhook(rawBody, req.headers["x-u2auth-signature"], webhookSecret);
```

Every SDK ships the same helper. It checks the HMAC **and** the signed timestamp,
rejecting anything more than 300 seconds from your clock, so a captured delivery
cannot be replayed indefinitely.

## Shared test vectors

[`testvectors/`](./testvectors) holds fixtures that every SDK and the backend assert
against — one known secret, timestamp, body and signature. They are how a port to a
new language proves it agrees with the reference implementation rather than merely
looking similar.

## About this repository

This is a **published snapshot**. The SDKs are developed in a private monorepo and
exported here on release, so pull requests against this repository would be
overwritten by the next release and cannot be merged.

Bug reports and questions are very welcome — open an issue, or email
[support@u2secured.com](mailto:support@u2secured.com).

## Licence

MIT. See the `LICENSE` file in each package directory.
