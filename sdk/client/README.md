# @u2secured/authenticator-client

Framework-agnostic TypeScript core for embedding tap-to-approve into your app using [U2 Secured Authenticator](https://u2secured.com).

## What this package is

This is the **core** SDK: typed API client for device registration, listing pending approvals, and approve/deny with number-match selection. It has no native dependencies.

Platform-bound surfaces (`KeyStore`, `Biometric`, `PushTokens`) are **host-injected interfaces** — you provide implementations for your platform. React Native / iOS / Android packages that fulfil these interfaces are a follow-on requiring the mobile toolchain and are not part of this package.

## Usage

```ts
import { U2AuthClient } from "@u2secured/authenticator-client";

const client = new U2AuthClient(
  {
    baseUrl: "https://auth.u2secured.com",
    getAccessToken: () => yourAuthStore.getJwt(),
  },
  yourBiometricImpl, // optional — host-injected Biometric; omit to skip biometric gate
);

// Register this device once (e.g. on first launch)
const { device_id } = await client.registerDevice("Alice's iPhone", fcmToken);
console.log("Registered device:", device_id);

// Poll or push-triggered: fetch pending approvals
const approvals = await client.listPendingApprovals();

// User taps "Approve" — biometric gate fires automatically if biometric was provided
await client.respond(approvals[0].approval_id, "approved", {
  selectedNumber: 42,
});
```
