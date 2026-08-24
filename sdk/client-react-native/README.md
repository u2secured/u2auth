# @u2secured/authenticator-client-react-native

React Native implementation of the U2 Secured Authenticator client SDK.

Wraps the verified TypeScript core (`@u2secured/authenticator-client`) with
React Native native modules that provide:

| Interface | Native backing |
|---|---|
| `KeyStore` | iOS Secure Enclave P-256 / Android Keystore EC P-256 |
| `Biometric` | iOS LAContext (Face ID / Touch ID) / Android BiometricPrompt |
| `PushTokens` | APNs token (iOS) / FCM registration token (Android) |

---

## Install

```bash
npm install @u2secured/authenticator-client-react-native \
            @u2secured/authenticator-client
```

### iOS

```bash
cd ios && pod install
```

Add `NSFaceIDUsageDescription` to your `Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Allow $(PRODUCT_NAME) to verify your identity when approving sign-in requests.</string>
```

### Android

Add permissions to `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

Register `U2AuthPackage` in `MainApplication`:

```kotlin
override fun getPackages(): List<ReactPackage> =
    PackageList(this).packages.apply {
        add(U2AuthPackage())
    }
```

### Expo

```js
// app.config.js
export default {
  expo: {
    plugins: [
      ["@u2secured/authenticator-client-react-native/expo-plugin/withU2Auth", {
        faceIDPermission: "Allow $(PRODUCT_NAME) to verify your identity."
      }]
    ]
  }
}
```

---

## Usage

```ts
import {
  createU2AuthClient,
  RNPushTokens,
} from '@u2secured/authenticator-client-react-native';

// 1. Create the client — biometric: true gates approvals with Face ID / fingerprint.
const client = createU2AuthClient({
  baseUrl: 'https://auth.u2secured.com',
  getAccessToken: () => getMyStoredJwt(),
  biometric: true,
});

// 2. On first launch: register this device.
//    The host app must have configured FCM (Android) / APNs (iOS) first.
const push = new RNPushTokens();
const fcmToken = await push.getToken();
const { device_id } = await client.registerDevice('My iPhone 15', fcmToken);
// Persist device_id and pass it as cfg.deviceId on subsequent launches.

// 3. Poll or receive push for pending approvals.
const approvals = await client.listPendingApprovals();

// 4. Respond — the biometric prompt fires automatically before the request is sent.
if (approvals.length > 0) {
  await client.respond(approvals[0].approval_id, 'approved', {
    selectedNumber: approvals[0].candidates[0],
  });
}
```

### Low-level usage (KeyStore + Biometric directly)

```ts
import {
  RNKeyStore,
  RNBiometric,
  U2AuthClient,
} from '@u2secured/authenticator-client-react-native';

const keyStore = new RNKeyStore();
const publicKey = await keyStore.ensureKeyPair();  // base64 X9.63 / X.509 DER

const challenge = new TextEncoder().encode('hello');
const signature = await keyStore.sign(challenge);  // Uint8Array DER ECDSA sig

const bio = new RNBiometric();
const ok = await bio.authenticate('Confirm your identity');
```

---

## Native build status

> **TS layer: typechecked (`tsc --noEmit` passes).**

> **Native modules (iOS Swift + Android Kotlin) are written and correct to the
> best of our knowledge, but REQUIRE an on-device Xcode / Gradle build to
> verify.** They cannot be compiled in a CI sandbox without macOS + Xcode for
> iOS or an Android SDK / emulator for Android. Native correctness must be
> validated on a physical or emulated device before shipping.

Specifically:

- `ios/U2AuthKeystore.swift` — P-256 key via `SecKeyCreateRandomKey` +
  `kSecAttrTokenIDSecureEnclave`; signing via `SecKeyCreateSignature`.
- `ios/U2AuthBiometric.swift` — `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics…)`.
- `ios/U2AuthPush.swift` — reads APNs token from `UserDefaults`; host app must
  store it under `"U2AuthAPNsToken"` or be replaced with a firebase call.
- `android/.../U2AuthKeystoreModule.kt` — Android Keystore EC P-256 with
  `setUserAuthenticationRequired(true)`; `SHA256withECDSA`.
- `android/.../U2AuthBiometricModule.kt` — `androidx.biometric.BiometricPrompt`.
- `android/.../U2AuthPushModule.kt` — reads FCM token from `SharedPreferences`.

---

## License

MIT
