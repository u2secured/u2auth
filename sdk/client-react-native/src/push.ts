/**
 * push.ts
 *
 * RNPushTokens — implements the core PushTokens interface over a native module
 * that exposes the platform push token (FCM on Android, APNs on iOS).
 *
 * Host app responsibility
 * ───────────────────────
 * The host application is responsible for:
 *   iOS    — requesting APNs permission (UNUserNotificationCenter) and
 *             registering for remote notifications. The native module reads
 *             the token from UIApplication.shared.
 *   Android — initialising the Firebase SDK (google-services.json / FirebaseApp)
 *             and granting POST_NOTIFICATIONS permission (Android 13+).
 *             The native module fetches the FCM registration token.
 *
 * Without those host-app steps getToken() will reject with a descriptive error.
 *
 * Bridge
 * ──────
 * iOS  → ios/U2AuthPush.swift   (to be added when APNs polling is implemented)
 * Android → android/.../U2AuthPushModule.kt
 */

import { NativeModules } from "react-native";
import type { PushTokens } from "@u2secured/authenticator-client";

interface NativeU2AuthPush {
  /** Return the current FCM/APNs token; rejects if not yet available. */
  getToken(): Promise<string>;
}

let _pushMod: NativeU2AuthPush | null = null;

function getPushMod(): NativeU2AuthPush {
  if (!_pushMod) {
    const mod = (NativeModules as Record<string, unknown>)["U2AuthPush"] as
      | NativeU2AuthPush
      | undefined;
    if (!mod) {
      throw new Error(
        "[U2Auth] Native module \"U2AuthPush\" is not available. " +
          "Ensure the package is linked and the host app has configured " +
          "FCM (Android) / APNs (iOS) before calling getToken()."
      );
    }
    _pushMod = mod;
  }
  return _pushMod;
}

/**
 * RNPushTokens reads the platform push token through the U2AuthPush native module.
 *
 * Usage:
 *   const push = new RNPushTokens();
 *   const token = await push.getToken();   // call after host-app FCM/APNs setup
 */
export class RNPushTokens implements PushTokens {
  /**
   * Return the FCM (Android) or APNs (iOS) push token for this device.
   *
   * Call this after the host app has finished push-notification initialisation.
   * Rejects with a descriptive error when the token is not yet available.
   */
  async getToken(): Promise<string> {
    return getPushMod().getToken();
  }
}
