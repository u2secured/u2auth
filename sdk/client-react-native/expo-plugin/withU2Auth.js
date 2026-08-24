/**
 * withU2Auth.js — Expo Config Plugin for @u2secured/authenticator-client-react-native
 *
 * Automates the native configuration required by U2AuthClientRN:
 *
 *   iOS
 *   ───
 *   • Adds NSFaceIDUsageDescription to Info.plist (required for Face ID use).
 *   • Ensures the pod `U2AuthClientRN` is available via `pod install`.
 *   • Adds the LocalAuthentication + Security frameworks (handled by the podspec).
 *
 *   Android
 *   ───────
 *   • Adds USE_BIOMETRIC permission to AndroidManifest.xml.
 *   • Documents that U2AuthPackage must be registered in MainApplication.
 *     (Automatic registration via Expo's autolinking is planned but not yet wired.)
 *
 * Usage in app.config.js / app.json:
 *   {
 *     "expo": {
 *       "plugins": [
 *         ["@u2secured/authenticator-client-react-native/expo-plugin/withU2Auth", {
 *           "faceIDPermission": "Allow U2 Secured to verify your identity"
 *         }]
 *       ]
 *     }
 *   }
 */

// @ts-check
const { withInfoPlist, withAndroidManifest } = require("@expo/config-plugins");

const DEFAULT_FACE_ID_PERMISSION =
  "Allow $(PRODUCT_NAME) to use Face ID or Touch ID to approve sign-in requests.";

/**
 * @param {import('@expo/config-plugins').ExpoConfig} config
 * @param {{ faceIDPermission?: string }} [options]
 * @returns {import('@expo/config-plugins').ExpoConfig}
 */
function withU2Auth(config, options = {}) {
  const faceIDPermission =
    options.faceIDPermission ?? DEFAULT_FACE_ID_PERMISSION;

  // ── iOS: Info.plist ────────────────────────────────────────────────────────
  config = withInfoPlist(config, (iosConfig) => {
    // NSFaceIDUsageDescription is required for any use of LAContext on iOS.
    // Omitting it causes a crash on devices with Face ID.
    iosConfig.modResults["NSFaceIDUsageDescription"] = faceIDPermission;
    return iosConfig;
  });

  // ── Android: AndroidManifest.xml ───────────────────────────────────────────
  config = withAndroidManifest(config, (androidConfig) => {
    const manifest = androidConfig.modResults;
    const mainApplication = manifest.manifest;

    // Ensure the permissions array exists.
    if (!mainApplication["uses-permission"]) {
      mainApplication["uses-permission"] = [];
    }

    const permissions = mainApplication["uses-permission"];

    /**
     * @param {string} name
     */
    function addPermissionIfMissing(name) {
      const alreadyPresent = permissions.some(
        (p) => p.$?.["android:name"] === name
      );
      if (!alreadyPresent) {
        permissions.push({ $: { "android:name": name } });
      }
    }

    // USE_BIOMETRIC is the modern replacement for USE_FINGERPRINT (API 28+).
    addPermissionIfMissing("android.permission.USE_BIOMETRIC");
    // USE_FINGERPRINT is still required for BiometricPrompt compat on API < 28.
    addPermissionIfMissing("android.permission.USE_FINGERPRINT");

    return androidConfig;
  });

  return config;
}

module.exports = withU2Auth;
