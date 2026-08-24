/**
 * @u2secured/authenticator-client-react-native
 *
 * React Native implementation of the U2 Secured Authenticator client SDK.
 *
 * Provides hardware-backed KeyStore, biometric gate, and push-token source
 * through React Native native modules, and a convenience factory that wires
 * them into the core U2AuthClient.
 */

export { RNKeyStore, RNBiometric } from "./native-modules.js";
export { RNPushTokens } from "./push.js";
export { createU2AuthClient } from "./factory.js";

// Re-export the core's public types so consumers only need this package.
export type {
  ClientConfig,
  PendingApproval,
  ApprovalAction,
  RespondOptions,
  KeyStore,
  Biometric,
  PushTokens,
} from "@u2secured/authenticator-client";
export { U2AuthClient } from "@u2secured/authenticator-client";
