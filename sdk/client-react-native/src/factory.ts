/**
 * factory.ts
 *
 * Convenience factory that constructs a fully-wired U2AuthClient using
 * the React Native native implementations of KeyStore, Biometric, and PushTokens.
 */

import { U2AuthClient } from "@u2secured/authenticator-client";
import type { ClientConfig } from "@u2secured/authenticator-client";
import { RNBiometric } from "./native-modules.js";

export interface RNClientConfig extends ClientConfig {
  /**
   * When true the client will use RNBiometric to gate approval responses.
   * If false or omitted, approvals are sent without biometric verification.
   */
  biometric?: boolean;
}

/**
 * Create a U2AuthClient wired to React Native native implementations.
 *
 * @example
 * ```ts
 * import { createU2AuthClient } from '@u2secured/authenticator-client-react-native';
 *
 * const client = createU2AuthClient({
 *   baseUrl: 'https://auth.u2secured.com',
 *   getAccessToken: () => getMyStoredJwt(),
 *   biometric: true,           // gate approvals with Face ID / fingerprint
 * });
 *
 * // Register this device on first launch
 * const push = new RNPushTokens();
 * const fcmToken = await push.getToken();
 * const { device_id } = await client.registerDevice('My iPhone', fcmToken);
 *
 * // Poll / receive push for pending approvals
 * const [approval] = await client.listPendingApprovals();
 *
 * // Respond (biometric prompt shown automatically when biometric:true)
 * await client.respond(approval.approval_id, 'approved', {
 *   selectedNumber: approval.candidates[0],
 * });
 * ```
 */
export function createU2AuthClient(config: RNClientConfig): U2AuthClient {
  const biometric = config.biometric ? new RNBiometric() : undefined;
  return new U2AuthClient(config, biometric);
}
