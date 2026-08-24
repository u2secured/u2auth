/**
 * On-device hardware-backed keypair (iOS Keychain / Android Keystore).
 * The host provides it — this SDK declares the interface only.
 */
export interface KeyStore {
  /** Ensure a device keypair exists; returns the public key (base64). */
  ensureKeyPair(): Promise<string>;
  /** Sign a challenge with the private key (never leaves the device). */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Biometric gate (Face ID / Touch ID / fingerprint).
 * The host provides it — this SDK declares the interface only.
 */
export interface Biometric {
  authenticate(reason: string): Promise<boolean>;
}

/**
 * Push token source (FCM / APNs).
 * The host provides it — this SDK declares the interface only.
 */
export interface PushTokens {
  getToken(): Promise<string>;
}
