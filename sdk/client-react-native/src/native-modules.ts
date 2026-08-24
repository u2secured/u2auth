/**
 * native-modules.ts
 *
 * Typed wrappers over the React Native bridge for the U2 Secured
 * hardware-backed keystore and biometric native modules.
 *
 * Bridge contract
 * ───────────────
 * The JS<->Native bridge can only carry JSON-serialisable values, so
 * Uint8Array is converted to/from base64 strings at this boundary.
 *
 * iOS  → ios/U2AuthKeystore.swift  + ios/U2AuthBiometric.swift
 * Android → android/.../U2AuthKeystoreModule.kt + U2AuthBiometricModule.kt
 */

import { NativeModules } from "react-native";
import type { KeyStore, Biometric } from "@u2secured/authenticator-client";

// ---------------------------------------------------------------------------
// Typed bridge interfaces (what the native side exposes)
// ---------------------------------------------------------------------------

interface NativeU2AuthKeystore {
  /** Generate or retrieve the device P-256 keypair; returns the public key as base64. */
  ensureKeyPair(): Promise<string>;
  /** Sign base64-encoded data with the device private key; returns base64 signature. */
  sign(base64Data: string): Promise<string>;
}

interface NativeU2AuthBiometric {
  /** Prompt the user for biometric authentication; resolves true/false. */
  authenticate(reason: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Retrieve the native modules (runtime error if the native build is missing)
// ---------------------------------------------------------------------------

function requireNativeModule<T>(name: string): T {
  const mod = (NativeModules as Record<string, unknown>)[name] as T | undefined;
  if (!mod) {
    throw new Error(
      `[U2Auth] Native module "${name}" is not available. ` +
        "Ensure the package is linked (pod install / Gradle sync) and that " +
        "you are running on a real device or emulator, not a JS-only environment."
    );
  }
  return mod;
}

// Lazily resolved so importing this module in a plain Node/test env does not
// immediately throw — only the first actual call will.
let _keystoreMod: NativeU2AuthKeystore | null = null;
let _biometricMod: NativeU2AuthBiometric | null = null;

function getKeystoreMod(): NativeU2AuthKeystore {
  if (!_keystoreMod) {
    _keystoreMod = requireNativeModule<NativeU2AuthKeystore>("U2AuthKeystore");
  }
  return _keystoreMod;
}

function getBiometricMod(): NativeU2AuthBiometric {
  if (!_biometricMod) {
    _biometricMod = requireNativeModule<NativeU2AuthBiometric>("U2AuthBiometric");
  }
  return _biometricMod;
}

// ---------------------------------------------------------------------------
// Base64 <-> Uint8Array helpers
// ---------------------------------------------------------------------------

/** Encode a Uint8Array to a base64 string for the native bridge. */
function uint8ToBase64(bytes: Uint8Array): string {
  // In React Native the global `btoa` is available; fall back to Buffer in Node.
  if (typeof btoa === "function") {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  // Node / test environment fallback
  return Buffer.from(bytes).toString("base64");
}

/** Decode a base64 string from the native bridge to a Uint8Array. */
function base64ToUint8(b64: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// ---------------------------------------------------------------------------
// RNKeyStore — implements the core KeyStore interface
// ---------------------------------------------------------------------------

/**
 * Hardware-backed keypair backed by:
 *   iOS    — Secure Enclave P-256 key (access-controlled by biometry)
 *   Android — Android Keystore EC P-256 key (setUserAuthenticationRequired)
 *
 * The private key NEVER leaves the secure hardware.
 */
export class RNKeyStore implements KeyStore {
  /**
   * Ensure the device key exists and return the public key as base64.
   * On first call this generates a new key; subsequent calls return the cached key.
   */
  async ensureKeyPair(): Promise<string> {
    return getKeystoreMod().ensureKeyPair();
  }

  /**
   * Sign `data` with the device private key.
   * The bridge transports the payload as base64; conversion happens here so
   * the core SDK always sees Uint8Array on both sides.
   *
   * Returns the DER-encoded ECDSA signature.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const b64Input = uint8ToBase64(data);
    const b64Sig = await getKeystoreMod().sign(b64Input);
    return base64ToUint8(b64Sig);
  }
}

// ---------------------------------------------------------------------------
// RNBiometric — implements the core Biometric interface
// ---------------------------------------------------------------------------

/**
 * Biometric gate backed by:
 *   iOS    — LAContext (Face ID / Touch ID)
 *   Android — androidx.biometric.BiometricPrompt
 */
export class RNBiometric implements Biometric {
  /**
   * Show the system biometric prompt with `reason` as the descriptive text.
   * Resolves `true` when authentication succeeds, `false` when the user
   * cancels or the device falls back (e.g. passcode fallback not permitted).
   */
  async authenticate(reason: string): Promise<boolean> {
    return getBiometricMod().authenticate(reason);
  }
}
