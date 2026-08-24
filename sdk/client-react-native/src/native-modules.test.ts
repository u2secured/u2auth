/**
 * native-modules.test.ts
 *
 * Runtime unit tests for the JS↔Native bridge layer.
 *
 * Strategy
 * ────────
 * The source files (`native-modules.ts`, `push.ts`) cache the native module
 * reference in module-level `let` variables on first use.  To prevent leakage
 * between test suites we call `vi.resetModules()` before each suite and
 * re-import the module under test so every suite gets a fresh (uncached) copy.
 *
 * Native modules are mocked via `vi.doMock('react-native', ...)` before the
 * dynamic import so that when the source file calls
 *   `import { NativeModules } from 'react-native'`
 * it receives our mock object.
 *
 * The @u2secured/authenticator-client peer dep is NOT called in these tests
 * so no extra mock is needed for it.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode bytes to base64 the same way the source does (Buffer path in Node). */
function b64(bytes: number[]): string {
  return Buffer.from(new Uint8Array(bytes)).toString("base64");
}

/** Decode a base64 string to an array of byte values for comparison. */
function fromB64(s: string): number[] {
  return Array.from(Buffer.from(s, "base64"));
}

// ---------------------------------------------------------------------------
// RNKeyStore tests
// ---------------------------------------------------------------------------

describe("RNKeyStore", () => {
  // Shared mock functions — recreated for every test.
  let mockEnsureKeyPair: ReturnType<typeof vi.fn>;
  let mockSign: ReturnType<typeof vi.fn>;

  // Lazily imported module — re-imported fresh for every test so the
  // module-level `_keystoreMod` cache starts null.
  let RNKeyStore: typeof import("./native-modules.js").RNKeyStore;

  beforeEach(async () => {
    mockEnsureKeyPair = vi.fn();
    mockSign = vi.fn();

    vi.resetModules();
    vi.doMock("react-native", () => ({
      NativeModules: {
        U2AuthKeystore: {
          ensureKeyPair: mockEnsureKeyPair,
          sign: mockSign,
        },
        U2AuthBiometric: { authenticate: vi.fn() },
        U2AuthPush: { getToken: vi.fn() },
      },
    }));

    // Dynamic import AFTER the mock is registered.
    const mod = await import("./native-modules.js");
    RNKeyStore = mod.RNKeyStore;
  });

  it("ensureKeyPair() calls the native module and returns the base64 public key", async () => {
    const pubKeyB64 = b64([0xde, 0xad, 0xbe, 0xef]);
    mockEnsureKeyPair.mockResolvedValue(pubKeyB64);

    const ks = new RNKeyStore();
    const result = await ks.ensureKeyPair();

    expect(mockEnsureKeyPair).toHaveBeenCalledOnce();
    expect(result).toBe(pubKeyB64);
  });

  it("sign() base64-encodes input, calls native sign, and decodes the returned base64 to Uint8Array", async () => {
    const inputBytes = new Uint8Array([1, 2, 3, 4]);
    const outputBytes = [5, 6, 7, 8];
    const outputB64 = b64(outputBytes);

    mockSign.mockResolvedValue(outputB64);

    const ks = new RNKeyStore();
    const result = await ks.sign(inputBytes);

    // (a) The native method must have been called with the base64 of [1,2,3,4].
    expect(mockSign).toHaveBeenCalledOnce();
    expect(mockSign).toHaveBeenCalledWith(b64([1, 2, 3, 4]));

    // (b) The returned value must be a Uint8Array equal to [5,6,7,8].
    expect(result).toBeInstanceOf(Uint8Array);
    expect(Array.from(result)).toEqual(outputBytes);
  });

  it("sign() round-trips arbitrary bytes correctly through base64", async () => {
    // Use a longer, non-trivial payload that exercises the encode→decode path.
    const inputBytes = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
    const returnedSigBytes = new Uint8Array(Array.from({ length: 64 }, (_, i) => i * 2));
    const returnedSigB64 = Buffer.from(returnedSigBytes).toString("base64");

    mockSign.mockResolvedValue(returnedSigB64);

    const ks = new RNKeyStore();
    const result = await ks.sign(inputBytes);

    expect(mockSign).toHaveBeenCalledWith(Buffer.from(inputBytes).toString("base64"));
    expect(Array.from(result)).toEqual(Array.from(returnedSigBytes));
  });
});

// ---------------------------------------------------------------------------
// RNBiometric tests
// ---------------------------------------------------------------------------

describe("RNBiometric", () => {
  let mockAuthenticate: ReturnType<typeof vi.fn>;
  let RNBiometric: typeof import("./native-modules.js").RNBiometric;

  beforeEach(async () => {
    mockAuthenticate = vi.fn();

    vi.resetModules();
    vi.doMock("react-native", () => ({
      NativeModules: {
        U2AuthKeystore: { ensureKeyPair: vi.fn(), sign: vi.fn() },
        U2AuthBiometric: { authenticate: mockAuthenticate },
        U2AuthPush: { getToken: vi.fn() },
      },
    }));

    const mod = await import("./native-modules.js");
    RNBiometric = mod.RNBiometric;
  });

  it("authenticate() calls the native module with the given reason and returns true on success", async () => {
    mockAuthenticate.mockResolvedValue(true);

    const bio = new RNBiometric();
    const result = await bio.authenticate("Approve login request");

    expect(mockAuthenticate).toHaveBeenCalledOnce();
    expect(mockAuthenticate).toHaveBeenCalledWith("Approve login request");
    expect(result).toBe(true);
  });

  it("authenticate() returns false when the user cancels", async () => {
    mockAuthenticate.mockResolvedValue(false);

    const bio = new RNBiometric();
    const result = await bio.authenticate("Confirm action");

    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// RNPushTokens tests
// ---------------------------------------------------------------------------

describe("RNPushTokens", () => {
  let mockGetToken: ReturnType<typeof vi.fn>;
  let RNPushTokens: typeof import("./push.js").RNPushTokens;

  beforeEach(async () => {
    mockGetToken = vi.fn();

    vi.resetModules();
    vi.doMock("react-native", () => ({
      NativeModules: {
        U2AuthKeystore: { ensureKeyPair: vi.fn(), sign: vi.fn() },
        U2AuthBiometric: { authenticate: vi.fn() },
        U2AuthPush: { getToken: mockGetToken },
      },
    }));

    const mod = await import("./push.js");
    RNPushTokens = mod.RNPushTokens;
  });

  it("getToken() calls the native module and returns the push token string", async () => {
    mockGetToken.mockResolvedValue("fcm-token-xyz");

    const push = new RNPushTokens();
    const token = await push.getToken();

    expect(mockGetToken).toHaveBeenCalledOnce();
    expect(token).toBe("fcm-token-xyz");
  });
});

// ---------------------------------------------------------------------------
// createU2AuthClient factory test
// ---------------------------------------------------------------------------

describe("createU2AuthClient", () => {
  let createU2AuthClient: typeof import("./factory.js").createU2AuthClient;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock("react-native", () => ({
      NativeModules: {
        U2AuthKeystore: { ensureKeyPair: vi.fn(), sign: vi.fn() },
        U2AuthBiometric: { authenticate: vi.fn().mockResolvedValue(true) },
        U2AuthPush: { getToken: vi.fn() },
      },
    }));

    const mod = await import("./factory.js");
    createU2AuthClient = mod.createU2AuthClient;
  });

  it("returns a U2AuthClient instance", async () => {
    // We need the U2AuthClient class to do the instanceof check.
    const { U2AuthClient } = await import(
      "@u2secured/authenticator-client"
    );

    const client = createU2AuthClient({
      baseUrl: "https://auth.example.com",
      getAccessToken: async () => "test-token",
      biometric: true,
    });

    expect(client).toBeInstanceOf(U2AuthClient);
  });

  it("returns a U2AuthClient instance even without biometric", async () => {
    const { U2AuthClient } = await import(
      "@u2secured/authenticator-client"
    );

    const client = createU2AuthClient({
      baseUrl: "https://auth.example.com",
      getAccessToken: async () => "test-token",
    });

    expect(client).toBeInstanceOf(U2AuthClient);
  });
});
