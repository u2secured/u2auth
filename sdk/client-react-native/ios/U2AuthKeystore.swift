import Foundation
import Security

/// React Native module — hardware-backed P-256 keypair via Secure Enclave.
///
/// Key lifecycle
/// ─────────────
/// • ensureKeyPair() generates a P-256 private key protected by the Secure
///   Enclave (falling back to the Software Keychain on Simulator where the
///   Secure Enclave is not available) and stores it under a fixed application
///   tag. Subsequent calls return the existing key's public half.
///
/// • sign() performs ECDSA-SHA256 over the supplied data and returns the
///   DER-encoded signature. The private key never leaves secure hardware.
///
/// iOS deployment target: 14.0+  (kSecAttrTokenIDSecureEnclave available since iOS 9)
@objc(U2AuthKeystore)
final class U2AuthKeystore: NSObject {

  // Application tag that identifies our device key in the Keychain.
  private static let keyTag = "com.u2secured.authclient.devicekey"
      .data(using: .utf8)!

  // MARK: - RCTBridgeModule

  @objc static func requiresMainQueueSetup() -> Bool { false }

  // MARK: - Key management helpers

  /// Return the existing SecKey from the Keychain, or nil if absent.
  private func existingPrivateKey() -> SecKey? {
    let query: [CFString: Any] = [
      kSecClass:              kSecClassKey,
      kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrApplicationTag: U2AuthKeystore.keyTag,
      kSecAttrKeyClass:       kSecAttrKeyClassPrivate,
      kSecReturnRef:          true,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { return nil }
    // swiftlint:disable:next force_cast
    return (result as! SecKey)
  }

  /// Generate a new P-256 private key in the Secure Enclave (or software
  /// Keychain on Simulator) protected by biometric access control.
  private func generatePrivateKey() throws -> SecKey {
    // Access control: biometry (any enrolled finger/face) required for use.
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryAny],
      &error
    ) else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
      throw NSError(
        domain: "U2AuthKeystore",
        code: -1,
        userInfo: [NSLocalizedDescriptionKey: "Access control creation failed: \(msg)"]
      )
    }

    // Attempt Secure Enclave first; Simulator falls back to software key.
    let useSecureEnclave: Bool
    #if targetEnvironment(simulator)
      useSecureEnclave = false
    #else
      useSecureEnclave = true
    #endif

    var keyAttributes: [CFString: Any] = [
      kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits:  256,
      kSecPrivateKeyAttrs: [
        kSecAttrIsPermanent:    true,
        kSecAttrApplicationTag: U2AuthKeystore.keyTag,
        kSecAttrAccessControl:  access,
      ] as [CFString: Any],
    ]

    if useSecureEnclave {
      keyAttributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
    }

    guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
      throw NSError(
        domain: "U2AuthKeystore",
        code: -2,
        userInfo: [NSLocalizedDescriptionKey: "Key generation failed: \(msg)"]
      )
    }
    return privateKey
  }

  /// Extract the public key bytes in X9.63 uncompressed format and base64-encode them.
  private func publicKeyBase64(from privateKey: SecKey) throws -> String {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw NSError(
        domain: "U2AuthKeystore",
        code: -3,
        userInfo: [NSLocalizedDescriptionKey: "Could not derive public key"]
      )
    }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
      throw NSError(
        domain: "U2AuthKeystore",
        code: -4,
        userInfo: [NSLocalizedDescriptionKey: "Public key export failed: \(msg)"]
      )
    }
    return (data as Data).base64EncodedString()
  }

  // MARK: - React Native exports

  /// Ensure a device keypair exists and return the public key as base64.
  /// Thread-safe: called on an arbitrary background thread by the RN bridge.
  @objc func ensureKeyPair(
    _ resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    do {
      let privateKey = existingPrivateKey() ?? (try generatePrivateKey())
      let pubKeyB64 = try publicKeyBase64(from: privateKey)
      resolve(pubKeyB64)
    } catch {
      reject("KEYSTORE_ERROR", error.localizedDescription, error)
    }
  }

  /// Sign base64-encoded data with the device private key.
  /// Returns a base64-encoded DER ECDSA signature (X9.62 / SHA-256).
  @objc func sign(
    _ base64Data: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let data = Data(base64Encoded: base64Data) else {
      reject("INVALID_INPUT", "base64Data is not valid base64", nil)
      return
    }

    guard let privateKey = existingPrivateKey() else {
      reject("KEY_MISSING", "Device key not found — call ensureKeyPair() first", nil)
      return
    }

    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
      privateKey,
      .ecdsaSignatureMessageX962SHA256,
      data as CFData,
      &error
    ) else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
      reject("SIGN_ERROR", "Signing failed: \(msg)", nil)
      return
    }

    resolve((signature as Data).base64EncodedString())
  }
}
