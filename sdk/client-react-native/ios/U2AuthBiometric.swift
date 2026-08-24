import Foundation
import LocalAuthentication

/// React Native module — biometric authentication via LocalAuthentication.
///
/// Wraps LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, …)
/// and resolves with a boolean. The caller must supply a localised reason string
/// that iOS/macOS will display in the system prompt.
///
/// If biometrics are unavailable (not enrolled, locked out, or not supported)
/// the promise resolves `false`; it does NOT fall back to passcode so that the
/// security boundary is maintained.
///
/// iOS deployment target: 14.0+
@objc(U2AuthBiometric)
final class U2AuthBiometric: NSObject {

  // MARK: - RCTBridgeModule

  @objc static func requiresMainQueueSetup() -> Bool { false }

  // MARK: - React Native exports

  /// Prompt the user for biometric authentication.
  ///
  /// - Parameter reason: A localised string describing why authentication is
  ///   needed (displayed in the system Face ID / Touch ID sheet).
  /// - Resolves: `true` when authentication succeeds; `false` when the user
  ///   cancels, no biometry is enrolled, or the hardware denies the request.
  @objc func authenticate(
    _ reason: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    let context = LAContext()
    var policyError: NSError?

    // Disable the passcode fallback so the gate stays biometric-only.
    context.localizedFallbackTitle = ""

    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
      // Biometrics unavailable — resolve false rather than rejecting so the
      // caller can decide how to handle the degraded path.
      resolve(false)
      return
    }

    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: reason
    ) { success, _ in
      // evaluatePolicy callback may arrive on any thread.
      resolve(success)
    }
  }
}
