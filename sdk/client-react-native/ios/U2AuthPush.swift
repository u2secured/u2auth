import Foundation
import UIKit

/// React Native module — APNs push token retrieval.
///
/// Host app responsibility
/// ───────────────────────
/// The host application must:
///   1. Request notification permission with UNUserNotificationCenter.
///   2. Call UIApplication.shared.registerForRemoteNotifications().
///   3. Implement application(_:didRegisterForRemoteNotificationsWithDeviceToken:)
///      in the AppDelegate and store the token as Data, converting it to a
///      hex string. The simplest approach is to use react-native-push-notification
///      or @react-native-firebase/messaging which do this automatically.
///
/// This module reads the token from AppDelegate via a shared store. When using
/// react-native-firebase/messaging, replace getToken() with the FCM token call.
///
/// iOS deployment target: 14.0+
@objc(U2AuthPush)
final class U2AuthPush: NSObject {

  // MARK: - RCTBridgeModule

  @objc static func requiresMainQueueSetup() -> Bool { false }

  // MARK: - React Native exports

  /// Return the current APNs device token as a hex string.
  ///
  /// Rejects if the host app has not yet registered for remote notifications or
  /// if the user has denied notification permission.
  ///
  /// When using @react-native-firebase/messaging, replace this implementation
  /// with a native call to FIRMessaging.messaging().token(completion:).
  @objc func getToken(
    _ resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    DispatchQueue.main.async {
      // Attempt to read the APNs token stored by the host AppDelegate.
      // The key "U2AuthAPNsToken" must be written by the host in
      // application(_:didRegisterForRemoteNotificationsWithDeviceToken:).
      if let token = UserDefaults.standard.string(forKey: "U2AuthAPNsToken"), !token.isEmpty {
        resolve(token)
      } else {
        reject(
          "PUSH_TOKEN_UNAVAILABLE",
          "APNs/FCM token is not yet available. " +
            "Ensure the host app calls registerForRemoteNotifications() and " +
            "stores the token under the UserDefaults key \"U2AuthAPNsToken\" " +
            "(or configure FCM via @react-native-firebase/messaging).",
          nil
        )
      }
    }
  }
}
