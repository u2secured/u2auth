package com.u2secured.authclient

import android.content.SharedPreferences
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/**
 * U2AuthPushModule — FCM push token retrieval.
 *
 * Host app responsibility
 * ───────────────────────
 * The host application is responsible for initialising the Firebase SDK and
 * storing the FCM registration token before this module is called. The
 * recommended approach is to use @react-native-firebase/messaging, which
 * handles token refresh automatically.
 *
 * If using @react-native-firebase/messaging, the host app should write the
 * token to SharedPreferences under the key "U2AuthFCMToken" in its
 * FirebaseMessagingService.onNewToken() override (or via a JS call into the
 * native layer), so this module can retrieve it synchronously.
 *
 * Alternatively: replace the SharedPreferences read with a call to
 * FirebaseMessaging.getInstance().token and await the Task in getToken().
 */
class U2AuthPushModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        private const val MODULE_NAME = "U2AuthPush"
        private const val PREFS_NAME = "U2AuthPrefs"
        private const val TOKEN_KEY = "U2AuthFCMToken"
    }

    override fun getName(): String = MODULE_NAME

    private fun prefs(): SharedPreferences =
        reactApplicationContext.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)

    /**
     * Return the FCM registration token.
     *
     * Reads from SharedPreferences where the host app (or a companion JS module
     * using @react-native-firebase/messaging) has stored the current token.
     *
     * Rejects with PUSH_TOKEN_UNAVAILABLE when the token has not yet been written.
     */
    @ReactMethod
    fun getToken(promise: Promise) {
        val token = prefs().getString(TOKEN_KEY, null)
        if (!token.isNullOrBlank()) {
            promise.resolve(token)
        } else {
            promise.reject(
                "PUSH_TOKEN_UNAVAILABLE",
                "FCM token is not yet available. Ensure the host app initialises " +
                    "Firebase and writes the token to SharedPreferences under the key " +
                    "\"U2AuthFCMToken\" (e.g. via @react-native-firebase/messaging)."
            )
        }
    }

    /**
     * Store an FCM token (called from JS or a companion FirebaseMessagingService).
     * Exposed so the host app's JS layer can set the token after FCM delivers it
     * without requiring a custom native module.
     */
    @ReactMethod
    fun setToken(token: String, promise: Promise) {
        prefs().edit().putString(TOKEN_KEY, token).apply()
        promise.resolve(null)
    }
}
