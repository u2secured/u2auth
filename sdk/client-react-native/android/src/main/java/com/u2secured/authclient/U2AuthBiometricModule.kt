package com.u2secured.authclient

import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/**
 * U2AuthBiometricModule — biometric authentication via androidx.biometric.BiometricPrompt.
 *
 * Requires the host app to have BIOMETRIC or USE_BIOMETRIC permission declared in
 * AndroidManifest.xml:
 *   <uses-permission android:name="android.permission.USE_BIOMETRIC" />
 *
 * BiometricPrompt requires the current Activity to be a FragmentActivity (AppCompatActivity).
 * If the current activity is not a FragmentActivity the promise resolves `false`
 * rather than crashing — the caller can then decide how to proceed.
 *
 * Class-3 (strong) biometry is preferred; the prompt is restricted to biometry only
 * (no device-credential fallback) so the security boundary stays biometric.
 */
class U2AuthBiometricModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        private const val MODULE_NAME = "U2AuthBiometric"
    }

    override fun getName(): String = MODULE_NAME

    /**
     * Display a biometric prompt with the given [reason] string.
     *
     * Resolves `true` when the user authenticates successfully.
     * Resolves `false` when:
     *   • the user cancels,
     *   • no biometry is enrolled / hardware absent,
     *   • the current activity is not a FragmentActivity.
     * Rejects only on unrecoverable internal errors.
     */
    @ReactMethod
    fun authenticate(reason: String, promise: Promise) {
        val activity = currentActivity

        // Guard: BiometricPrompt requires a FragmentActivity.
        if (activity !is FragmentActivity) {
            promise.resolve(false)
            return
        }

        // Guard: check that the device can perform biometric authentication.
        val biometricManager = BiometricManager.from(reactApplicationContext)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            promise.resolve(false)
            return
        }

        // BiometricPrompt must be built and shown on the main thread.
        Handler(Looper.getMainLooper()).post {
            try {
                val executor = ContextCompat.getMainExecutor(activity)

                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        promise.resolve(true)
                    }

                    override fun onAuthenticationFailed() {
                        // A single attempt failed (e.g. unrecognised finger) — the prompt
                        // remains visible; do nothing here, the system will retry.
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        // User-cancelled (ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON) or
                        // too many attempts (ERROR_LOCKOUT) → resolve false so the caller
                        // can show its own "authentication failed" UI.
                        when (errorCode) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED,
                            BiometricPrompt.ERROR_LOCKOUT,
                            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> promise.resolve(false)

                            else -> promise.reject(
                                "BIOMETRIC_ERROR",
                                "Biometric error $errorCode: $errString"
                            )
                        }
                    }
                }

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("U2 Secured")
                    .setSubtitle(reason)
                    // Biometry-only: no passcode fallback button.
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

                BiometricPrompt(activity, executor, callback).authenticate(promptInfo)
            } catch (e: Exception) {
                promise.reject("BIOMETRIC_ERROR", e.message ?: "BiometricPrompt setup failed", e)
            }
        }
    }
}
