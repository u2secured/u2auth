package com.u2secured.authclient

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * U2AuthKeystoreModule — Android Keystore-backed EC P-256 keypair for U2 Secured.
 *
 * Key properties
 * ──────────────
 * • Algorithm : EC (P-256 / secp256r1)
 * • Signing   : SHA256withECDSA
 * • Auth gate : setUserAuthenticationRequired(true) — the key is only usable
 *               after the user has authenticated (biometric or device credential)
 *               within the last [authValiditySeconds] seconds.
 * • Keystore  : "AndroidKeyStore" (hardware-backed on supported devices)
 *
 * The private key NEVER leaves the hardware-backed keystore.
 * Public key is exported as an X.509 DER SubjectPublicKeyInfo blob (base64).
 */
class U2AuthKeystoreModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        private const val MODULE_NAME = "U2AuthKeystore"
        private const val KEY_ALIAS = "u2auth_device_key"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /**
         * How long (seconds) after a successful user authentication the key
         * may be used without re-authenticating.
         * Set to 0 to require authentication on every use.
         */
        private const val AUTH_VALIDITY_SECONDS = 0
    }

    override fun getName(): String = MODULE_NAME

    // -------------------------------------------------------------------------
    // Key management helpers
    // -------------------------------------------------------------------------

    private fun androidKeystore(): KeyStore =
        KeyStore.getInstance(KEYSTORE_PROVIDER).also { it.load(null) }

    private fun keyExists(): Boolean =
        androidKeystore().containsAlias(KEY_ALIAS)

    /**
     * Generate a new EC P-256 keypair in the Android Keystore.
     * Idempotent: if the key already exists, does nothing.
     */
    private fun ensureKey() {
        if (keyExists()) return

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // Bind auth validity. API 30+ uses setUserAuthenticationParameters
            // (which also pins STRONG biometry); pre-R falls back to the older,
            // now-deprecated duration API. They are mutually exclusive — calling
            // both on R+ is redundant, so gate by API level.
            .apply {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        AUTH_VALIDITY_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
                }
                // Prefer StrongBox (dedicated security chip) when available.
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    /** Return the X.509-encoded public key bytes (SubjectPublicKeyInfo). */
    private fun publicKeyBytes(): ByteArray {
        val ks = androidKeystore()
        val cert = ks.getCertificate(KEY_ALIAS)
            ?: error("Key entry has no certificate — key generation may have failed")
        // The certificate's public key gives us the SubjectPublicKeyInfo (X.509) encoding.
        return cert.publicKey.encoded
    }

    // -------------------------------------------------------------------------
    // React Native exports
    // -------------------------------------------------------------------------

    /**
     * Ensure the device keypair exists and return the X.509-encoded public key
     * as a base64 string (no line-breaks).
     */
    @ReactMethod
    fun ensureKeyPair(promise: Promise) {
        try {
            ensureKey()
            val b64 = Base64.encodeToString(publicKeyBytes(), Base64.NO_WRAP)
            promise.resolve(b64)
        } catch (e: Exception) {
            promise.reject("KEYSTORE_ERROR", e.message ?: "ensureKeyPair failed", e)
        }
    }

    /**
     * Sign base64-encoded data with the device private key.
     * Uses SHA256withECDSA; returns a base64-encoded DER signature.
     *
     * @param base64Data Base64-encoded payload to sign.
     */
    @ReactMethod
    fun sign(base64Data: String, promise: Promise) {
        try {
            val data = Base64.decode(base64Data, Base64.DEFAULT)

            val ks = androidKeystore()
            val entry = ks.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("Device key not found — call ensureKeyPair() first")

            val sig = Signature.getInstance("SHA256withECDSA").apply {
                initSign(entry.privateKey)
                update(data)
            }.sign()

            promise.resolve(Base64.encodeToString(sig, Base64.NO_WRAP))
        } catch (e: Exception) {
            promise.reject("SIGN_ERROR", e.message ?: "sign() failed", e)
        }
    }
}
