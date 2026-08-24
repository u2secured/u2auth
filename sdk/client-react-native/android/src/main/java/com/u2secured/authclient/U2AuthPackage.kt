package com.u2secured.authclient

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * U2AuthPackage — registers all U2 Secured Authenticator native modules with
 * the React Native bridge.
 *
 * Host app integration
 * ────────────────────
 * Add this package in the host app's [MainApplication.getPackages()]:
 *
 *   override fun getPackages(): List<ReactPackage> =
 *       PackageList(this).packages.apply {
 *           add(U2AuthPackage())
 *       }
 *
 * When using Expo / Expo Modules Core, the expo-plugin (withU2Auth.js) handles
 * this registration automatically.
 */
class U2AuthPackage : ReactPackage {

    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
        listOf(
            U2AuthKeystoreModule(reactContext),
            U2AuthBiometricModule(reactContext),
            U2AuthPushModule(reactContext),
        )

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
        emptyList()
}
