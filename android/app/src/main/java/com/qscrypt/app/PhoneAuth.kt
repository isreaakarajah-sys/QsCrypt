package com.qscrypt.app

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/**
 * The phone's own authentication: fingerprint or face, with the phone's
 * PIN, pattern or password as the fallback. Used as the second factor of
 * the app lock (after the QsCrypt PIN or pattern), instead of it, or alone.
 */
object PhoneAuth {
    /** How the app is unlocked. */
    enum class Mode(val id: Int) {
        /** The QsCrypt PIN or pattern only. */
        Pin(0),
        /** The QsCrypt PIN or pattern, then the phone's lock (two-factor). */
        TwoFactor(1),
        /** Either the phone's lock or the PIN / pattern. */
        Either(2),
        /** The phone's lock only: no internal secret. */
        PhoneOnly(3);

        companion object {
            fun of(id: Int) = entries.firstOrNull { it.id == id } ?: Pin
        }
    }

    // BIOMETRIC_STRONG | DEVICE_CREDENTIAL is not accepted on Android 9-10.
    private val authenticators: Int
        get() = if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_WEAK or DEVICE_CREDENTIAL

    fun available(context: Context): Boolean =
        runCatching { BiometricManager.from(context).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS }.getOrDefault(false)

    /** A strong fingerprint (or face) sensor with something enrolled: needed to bind keys to it. */
    fun strongBiometrics(context: Context): Boolean =
        runCatching { BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS }.getOrDefault(false)

    /**
     * Effective mode: falls back to the PIN when the phone has no lock any
     * more (PhoneOnly stays, and the lock screen asks for a new app lock).
     */
    fun mode(context: Context): Mode {
        if (Prefs.secretKind == SECRET_NONE) return Mode.PhoneOnly
        val m = Mode.of(Prefs.lockMode)
        return when {
            m == Mode.PhoneOnly -> if (available(context)) Mode.Either else Mode.Pin
            m != Mode.Pin && !available(context) -> Mode.Pin
            else -> m
        }
    }

    /**
     * Shows the system prompt. `onResult(true)` after success; `false` with a
     * message on error or cancel.
     */
    fun prompt(activity: FragmentActivity, title: String, subtitle: String, onResult: (Boolean, String?) -> Unit) {
        // The device-credential screen is a separate activity: do not treat
        // leaving for it as leaving the app.
        AppState.pickerOpen = true
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onResult(true, null)
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onResult(false, errString.toString())
                override fun onAuthenticationFailed() {}
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .setConfirmationRequired(false)
            .build()
        runCatching { prompt.authenticate(info) }.onFailure { onResult(false, it.message) }
    }

    /**
     * A fingerprint (strong biometrics only) that unlocks `cipher`, a cipher
     * over a Keystore key bound to biometrics. `onResult` gets the cipher, or
     * null with a message.
     */
    fun promptCrypto(activity: FragmentActivity, title: String, subtitle: String, cipher: Cipher, onResult: (Cipher?, String?) -> Unit) {
        AppState.pickerOpen = true
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onResult(result.cryptoObject?.cipher, null)
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onResult(null, errString.toString())
                override fun onAuthenticationFailed() {}
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText("إلغاء")
            .setConfirmationRequired(false)
            .build()
        runCatching { prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher)) }.onFailure { onResult(null, it.message) }
    }
}
