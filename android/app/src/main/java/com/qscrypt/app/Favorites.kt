package com.qscrypt.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.fragment.app.FragmentActivity
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Favourite containers that open with a fingerprint. The container's
 * password (and PIM, keyfiles) is sealed by a Keystore key that the
 * hardware releases only after a strong fingerprint or face match, for each
 * use, and that is destroyed when a new fingerprint is enrolled.
 */
object Favorites {
    /** One Keystore key per profile, so forgetting all in one never touches the other. */
    private val ALIAS: String get() = Profile.name("qscrypt_favorites_key")

    /** What a favourite remembers. Wipe `password` after use. */
    class Secret(val password: ByteArray, val pim: Int, val keyfiles: List<String>, val unlock: String)

    private fun prefs(context: Context) = context.getSharedPreferences(Profile.name("qscrypt_favorites"), Context.MODE_PRIVATE)

    fun has(context: Context, key: String): Boolean = key.isNotEmpty() && prefs(context).contains(key)

    fun keys(context: Context): Set<String> = prefs(context).all.keys

    fun forget(context: Context, key: String) = prefs(context).edit().remove(key).apply()

    fun forgetAll(context: Context) {
        prefs(context).edit().clear().apply()
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS) }
    }

    private fun key(create: Boolean): SecretKey? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(spec.build())
        return gen.generateKey()
    }

    /** The key was invalidated (new fingerprint): every favourite is gone. */
    class Invalidated : Exception()

    private fun cipher(mode: Int, iv: ByteArray?): Cipher {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            val k = key(create = mode == Cipher.ENCRYPT_MODE) ?: throw Invalidated()
            if (iv == null) c.init(mode, k) else c.init(mode, k, GCMParameterSpec(128, iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw Invalidated()
        }
        return c
    }

    /**
     * Asks for a fingerprint and remembers the secret under `key`.
     * `onDone(null)` on success, or an error message.
     */
    fun save(activity: FragmentActivity, key: String, name: String, secret: Secret, onDone: (String?) -> Unit) {
        val c = try {
            cipher(Cipher.ENCRYPT_MODE, null)
        } catch (e: Invalidated) {
            forgetAll(activity)
            return save(activity, key, name, secret, onDone)
        } catch (e: Exception) {
            onDone("تعذّر إنشاء مفتاح البصمة على هذا الهاتف.")
            return
        }
        PhoneAuth.promptCrypto(activity, "حفظ للفتح بالبصمة", name, c) { ok, msg ->
            if (ok == null) {
                onDone(msg ?: "لم يتم التأكيد")
                return@promptCrypto
            }
            val plain = JSONObject()
                .put("pw", Base64.encodeToString(secret.password, Base64.NO_WRAP))
                .put("pim", secret.pim)
                .put("kf", JSONArray(secret.keyfiles))
                .put("unlock", secret.unlock)
                .toString().toByteArray()
            val sealed = runCatching { ok.iv + ok.doFinal(plain) }.getOrNull()
            plain.fill(0)
            if (sealed == null) {
                onDone("تعذّر الحفظ.")
            } else {
                prefs(activity).edit().putString(key, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
                onDone(null)
            }
        }
    }

    /** Asks for a fingerprint and returns the remembered secret, or null with a message. */
    fun open(activity: FragmentActivity, key: String, name: String, onDone: (Secret?, String?) -> Unit) {
        val sealed = prefs(activity).getString(key, null)?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() }
        if (sealed == null || sealed.size < 13) {
            onDone(null, "لا توجد كلمة مرور محفوظة.")
            return
        }
        val c = try {
            cipher(Cipher.DECRYPT_MODE, sealed.copyOfRange(0, 12))
        } catch (e: Invalidated) {
            forgetAll(activity)
            onDone(null, "أُضيفت بصمة جديدة إلى الهاتف، فأُلغي الفتح بالبصمة حمايةً لك. افتح بكلمة المرور ثم فعّله من جديد.")
            return
        } catch (e: Exception) {
            onDone(null, "تعذّر استخدام مفتاح البصمة.")
            return
        }
        PhoneAuth.promptCrypto(activity, "افتح بالبصمة", name, c) { ok, msg ->
            if (ok == null) {
                onDone(null, msg)
                return@promptCrypto
            }
            val plain = runCatching { ok.doFinal(sealed, 12, sealed.size - 12) }.getOrNull()
            if (plain == null) {
                onDone(null, "تعذّر فك كلمة المرور المحفوظة.")
                return@promptCrypto
            }
            val j = runCatching { JSONObject(String(plain)) }.getOrNull()
            plain.fill(0)
            if (j == null) {
                onDone(null, "البيانات المحفوظة تالفة.")
                return@promptCrypto
            }
            val kf = j.optJSONArray("kf") ?: JSONArray()
            onDone(
                Secret(
                    Base64.decode(j.optString("pw"), Base64.NO_WRAP),
                    j.optInt("pim"),
                    (0 until kf.length()).map { kf.getString(it) },
                    j.optString("unlock", "password"),
                ),
                null,
            )
        }
    }
}
