package com.qscrypt.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets kept on this phone only, wrapped by a key that lives in the
 * Android Keystore (hardware-backed where the phone has it): the user's
 * QsCrypt identity, and file keys remembered for "auto-open" files.
 */
object Vaulted {
    private const val ALIAS = "qscrypt_device_key"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun seal(plain: ByteArray): ByteArray? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.iv + c.doFinal(plain)
    }.getOrNull()

    fun open(sealed: ByteArray): ByteArray? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, 12))
        c.doFinal(sealed, 12, sealed.size - 12)
    }.getOrNull()
}

/** The user's own QsCrypt identity (what contacts encrypt to). */
object Identity {
    private fun file(context: Context) = File(context.filesDir, "identity.bin")

    fun exists(context: Context) = file(context).exists()

    /** The secret identity bytes, or null. Wipe after use. */
    fun secret(context: Context): ByteArray? = runCatching { Vaulted.open(file(context).readBytes()) }.getOrNull()

    fun create(context: Context, name: String): Boolean {
        val secret = Call("id.generate").put("name", name).bytes() ?: return false
        val sealed = Vaulted.seal(secret)
        secret.fill(0)
        sealed ?: return false
        file(context).writeBytes(sealed)
        return true
    }

    fun rename(context: Context, name: String): Boolean {
        val s = secret(context) ?: return false
        val renamed = Call("id.rename").put("name", name).blob("identity", s).bytes() ?: return false
        val sealed = Vaulted.seal(renamed)
        renamed.fill(0)
        sealed ?: return false
        file(context).writeBytes(sealed)
        return true
    }

    /** name, card, safety, fingerprint, signKey. */
    fun public(context: Context): JSONObject? {
        val s = secret(context) ?: return null
        val r = Call("id.public").blob("identity", s).run()
        return if (r.ok) r.json else null
    }

    fun delete(context: Context) {
        file(context).delete()
    }
}

/** File keys of "auto-open" QsCrypt files, wrapped by the device key. */
object FileKeys {
    private fun prefs(context: Context) = context.getSharedPreferences("qscrypt_filekeys", Context.MODE_PRIVATE)

    fun put(context: Context, fileId: String, keyHex: String) {
        val raw = keyHex.chunked(2).mapNotNull { it.toIntOrNull(16)?.toByte() }.toByteArray()
        if (raw.size != 32) return
        val sealed = Vaulted.seal(raw)
        raw.fill(0)
        sealed ?: return
        prefs(context).edit().putString(fileId, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
    }

    fun get(context: Context, fileId: String): ByteArray? {
        val s = prefs(context).getString(fileId, null) ?: return null
        return runCatching { Vaulted.open(Base64.decode(s, Base64.NO_WRAP)) }.getOrNull()
    }

    fun forget(context: Context, fileId: String) = prefs(context).edit().remove(fileId).apply()

    fun has(context: Context, fileId: String): Boolean = fileId.isNotEmpty() && prefs(context).contains(fileId)
}
