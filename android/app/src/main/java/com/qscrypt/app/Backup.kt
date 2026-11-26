package com.qscrypt.app

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * The encrypted backup of what lives only inside the app: the identity (the
 * secret contacts encrypt to), the contacts, the vault list and the keys of
 * "auto-open" QsCrypt files. Vault contents are not in it: they are already in
 * their own encrypted files.
 *
 * The file is an ordinary QsCrypt v2 file sealed with a password (Argon2id,
 * XChaCha20-Poly1305), written by the engine; only a backup opens as one.
 * Each profile (see [Profile]) backs up and restores its own data.
 */
object Backup {
    data class Summary(val identity: Boolean, val contacts: Int, val vaults: Int, val keys: Int)

    /** The plain bundle, built in memory only. Wipe after use. */
    private fun bundle(context: Context): ByteArray {
        val j = JSONObject().put("qscryptBackup", 1).put("created", System.currentTimeMillis() / 1000)
        Identity.secret(context)?.let { s ->
            j.put("identity", Base64.encodeToString(s, Base64.NO_WRAP))
            s.fill(0)
        }
        j.put("contacts", JSONArray().apply { Prefs.contacts().forEach { put(it.toJson()) } })
        j.put("vaults", JSONArray().apply { AppState.containers.forEach { put(it.toJson()) } })
        val keys = JSONObject()
        for (id in FileKeys.ids(context)) {
            val k = FileKeys.get(context, id) ?: continue
            keys.put(id, k.joinToString("") { "%02x".format(it) })
            k.fill(0)
        }
        j.put("fileKeys", keys)
        return j.toString().toByteArray(Charsets.UTF_8)
    }

    /** What a backup made now would hold. */
    fun preview(context: Context): Summary = Summary(
        identity = Identity.exists(context),
        contacts = Prefs.contacts().size,
        vaults = AppState.containers.size,
        keys = FileKeys.ids(context).size,
    )

    /** The sealed backup file's bytes, or null. */
    fun seal(context: Context, password: ByteArray): ByteArray? {
        val data = bundle(context)
        return Call("backup.seal").put("now", System.currentTimeMillis() / 1000).blob("password", password).blob("data", data).bytes()
    }

    sealed interface Restored {
        data class Done(val summary: Summary) : Restored
        data object WrongPassword : Restored
        data object NotABackup : Restored
    }

    /**
     * Restores a backup: the identity is replaced (if the backup has one),
     * contacts, vaults and keys are added to what is already here.
     */
    fun restore(context: Context, file: ByteArray, password: ByteArray): Restored {
        val plain = Call("backup.open").blob("password", password).blob("data", file).bytes() ?: return Restored.WrongPassword
        val j = runCatching { JSONObject(String(plain, Charsets.UTF_8)) }.getOrNull()
        plain.fill(0)
        if (j == null || j.optInt("qscryptBackup") != 1) return Restored.NotABackup

        var identity = false
        j.optString("identity").takeIf { it.isNotEmpty() }?.let { b ->
            val secret = runCatching { Base64.decode(b, Base64.NO_WRAP) }.getOrNull()
            if (secret != null) {
                identity = Identity.restore(context, secret)
                secret.fill(0)
            }
        }

        val have = Prefs.contacts()
        val added = mutableListOf<Contact>()
        j.optJSONArray("contacts")?.let { arr ->
            for (i in 0 until arr.length()) {
                val c = runCatching { Contact.from(arr.getJSONObject(i)) }.getOrNull() ?: continue
                if (have.none { it.fingerprint == c.fingerprint } && added.none { it.fingerprint == c.fingerprint }) added += c
            }
        }
        if (added.isNotEmpty()) Prefs.saveContacts(have + added)

        var vaults = 0
        j.optJSONArray("vaults")?.let { arr ->
            for (i in arr.length() - 1 downTo 0) {
                val c = runCatching { Container.from(arr.getJSONObject(i)) }.getOrNull() ?: continue
                if (AppState.containers.none { it.uri == c.uri }) {
                    AppState.addContainer(c)
                    vaults++
                }
            }
        }

        var keys = 0
        j.optJSONObject("fileKeys")?.let { o ->
            for (id in o.keys()) {
                if (FileKeys.has(context, id)) continue
                val hex = o.optString(id)
                val raw = hex.chunked(2).mapNotNull { it.toIntOrNull(16)?.toByte() }.toByteArray()
                if (raw.size == 32) {
                    FileKeys.putRaw(context, id, raw)
                    keys++
                }
                raw.fill(0)
            }
        }
        return Restored.Done(Summary(identity, added.size, vaults, keys))
    }
}
