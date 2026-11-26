package com.qscrypt.app

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** A container or file the user added to the list. */
data class Container(
    val uri: String,
    val name: String,
    val size: Long,
    val added: Long,
    val format: String = "",
    val ea: String = "",
    val fs: String = "",
) {
    fun toJson(): JSONObject = JSONObject()
        .put("uri", uri).put("name", name).put("size", size).put("added", added)
        .put("format", format).put("ea", ea).put("fs", fs)

    companion object {
        fun from(j: JSONObject) = Container(
            uri = j.optString("uri"),
            name = j.optString("name"),
            size = j.optLong("size"),
            added = j.optLong("added"),
            format = j.optString("format"),
            ea = j.optString("ea"),
            fs = j.optString("fs"),
        )
    }
}

/** A contact: someone's public QsCrypt card. */
data class Contact(val name: String, val card: String, val safety: String, val fingerprint: String, val signKey: String, val verified: Boolean, val added: Long) {
    fun toJson(): JSONObject = JSONObject()
        .put("name", name).put("card", card).put("safety", safety).put("fingerprint", fingerprint)
        .put("signKey", signKey).put("verified", verified).put("added", added)

    companion object {
        fun from(j: JSONObject) = Contact(
            name = j.getString("name"),
            card = j.getString("card"),
            safety = j.optString("safety"),
            fingerprint = j.optString("fingerprint"),
            signKey = j.optString("signKey"),
            verified = j.optBoolean("verified"),
            added = j.optLong("added"),
        )
    }
}

/** One failed attempt: the app lock, the disguise calculator, a vault or a QsCrypt file. */
data class Attempt(val time: Long, val kind: String, val target: String) {
    fun toJson(): JSONObject = JSONObject().put("t", time).put("k", kind).put("n", target)

    companion object {
        fun from(j: JSONObject) = Attempt(j.getLong("t"), j.optString("k"), j.optString("n"))
    }
}

const val SECRET_PIN = 0
const val SECRET_PATTERN = 1
const val SECRET_NONE = 2

/** App settings and the PIN, in app-private storage. Never holds passwords. */
object Prefs {
    private lateinit var sp: SharedPreferences

    fun init(context: Context) {
        sp = context.getSharedPreferences("qscrypt", Context.MODE_PRIVATE)
    }

    // ---------------------------------------------------------- PIN

    /** An internal secret (PIN or pattern) is set. */
    fun hasPin(): Boolean = sp.contains("pin_hash")

    /** What unlocks the app inside QsCrypt: a PIN, a pattern, or nothing (the phone's lock only). */
    var secretKind: Int
        get() = sp.getInt("secret_kind", if (hasPin()) SECRET_PIN else -1)
        set(v) = sp.edit().putInt("secret_kind", v).apply()

    /** The app lock is set up, with an internal secret or with the phone's lock only. */
    fun lockConfigured(): Boolean = hasPin() || secretKind == SECRET_NONE

    fun setPin(pin: String): Boolean = setSecret(SECRET_PIN, pin)

    /** Stores a PIN or a pattern (its dots as digits 1-9) as a salted PBKDF2 hash. */
    fun setSecret(kind: Int, secret: String): Boolean {
        val salt = QsCore.randomBytes(32) ?: return false
        val hash = QsCore.pinHash(secret.toByteArray(), salt) ?: return false
        sp.edit()
            .putString("pin_salt", b64(salt))
            .putString("pin_hash", b64(hash))
            .putInt("secret_kind", kind)
            .putInt("fail_count", 0)
            .putLong("lock_until", 0)
            .apply()
        return true
    }

    /** No internal secret: the phone's fingerprint, face or lock opens the app. */
    fun clearSecret() {
        sp.edit().remove("pin_salt").remove("pin_hash").putInt("secret_kind", SECRET_NONE)
            .putInt("fail_count", 0).putLong("lock_until", 0).apply()
    }

    fun checkPin(pin: String): Boolean {
        val salt = unb64(sp.getString("pin_salt", null)) ?: return false
        val expect = unb64(sp.getString("pin_hash", null)) ?: return false
        val got = QsCore.pinHash(pin.toByteArray(), salt) ?: return false
        return MessageDigest.isEqual(got, expect)
    }

    var failCount: Int
        get() = sp.getInt("fail_count", 0)
        set(v) = sp.edit().putInt("fail_count", v).apply()

    /** Wall-clock time (ms) until which PIN entry is blocked. */
    var lockUntil: Long
        get() = sp.getLong("lock_until", 0)
        set(v) = sp.edit().putLong("lock_until", v).apply()

    // ---------------------------------------------------------- activation

    var activated: Boolean
        get() = sp.getBoolean("activated", false)
        set(v) = sp.edit().putBoolean("activated", v).apply()

    var activationFails: Int
        get() = sp.getInt("act_fail", 0)
        set(v) = sp.edit().putInt("act_fail", v).apply()

    var activationLockUntil: Long
        get() = sp.getLong("act_until", 0)
        set(v) = sp.edit().putLong("act_until", v).apply()

    // ---------------------------------------------------------- settings

    var autoLockMs: Long
        get() = sp.getLong("autolock_ms", 30_000)
        set(v) = sp.edit().putLong("autolock_ms", v).apply()

    /** PhoneAuth.Mode id; -1 until the user has chosen. */
    var lockMode: Int
        get() = sp.getInt("lock_mode", -1)
        set(v) = sp.edit().putInt("lock_mode", v).apply()

    var closeVaultsOnLock: Boolean
        get() = sp.getBoolean("close_on_lock", true)
        set(v) = sp.edit().putBoolean("close_on_lock", v).apply()

    /** Close every vault and lock when the screen turns off. */
    var closeOnScreenOff: Boolean
        get() = sp.getBoolean("close_screen_off", false)
        set(v) = sp.edit().putBoolean("close_screen_off", v).apply()

    /** Close vaults after this many minutes without use (0: never). */
    var idleCloseMinutes: Int
        get() = sp.getInt("idle_close_min", 0)
        set(v) = sp.edit().putInt("idle_close_min", v).apply()

    /** A notification with "lock all" while vaults are open and the app is in the background. */
    var openVaultsNotice: Boolean
        get() = sp.getBoolean("open_notice", true)
        set(v) = sp.edit().putBoolean("open_notice", v).apply()

    /** Background operations pause when the battery is low and the phone is not charging. */
    var notificationsAsked: Boolean
        get() = sp.getBoolean("notif_asked", false)
        set(v) = sp.edit().putBoolean("notif_asked", v).apply()

    var pauseOnLowBattery: Boolean
        get() = sp.getBoolean("pause_low_battery", true)
        set(v) = sp.edit().putBoolean("pause_low_battery", v).apply()

    // ---------------------------------------------------------- failed attempts

    /** Wrong PINs, patterns and passwords, newest first (at most 100). */
    fun attemptsLog(): List<Attempt> {
        val arr = runCatching { JSONArray(sp.getString("attempts", "[]")) }.getOrElse { JSONArray() }
        return (0 until arr.length()).mapNotNull { runCatching { Attempt.from(arr.getJSONObject(it)) }.getOrNull() }
    }

    fun logAttempt(kind: String, target: String = "") {
        if (!logAttempts) return
        val list = listOf(Attempt(System.currentTimeMillis(), kind, target)) + attemptsLog().take(99)
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        sp.edit().putString("attempts", arr.toString()).apply()
    }

    fun clearAttempts() = sp.edit().remove("attempts").putLong("attempts_seen", System.currentTimeMillis()).apply()

    var logAttempts: Boolean
        get() = sp.getBoolean("log_attempts", true)
        set(v) = sp.edit().putBoolean("log_attempts", v).apply()

    /** When the log was last shown; newer entries are reported after unlocking. */
    var attemptsSeen: Long
        get() = sp.getLong("attempts_seen", 0)
        set(v) = sp.edit().putLong("attempts_seen", v).apply()

    // ---------------------------------------------------------- background fill of free space

    /** Where filling a container's free space stopped (bytes), or -1 if nothing is pending. */
    fun fillCursor(id: String): Long = sp.getLong("fill_$id", -1)

    fun setFillCursor(id: String, cursor: Long) = sp.edit().putLong("fill_$id", cursor).apply()

    fun clearFill(id: String) = sp.edit().remove("fill_$id").apply()

    // ---------------------------------------------------------- unfinished jobs (no secrets)

    var pendingJobs: String
        get() = sp.getString("pending_jobs", "[]") ?: "[]"
        set(v) = sp.edit().putString("pending_jobs", v).apply()

    // ---------------------------------------------------------- time (clock rollback detection)

    /** The latest wall-clock time (seconds) the app has seen. */
    val maxSeenTime: Long get() = sp.getLong("max_seen", 0)

    fun noteTime(now: Long) {
        if (now > maxSeenTime) sp.edit().putLong("max_seen", now).apply()
    }

    // ---------------------------------------------------------- QsCrypt file policies

    /** Wrong-password attempts per QsCrypt file id. */
    fun attempts(fileId: String): Int = sp.getInt("att_$fileId", 0)

    fun setAttempts(fileId: String, n: Int) = sp.edit().putInt("att_$fileId", n).apply()

    /** Files opened once and burned on this phone. */
    fun burned(fileId: String): Boolean = sp.getBoolean("burn_$fileId", false)

    fun burn(fileId: String) = sp.edit().putBoolean("burn_$fileId", true).apply()

    // ---------------------------------------------------------- disguise

    var disguised: Boolean
        get() = sp.getBoolean("disguised", false)
        set(v) = sp.edit().putBoolean("disguised", v).apply()

    // ---------------------------------------------------------- contacts (public cards only)

    fun contacts(): List<Contact> {
        val arr = runCatching { JSONArray(sp.getString("contacts", "[]")) }.getOrElse { JSONArray() }
        return (0 until arr.length()).mapNotNull { runCatching { Contact.from(arr.getJSONObject(it)) }.getOrNull() }
    }

    fun saveContacts(list: List<Contact>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        sp.edit().putString("contacts", arr.toString()).apply()
    }

    // ---------------------------------------------------------- containers

    fun containers(): List<Container> {
        val arr = runCatching { JSONArray(sp.getString("containers", "[]")) }.getOrElse { JSONArray() }
        return (0 until arr.length()).map { Container.from(arr.getJSONObject(it)) }
    }

    fun saveContainers(list: List<Container>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        sp.edit().putString("containers", arr.toString()).apply()
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String?) = s?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() }
}

/** Storage Access Framework helpers. */
object Saf {
    data class Meta(val name: String, val size: Long)

    fun meta(context: Context, uri: Uri): Meta {
        var name = uri.lastPathSegment ?: "file"
        var size = -1L
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0 && !c.isNull(ni)) name = c.getString(ni)
                    if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                }
            }
        }
        if (size < 0) {
            size = runCatching { context.contentResolver.openFileDescriptor(uri, "r")?.use { it.statSize } }.getOrNull() ?: 0L
        }
        return Meta(name, size)
    }

    fun open(context: Context, uri: Uri, mode: String): ParcelFileDescriptor? =
        runCatching { context.contentResolver.openFileDescriptor(uri, mode) }.getOrNull()

    /** Keeps access to a picked document across restarts. */
    fun persist(context: Context, uri: Uri) {
        val rw = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        runCatching { context.contentResolver.takePersistableUriPermission(uri, rw) }
            .onFailure { runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) } }
    }

    fun release(context: Context, uri: Uri) {
        runCatching {
            context.contentResolver.releasePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
    }

    /** Human description of where a document lives. */
    fun location(uri: Uri): String {
        val id = runCatching { DocumentsContract.getDocumentId(uri) }.getOrNull() ?: return uri.authority ?: ""
        return when (uri.authority) {
            "com.android.externalstorage.documents" -> {
                val volume = id.substringBefore(':')
                val path = id.substringAfter(':', "").substringBeforeLast('/', "")
                val where = if (volume == "primary") "الذاكرة الداخلية" else "ذاكرة خارجية"
                if (path.isEmpty()) where else "$where – $path"
            }
            "com.android.providers.downloads.documents" -> "التنزيلات"
            "com.android.providers.media.documents" -> "الوسائط"
            else -> uri.authority ?: ""
        }
    }

    /** Creates a document inside a folder picked with OpenDocumentTree. */
    fun createInTree(context: Context, tree: Uri, name: String, mime: String = "application/octet-stream"): Uri? = runCatching {
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        DocumentsContract.createDocument(context.contentResolver, parent, mime, name)
    }.getOrNull()

    fun delete(context: Context, uri: Uri) {
        runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) }
    }

    /** The display name of a folder picked with OpenDocumentTree. */
    fun treeName(context: Context, tree: Uri): String = runCatching {
        val doc = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        context.contentResolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull() ?: tree.lastPathSegment?.substringAfterLast(':')?.substringAfterLast('/')?.ifBlank { null } ?: "مجلد"
}

/** "4.0 GB", "812 KB"... */
fun humanSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KB", "MB", "GB", "TB")
    var v = bytes / 1024.0
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    val s = if (v >= 100) "%.0f".format(java.util.Locale.US, v) else "%.1f".format(java.util.Locale.US, v)
    return "$s ${units[i]}"
}
