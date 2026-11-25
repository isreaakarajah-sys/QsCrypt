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

/** App settings and the PIN, in app-private storage. Never holds passwords. */
object Prefs {
    private lateinit var sp: SharedPreferences

    fun init(context: Context) {
        sp = context.getSharedPreferences("qscrypt", Context.MODE_PRIVATE)
    }

    // ---------------------------------------------------------- PIN

    fun hasPin(): Boolean = sp.contains("pin_hash")

    fun setPin(pin: String): Boolean {
        val salt = QsCore.randomBytes(32) ?: return false
        val hash = QsCore.pinHash(pin.toByteArray(), salt) ?: return false
        sp.edit()
            .putString("pin_salt", b64(salt))
            .putString("pin_hash", b64(hash))
            .putInt("fail_count", 0)
            .putLong("lock_until", 0)
            .apply()
        return true
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

    var closeVaultsOnLock: Boolean
        get() = sp.getBoolean("close_on_lock", true)
        set(v) = sp.edit().putBoolean("close_on_lock", v).apply()

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
