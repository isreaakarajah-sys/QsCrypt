package com.qscrypt.app

import org.json.JSONArray
import org.json.JSONObject

/** Progress callback invoked by the engine; return false to cancel. */
fun interface Progress {
    fun onProgress(done: Long, total: Long): Boolean
}

/** JNI bindings to the Rust engine (core/crates/qscrypt-ffi). */
object QsCore {
    init {
        System.loadLibrary("qscrypt_ffi")
    }

    external fun version(): String
    external fun selfTest(): String
    external fun openVolume(fd: Int, password: ByteArray, pim: Int, prf: Int, format: Int, readOnly: Boolean, tzMinutes: Int): String
    external fun closeVolume(handle: Long)
    external fun closeAll()
    external fun volumeInfo(handle: Long): String
    external fun list(handle: Long, path: String): String
    external fun readFile(handle: Long, path: String, maxBytes: Long): ByteArray?
    external fun exportFile(handle: Long, path: String, outFd: Int, progress: Progress?): String
    external fun importFile(handle: Long, inFd: Int, size: Long, dest: String, overwrite: Boolean, progress: Progress?): String
    external fun mkdir(handle: Long, path: String): String
    external fun remove(handle: Long, path: String): String
    external fun rename(handle: Long, path: String, newName: String): String
    external fun createVolume(fd: Int, size: Long, password: ByteArray, pim: Int, prf: Int, ea: Int, format: Int, label: String, progress: Progress?): String
    external fun qscEncrypt(inFd: Int, size: Long, outFd: Int, name: String, modified: Long, password: ByteArray, progress: Progress?): String
    external fun qscDecrypt(inFd: Int, outFd: Int, password: ByteArray, progress: Progress?): String
    external fun pinHash(pin: ByteArray, salt: ByteArray): ByteArray?
    external fun randomBytes(n: Int): ByteArray?
    external fun sniff(fd: Int): String
    external fun openAsset(data: ByteArray, password: ByteArray): ByteArray?
}

/** A parsed engine reply: `{"ok":true,...}` or `{"ok":false,"code":...}`. */
class Reply(raw: String) {
    val json: JSONObject = runCatching { JSONObject(raw) }.getOrElse { JSONObject().put("ok", false).put("code", "internal").put("message", raw) }
    val ok: Boolean get() = json.optBoolean("ok", false)
    val code: String get() = json.optString("code")
    val message: String get() = json.optString("message")
    val error: String get() = errorText(code, message)
}

data class VolumeInfo(
    val handle: Long,
    val format: String,
    val ea: String,
    val prf: String,
    val hidden: Boolean,
    val fs: String,
    val label: String,
    val readOnly: Boolean,
    val total: Long,
    val free: Long,
    val maxFile: Long,
) {
    companion object {
        fun from(j: JSONObject) = VolumeInfo(
            handle = j.optLong("handle"),
            format = j.optString("format"),
            ea = j.optString("ea"),
            prf = j.optString("prf"),
            hidden = j.optBoolean("hidden"),
            fs = j.optString("fs"),
            label = j.optString("label"),
            readOnly = j.optBoolean("readOnly"),
            total = j.optLong("total"),
            free = j.optLong("free"),
            maxFile = j.optLong("maxFile"),
        )
    }
}

data class Entry(val name: String, val dir: Boolean, val size: Long, val mtime: Long)

fun parseEntries(j: JSONObject): List<Entry> {
    val arr: JSONArray = j.optJSONArray("entries") ?: return emptyList()
    return (0 until arr.length()).map { i ->
        val e = arr.getJSONObject(i)
        Entry(e.optString("name"), e.optBoolean("dir"), e.optLong("size"), e.optLong("mtime"))
    }
}

data class SelfTestItem(val name: String, val ok: Boolean)

data class SelfTest(val ok: Boolean, val backend: String, val engine: String, val items: List<SelfTestItem>) {
    /** Algorithms safe to create volumes with: VeraCrypt's own vectors passed. */
    fun passed(eaName: String) = items.any { it.name == "$eaName (VeraCrypt)" && it.ok }

    companion object {
        fun run(): SelfTest {
            val r = Reply(QsCore.selfTest())
            val arr = r.json.optJSONArray("results") ?: JSONArray()
            val items = (0 until arr.length()).map { arr.getJSONObject(it).let { o -> SelfTestItem(o.optString("name"), o.optBoolean("ok")) } }
            return SelfTest(r.ok, r.json.optString("backend"), r.json.optString("engine"), items)
        }
    }
}

/** Engine error codes in plain Arabic. */
fun errorText(code: String, message: String): String = when (code) {
    "wrong_password" -> "كلمة المرور أو الـ PIM غير صحيحة، أو أن الملف ليس حاوية مشفّرة."
    "unsupported" -> when {
        message.contains("NTFS") -> "هذه الحاوية مهيّأة بنظام NTFS، ودعمه قادم في الإصدار التالي. يمكنك فتحها حالياً بـ VeraCrypt على الحاسوب."
        message.contains("exFAT") -> "الكتابة على exFAT قادمة في الإصدار التالي، والحاوية متاحة للقراءة فقط."
        message.contains("4 GB") -> "نظام FAT لا يقبل ملفاً أكبر من 4GB."
        message.contains("system encryption") -> "هذا قرص نظام مشفّر (قرص الإقلاع)، ولا يُفتح كحاوية."
        else -> "ميزة غير مدعومة بعد: $message"
    }
    "corrupt" -> "البيانات تالفة أو غير مكتملة."
    "tampered" -> "الملف معدّل أو ناقص، لذلك رُفض فكّه حفاظاً على سلامة بياناتك."
    "no_space" -> "لا توجد مساحة كافية داخل الخزنة."
    "exists" -> "يوجد عنصر بالاسم نفسه."
    "invalid_name" -> "الاسم يحتوي على رموز غير مسموحة: \" * / : < > ? \\ |"
    "read_only" -> "الخزنة مفتوحة للقراءة فقط."
    "not_found" -> "العنصر غير موجود."
    "not_a_directory" -> "هذا ليس مجلداً."
    "is_a_directory" -> "هذا مجلد وليس ملفاً."
    "cancelled" -> "تم الإلغاء."
    "io" -> "تعذّرت القراءة أو الكتابة. تأكد أن الملف ما زال موجوداً وأن الفلاشة متصلة."
    "invalid_argument" -> if (message.contains("closed")) "الخزنة مقفلة. افتحها من جديد." else "مدخلات غير صالحة: $message"
    else -> message.ifBlank { "حدث خطأ غير متوقع." }
}
