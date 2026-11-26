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

    // Generic API (core/crates/qscrypt-ffi/src/api2.rs): non-secret arguments
    // in JSON, secrets in byte arrays and file descriptors referred to by index.
    external fun call(method: String, args: String, blobs: Array<ByteArray>?, fds: IntArray?, progress: Progress?): String
    external fun callBytes(method: String, args: String, blobs: Array<ByteArray>?, fds: IntArray?): ByteArray?
    external fun stegoHide(pixels: IntArray, password: ByteArray, payload: ByteArray): String
    external fun stegoReveal(pixels: IntArray, password: ByteArray): ByteArray?
}

/**
 * Builds one engine call. Byte arrays given to [blob] are wiped after the
 * call, so pass copies of anything you still need.
 */
class Call(private val method: String) {
    val args = JSONObject()
    private val blobs = mutableListOf<ByteArray>()
    private val fds = mutableListOf<Int>()

    fun put(key: String, value: Any?): Call = apply { if (value != null) args.put(key, value) }

    fun blob(key: String, bytes: ByteArray?): Call = apply {
        if (bytes != null) {
            args.put(key, blobs.size)
            blobs.add(bytes)
        }
    }

    /** A blob referenced from inside a nested object. */
    fun blobIndex(bytes: ByteArray?): Int {
        if (bytes == null) return -1
        blobs.add(bytes)
        return blobs.size - 1
    }

    fun fd(key: String, fd: Int): Call = apply {
        args.put(key, fds.size)
        fds.add(fd)
    }

    /** The disk the call is about: a file descriptor or a USB drive / partition. */
    fun src(fd: Int): Call = apply {
        args.put("src", JSONObject().put("fd", fds.size))
        fds.add(fd)
    }

    fun srcUsb(t: UsbTarget): Call = apply {
        args.put("src", JSONObject().put("usb", t.handle).put("start", t.start).put("size", t.size))
    }

    fun context(): Call = apply {
        val now = System.currentTimeMillis() / 1000
        Prefs.noteTime(now)
        args.put("context", JSONObject().put("now", now).put("maxSeen", Prefs.maxSeenTime).put("online", Net.online()))
    }

    fun run(progress: Progress? = null): Reply = try {
        Reply(QsCore.call(method, args.toString(), blobs.toTypedArray(), fds.toIntArray(), progress))
    } finally {
        blobs.forEach { it.fill(0) }
    }

    fun bytes(): ByteArray? = try {
        QsCore.callBytes(method, args.toString(), blobs.toTypedArray(), fds.toIntArray())
    } finally {
        blobs.forEach { it.fill(0) }
    }
}

/** A USB drive opened by the engine, or one partition of it. */
data class UsbTarget(val handle: Long, val start: Long, val size: Long, val title: String, val kind: String)

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
    val protected: Boolean,
    val extra: JSONObject,
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
            protected = j.optBoolean("protected"),
            extra = j.optJSONObject("extra") ?: JSONObject(),
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
    "wrong_password", "duress" -> "كلمة المرور أو الـ PIM أو ملفات المفاتيح غير صحيحة، أو أن الملف ليس حاوية مشفّرة."
    "hidden_protected" -> "مُنعت الكتابة لأنها كانت ستقع فوق المجلد المخفي. حماية المجلد المخفي تعمل، وكل كتابة أخرى موقوفة حتى تُغلق الخزنة."
    "policy" -> policyText(message)
    "unsupported" -> when {
        message.contains("writing to NTFS") -> "حاويات NTFS تُفتح للقراءة فقط في هذا الإصدار. لتعديل الملفات استخدم VeraCrypt على الحاسوب، أو أنشئ حاوية exFAT."
        message.contains("4 GB") || message.contains("files over") -> "نظام FAT لا يقبل ملفاً أكبر من 4GB. أنشئ الحاوية بنظام exFAT."
        message.contains("system encryption") -> "هذا قرص نظام مشفّر (قرص الإقلاع)، ولا يُفتح كحاوية."
        message.contains("TPM") -> "قرص BitLocker هذا يُفتح بشريحة TPM أو مفتاح بدء أو بطاقة ذكية فقط. استخدم مفتاح الاسترداد المكوّن من 48 رقماً."
        message.contains("in progress") -> "تشفير BitLocker أو فكّه لم يكتمل على ويندوز. أكمله هناك أولاً."
        message.contains("Vista") -> "صيغة BitLocker القديمة من ويندوز فيستا غير مدعومة."
        message.contains("ReFS") -> "نظام ملفات ReFS غير مدعوم."
        else -> "ميزة غير مدعومة: $message"
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

fun policyText(reason: String): String = when (reason) {
    "online" -> "هذا الملف لا يُفتح والجهاز متصل بالإنترنت. افصل الواي فاي والبيانات ثم حاول."
    "expired" -> "انتهت صلاحية هذا الملف."
    "clock" -> "ساعة الجهاز أُرجعت إلى الوراء، لذلك يُعامل الملف كمنتهي الصلاحية."
    else -> "سياسة الملف تمنع فتحه الآن."
}
