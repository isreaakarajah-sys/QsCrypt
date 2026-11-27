package com.qscrypt.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.storage.StorageManager
import android.provider.MediaStore
import android.provider.Settings
import androidx.core.content.ContextCompat
import java.io.File

/** A file or folder on the phone's own storage (or an SD card). */
data class PhoneItem(val file: File, val dir: Boolean, val size: Long, val mtime: Long) {
    val name: String get() = file.name
    val path: String get() = file.absolutePath
}

/** Phone files copied or cut, waiting to be pasted (into a vault or another folder). */
data class PhoneClip(val paths: List<String>, val move: Boolean)

/**
 * The phone's storage, reached like a file manager: with "all files access"
 * on Android 11 and later, with the storage permission before. Nothing here
 * talks to the network; everything stays on the phone.
 */
object PhoneFiles {
    /** A storage volume: the phone's memory or an SD card. */
    data class Volume(val title: String, val root: File, val total: Long, val free: Long, val removable: Boolean)

    enum class Category(val title: String, val icon: Int) {
        Images("الصور", R.drawable.ic_image),
        Videos("الفيديو", R.drawable.ic_video),
        Audio("الصوت", R.drawable.ic_music),
        Documents("المستندات", R.drawable.ic_doc),
        Downloads("التنزيلات", R.drawable.ic_download),
        Apks("ملفات التثبيت", R.drawable.ic_archive),
        Archives("المضغوطة", R.drawable.ic_archive),
        Recent("الحديثة", R.drawable.ic_clock),
    }

    private val DOC_EXT = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "ods", "odp", "csv", "md", "epub", "pages", "numbers", "key", "json", "xml", "html", "htm")
    private val ARCHIVE_EXT = setOf("zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso")

    fun hasAccess(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    /** The settings page where "all files access" is turned on (Android 11+). */
    fun accessIntent(context: Context): Intent =
        Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${context.packageName}"))

    fun accessIntentFallback(): Intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)

    /** The phone's memory first, then SD cards. */
    fun volumes(context: Context): List<Volume> {
        val out = mutableListOf<Volume>()
        val sm = context.getSystemService(StorageManager::class.java)
        // Each app-specific folder sits at <volume root>/Android/data/<package>/files.
        for (dir in context.getExternalFilesDirs(null).filterNotNull()) {
            val root = dir.absolutePath.substringBefore("/Android/data/").let(::File)
            if (out.any { it.root == root }) continue
            val vol = runCatching { sm?.getStorageVolume(root) }.getOrNull()
            val removable = vol?.isRemovable ?: (root != Environment.getExternalStorageDirectory())
            val stat = runCatching { StatFs(root.absolutePath) }.getOrNull()
            out += Volume(
                title = if (!removable) "ذاكرة الهاتف" else (vol?.getDescription(context)?.takeIf { it.isNotBlank() } ?: "بطاقة الذاكرة"),
                root = root,
                total = stat?.totalBytes ?: 0L,
                free = stat?.availableBytes ?: 0L,
                removable = removable,
            )
        }
        if (out.isEmpty()) {
            val root = Environment.getExternalStorageDirectory()
            val stat = runCatching { StatFs(root.absolutePath) }.getOrNull()
            out += Volume("ذاكرة الهاتف", root, stat?.totalBytes ?: 0L, stat?.availableBytes ?: 0L, false)
        }
        return out
    }

    fun item(f: File): PhoneItem = PhoneItem(f, f.isDirectory, if (f.isDirectory) 0L else f.length(), f.lastModified())

    fun list(dir: File, hidden: Boolean): List<PhoneItem> =
        (dir.listFiles() ?: emptyArray()).filter { hidden || !it.name.startsWith(".") }.map(::item)

    /** Items of a category, newest first. */
    fun category(context: Context, c: Category, limit: Int = 2000): List<PhoneItem> = when (c) {
        Category.Downloads -> list(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), false).sortedByDescending { it.mtime }
        Category.Recent -> query(context, "${MediaStore.MediaColumns.DATE_MODIFIED} > ?", arrayOf(((System.currentTimeMillis() / 1000) - 14 * 86400).toString()), limit = 200)
        Category.Images -> query(context, "${MediaStore.Files.FileColumns.MEDIA_TYPE} = ${MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE}", null, limit)
        Category.Videos -> query(context, "${MediaStore.Files.FileColumns.MEDIA_TYPE} = ${MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO}", null, limit)
        Category.Audio -> query(context, "${MediaStore.Files.FileColumns.MEDIA_TYPE} = ${MediaStore.Files.FileColumns.MEDIA_TYPE_AUDIO}", null, limit)
        Category.Documents -> byExtension(context, DOC_EXT, limit)
        Category.Apks -> byExtension(context, setOf("apk", "apks", "xapk"), limit)
        Category.Archives -> byExtension(context, ARCHIVE_EXT, limit)
    }

    /** Files whose name contains the query, anywhere on the phone (the system's file index). */
    fun search(context: Context, q: String, limit: Int = 400): List<PhoneItem> {
        val like = "%" + q.trim().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return query(context, "${MediaStore.MediaColumns.DISPLAY_NAME} LIKE ? ESCAPE '\\'", arrayOf(like), limit, withDirs = true)
    }

    private fun byExtension(context: Context, exts: Set<String>, limit: Int): List<PhoneItem> {
        val sel = exts.joinToString(" OR ") { "${MediaStore.MediaColumns.DISPLAY_NAME} LIKE ?" }
        return query(context, "($sel)", exts.map { "%.$it" }.toTypedArray(), limit)
    }

    @Suppress("DEPRECATION")
    private fun query(context: Context, selection: String, args: Array<String>?, limit: Int, withDirs: Boolean = false): List<PhoneItem> {
        val uri = MediaStore.Files.getContentUri("external")
        val cols = arrayOf(MediaStore.MediaColumns.DATA, MediaStore.MediaColumns.SIZE, MediaStore.MediaColumns.DATE_MODIFIED, MediaStore.Files.FileColumns.MIME_TYPE)
        val out = mutableListOf<PhoneItem>()
        runCatching {
            context.contentResolver.query(uri, cols, selection, args, "${MediaStore.MediaColumns.DATE_MODIFIED} DESC")?.use { c ->
                while (c.moveToNext() && out.size < limit) {
                    val path = c.getString(0) ?: continue
                    val f = File(path)
                    val isDir = c.isNull(3) && f.isDirectory
                    if (isDir && !withDirs) continue
                    if (!f.exists()) continue
                    out += PhoneItem(f, isDir, if (isDir) 0L else c.getLong(1), c.getLong(2) * 1000)
                }
            }
        }
        return out
    }

    /** Every file under these items (folders walked), for imports and size estimates. */
    fun walk(items: List<File>, out: MutableList<File> = mutableListOf(), depth: Int = 0): List<File> {
        for (f in items) {
            if (f.isDirectory) {
                if (depth < 48) walk((f.listFiles() ?: emptyArray()).toList(), out, depth + 1)
            } else {
                out += f
            }
        }
        return out
    }

    fun totalSize(items: List<File>): Long = walk(items).sumOf { it.length() }

    /** "name (2).ext" until free in this folder. */
    fun freeName(dir: File, name: String): String {
        if (!File(dir, name).exists()) return name
        val base = name.substringBeforeLast('.', name)
        val ext = if (name.contains('.') && !name.startsWith('.')) "." + name.substringAfterLast('.') else ""
        for (n in 2..9999) {
            val c = "$base ($n)$ext"
            if (!File(dir, c).exists()) return c
        }
        return name
    }

    fun mkdir(parent: File, name: String): Boolean = File(parent, name).mkdir()

    fun rename(f: File, name: String): File? {
        val to = File(f.parentFile, name)
        if (to.exists() || name.isBlank() || name.contains('/')) return null
        return if (f.renameTo(to)) to.also { rescan(it.parentFile?.let { p -> listOf(f, it) } ?: listOf(it)) } else null
    }

    /** Deletes files and folders; tells the gallery so they disappear there too. */
    fun delete(items: List<File>): Int {
        var n = 0
        val gone = mutableListOf<File>()
        for (f in items) {
            val all = if (f.isDirectory) walk(listOf(f)) else listOf(f)
            if (if (f.isDirectory) f.deleteRecursively() else f.delete()) {
                n++
                gone += all
            }
        }
        rescan(gone)
        return n
    }

    private var app: Context? = null

    fun init(context: Context) {
        app = context.applicationContext
    }

    /** The system's media index follows changes made by the app. */
    fun rescan(files: List<File>) {
        val c = app ?: return
        if (files.isEmpty()) return
        runCatching { MediaScannerConnection.scanFile(c, files.map { it.absolutePath }.toTypedArray(), null, null) }
    }

    /** Folders worth encrypting at once: camera, screenshots, documents, downloads. */
    data class Personal(val title: String, val folder: File, val vaultFolder: String)

    fun personal(): List<Personal> {
        val root = Environment.getExternalStorageDirectory()
        fun pub(type: String) = Environment.getExternalStoragePublicDirectory(type)
        return listOf(
            Personal("صور وفيديو الكاميرا", File(pub(Environment.DIRECTORY_DCIM), "Camera"), "الكاميرا"),
            Personal("لقطات الشاشة", File(pub(Environment.DIRECTORY_PICTURES), "Screenshots").takeIf { it.exists() } ?: File(pub(Environment.DIRECTORY_DCIM), "Screenshots"), "لقطات الشاشة"),
            Personal("الصور الأخرى", pub(Environment.DIRECTORY_PICTURES), "الصور"),
            Personal("المستندات", pub(Environment.DIRECTORY_DOCUMENTS), "المستندات"),
            Personal("التنزيلات", pub(Environment.DIRECTORY_DOWNLOADS), "التنزيلات"),
            Personal("وسائط واتساب", File(root, "Android/media/com.whatsapp/WhatsApp/Media").takeIf { it.exists() } ?: File(root, "WhatsApp/Media"), "واتساب"),
        ).filter { it.folder.exists() }
    }
}
