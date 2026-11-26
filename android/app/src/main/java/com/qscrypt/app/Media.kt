package com.qscrypt.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.media.MediaDataSource
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import android.util.LruCache
import androidx.annotation.RequiresApi
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import java.io.ByteArrayInputStream

/**
 * Viewing files without writing them out: everything is read from the vault
 * on demand and decrypted in memory only.
 */
object VaultRead {
    /** Up to `len` bytes at `offset` (at most 8 MiB per call), or null on error. */
    fun range(handle: Long, path: String, offset: Long, len: Int): ByteArray? =
        Call("volume.readRange").put("handle", handle).put("path", path).put("offset", offset).put("len", len).bytes()
}

/** Decodes a picture, downsampled to `maxSide`, turned upright from its EXIF orientation. */
fun decodePicture(bytes: ByteArray, maxSide: Int): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= maxSide) sample *= 2
    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample }) ?: return null
    val orientation = runCatching { ExifInterface(ByteArrayInputStream(bytes)).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL) }
        .getOrDefault(ExifInterface.ORIENTATION_NORMAL)
    val m = Matrix()
    when (orientation) {
        ExifInterface.ORIENTATION_ROTATE_90 -> m.postRotate(90f)
        ExifInterface.ORIENTATION_ROTATE_180 -> m.postRotate(180f)
        ExifInterface.ORIENTATION_ROTATE_270 -> m.postRotate(270f)
        ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> m.postScale(-1f, 1f)
        ExifInterface.ORIENTATION_FLIP_VERTICAL -> m.postScale(1f, -1f)
        ExifInterface.ORIENTATION_TRANSPOSE -> { m.postRotate(90f); m.postScale(-1f, 1f) }
        ExifInterface.ORIENTATION_TRANSVERSE -> { m.postRotate(270f); m.postScale(-1f, 1f) }
        else -> return bmp
    }
    return runCatching { Bitmap.createBitmap(bmp, 0, 0, bmp.width, bmp.height, m, true) }.getOrDefault(bmp)
}

/** Thumbnails of pictures, kept in memory only, dropped when their vault closes. */
object Thumbs {
    private const val MAX_SOURCE = 32L shl 20
    private val cache = object : LruCache<String, ImageBitmap>(40 shl 20) {
        override fun sizeOf(key: String, value: ImageBitmap) = value.width * value.height * 4
    }

    fun cached(handle: Long, path: String): ImageBitmap? = cache.get("$handle:$path")

    fun clearAll() = cache.evictAll()

    /** Two pictures at a time: a folder of large photos must not fill the memory. */
    private val gate = java.util.concurrent.Semaphore(2)

    /** Reads and shrinks a picture (on a background thread). */
    fun load(handle: Long, path: String, size: Long, side: Int = 320): ImageBitmap? {
        cached(handle, path)?.let { return it }
        if (size <= 0 || size > MAX_SOURCE) return null
        gate.acquire()
        try {
            cached(handle, path)?.let { return it }
            val bytes = try {
                QsCore.readFile(handle, path, MAX_SOURCE)
            } catch (e: OutOfMemoryError) {
                null
            } ?: return null
            val bmp = try {
                decodePicture(bytes, side)
            } catch (e: OutOfMemoryError) {
                null
            } finally {
                bytes.fill(0)
            }
            val img = bmp?.asImageBitmap() ?: return null
            cache.put("$handle:$path", img)
            return img
        } finally {
            gate.release()
        }
    }

    fun forget(handle: Long) {
        cache.snapshot().keys.filter { it.startsWith("$handle:") }.forEach { cache.remove(it) }
    }
}

/**
 * Feeds MediaPlayer from the vault: 512 KiB blocks, a few kept in memory,
 * nothing on disk.
 */
class VaultMediaSource(private val handle: Long, private val path: String, private val length: Long) : MediaDataSource() {
    private val block = 512 * 1024
    private val blocks = object : LinkedHashMap<Long, ByteArray>(8, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>): Boolean {
            if (size > 8) {
                eldest.value.fill(0)
                return true
            }
            return false
        }
    }

    @Synchronized
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position >= length) return -1
        var pos = position
        var off = offset
        var left = minOf(size.toLong(), length - position).toInt()
        var n = 0
        while (left > 0) {
            val b = pos / block
            val data = blocks[b] ?: VaultRead.range(handle, path, b * block, block)?.also { blocks[b] = it } ?: break
            val inBlock = (pos - b * block).toInt()
            if (inBlock >= data.size) break
            val take = minOf(left, data.size - inBlock)
            System.arraycopy(data, inBlock, buffer, off, take)
            pos += take
            off += take
            left -= take
            n += take
        }
        return if (n == 0) -1 else n
    }

    override fun getSize(): Long = length

    @Synchronized
    override fun close() {
        blocks.values.forEach { it.fill(0) }
        blocks.clear()
    }
}

/**
 * A seekable file descriptor whose reads come from the vault (Android 8+),
 * for readers that need a real descriptor (PdfRenderer).
 */
@RequiresApi(26)
object VaultProxy {
    private var thread: HandlerThread? = null

    fun open(context: Context, handle: Long, path: String, length: Long): ParcelFileDescriptor? = runCatching {
        val t = thread ?: HandlerThread("qscrypt-proxy").also {
            it.start()
            thread = it
        }
        val sm = context.getSystemService(StorageManager::class.java)
        sm.openProxyFileDescriptor(
            ParcelFileDescriptor.MODE_READ_ONLY,
            object : ProxyFileDescriptorCallback() {
                override fun onGetSize(): Long = length

                override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
                    if (offset >= length) return 0
                    val b = VaultRead.range(handle, path, offset, size) ?: throw ErrnoException("read", OsConstants.EIO)
                    System.arraycopy(b, 0, data, 0, b.size)
                    val n = b.size
                    b.fill(0)
                    return n
                }

                override fun onRelease() {}
            },
            Handler(t.looper),
        )
    }.getOrNull()
}
