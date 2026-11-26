package com.qscrypt.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlin.math.max

/**
 * QR codes for identity cards. Cards are base45 (the QR alphanumeric set), so
 * they encode compactly. Scanning uses a photo from the system camera app,
 * so QsCrypt needs no camera permission.
 */
object Qr {
    fun encode(text: String, target: Int = 900): Bitmap {
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2)
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
        val scale = max(1, target / m.width)
        val w = m.width * scale
        val h = m.height * scale
        val px = IntArray(w * h)
        val dark = 0xFF0A2A20.toInt()
        val light = 0xFFFFFFFF.toInt()
        for (y in 0 until m.height) {
            for (x in 0 until m.width) {
                val c = if (m[x, y]) dark else light
                for (dy in 0 until scale) {
                    val row = (y * scale + dy) * w + x * scale
                    px.fill(c, row, row + scale)
                }
            }
        }
        return Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888)
    }

    private fun scaled(b: Bitmap, maxSide: Int): Bitmap {
        val side = max(b.width, b.height)
        if (side <= maxSide) return b
        val f = maxSide.toFloat() / side
        return Bitmap.createScaledBitmap(b, (b.width * f).toInt().coerceAtLeast(1), (b.height * f).toInt().coerceAtLeast(1), true)
    }

    private fun tryDecode(source: LuminanceSource): String? {
        val hints = mapOf(DecodeHintType.TRY_HARDER to true, DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
        for (s in listOf(source, source.invert())) {
            for (bin in listOf(HybridBinarizer(s), GlobalHistogramBinarizer(s))) {
                try {
                    return QRCodeReader().decode(BinaryBitmap(bin), hints).text
                } catch (_: Exception) {
                }
            }
        }
        return null
    }

    fun decode(bitmap: Bitmap): String? {
        for (side in intArrayOf(1600, 2400, 1000, 3200)) {
            val b = scaled(bitmap, side)
            val px = IntArray(b.width * b.height)
            b.getPixels(px, 0, b.width, 0, 0, b.width, b.height)
            tryDecode(RGBLuminanceSource(b.width, b.height, px))?.let { return it }
            if (max(bitmap.width, bitmap.height) <= side) break
        }
        return null
    }

    /** Reads a QR code from an image (a camera photo, a screenshot). */
    fun decode(context: Context, uri: Uri): String? = runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        var sample = 1
        while (max(bounds.outWidth, bounds.outHeight) / sample > 3200) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        val bmp = context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) } ?: return null
        decode(bmp)
    }.getOrNull()
}
