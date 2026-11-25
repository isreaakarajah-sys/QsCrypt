package com.qscrypt.app

import android.content.Context
import android.graphics.Typeface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.font.FontFamily
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * One-time activation. The APK is public (GitHub Releases), so it only works
 * after the activation password shared with friends is entered once.
 *
 * The password also decrypts `assets/fonts.qsa`, the licensed Hacen fonts
 * (Argon2id + XChaCha20-Poly1305, see android/tools/seal_assets.py): the
 * fonts never exist in clear text in the repository or the APK. A wrong
 * password simply fails to decrypt them, so nothing about the password is
 * stored anywhere.
 */
object Activation {
    private const val ASSET = "fonts.qsa"
    val FONTS = listOf("hacen_xxl.ttf", "hacen_xl.ttf", "hacen_print.ttf")

    fun fontsDir(context: Context) = File(context.filesDir, "fonts")

    fun isActive(context: Context): Boolean =
        Prefs.activated && FONTS.all { File(fontsDir(context), it).length() > 0 }

    /** Letters and digits only, upper case: "k7mp-q4xr" and "K7MPQ4XR" are the same. */
    fun normalize(password: String): String = password.filter { it.isLetterOrDigit() }.uppercase()

    /** Returns true and installs the fonts if the password is right. Slow (Argon2id): call off the main thread. */
    fun activate(context: Context, password: String): Boolean {
        val sealed = runCatching { context.assets.open(ASSET).use { it.readBytes() } }.getOrNull() ?: return false
        val key = normalize(password).toByteArray(Charsets.UTF_8)
        val plain = QsCore.openAsset(sealed, key)
        key.fill(0)
        if (plain == null) return false
        val files = parseBundle(plain)
        plain.fill(0)
        if (files == null || !FONTS.all { name -> files.any { it.first == name } }) return false
        val dir = fontsDir(context).apply { mkdirs() }
        for ((name, bytes) in files) {
            if (name in FONTS) File(dir, name).writeBytes(bytes)
        }
        Prefs.activated = true
        Fonts.load(context)
        return true
    }

    /** "QSFONTS1" | u32 count | { u16 name length | name | u32 size | bytes }* */
    private fun parseBundle(data: ByteArray): List<Pair<String, ByteArray>>? = runCatching {
        val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val magic = ByteArray(8).also { b.get(it) }
        if (String(magic, Charsets.US_ASCII) != "QSFONTS1") return null
        val count = b.int
        (0 until count).map {
            val name = ByteArray(b.short.toInt() and 0xFFFF).also { n -> b.get(n) }
            val bytes = ByteArray(b.int).also { d -> b.get(d) }
            String(name, Charsets.UTF_8) to bytes
        }
    }.getOrNull()
}

/** Font families in use; the Hacen fonts appear once activation decrypted them. */
object Fonts {
    var xxl by mutableStateOf<FontFamily>(FontFamily.Default)
    var xl by mutableStateOf<FontFamily>(FontFamily.Default)
    var print by mutableStateOf<FontFamily>(FontFamily.Default)

    fun load(context: Context) {
        val dir = Activation.fontsDir(context)
        xxl = family(File(dir, "hacen_xxl.ttf"))
        xl = family(File(dir, "hacen_xl.ttf"))
        print = family(File(dir, "hacen_print.ttf"))
    }

    private fun family(file: File): FontFamily =
        if (file.length() > 0) runCatching { FontFamily(Typeface.createFromFile(file)) }.getOrDefault(FontFamily.Default) else FontFamily.Default
}
