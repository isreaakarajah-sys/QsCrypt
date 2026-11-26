package com.qscrypt.app

import android.content.Context
import android.os.Build
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A small diagnostic log kept on the phone only (the app has no internet):
 * crashes with their stack traces, engine errors and failed background jobs,
 * so a friend can send it when something goes wrong. It never holds
 * passwords, keys or file contents. Settings shows it, copies it, shares it
 * or saves it as a file, and clears it.
 */
object Diag {
    private const val MAX_BYTES = 256 * 1024
    private val lock = Any()
    private var dir: File? = null
    private var version = "?"

    fun init(context: Context) {
        if (dir != null) return
        dir = File(context.filesDir, "diag").apply { mkdirs() }
        version = runCatching {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: "?"
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { write("F", "crash", "thread ${thread.name}\n" + error.stackTraceToString().take(12_000)) }
            previous?.uncaughtException(thread, error)
        }
        note("start", "QsCrypt $version | Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) | ${Build.MANUFACTURER} ${Build.MODEL} | ${Build.SUPPORTED_ABIS.joinToString(",")}")
    }

    /** The decoy profile (duress PIN) keeps its own, separate log. */
    private fun file(): File? = dir?.let { File(it, if (Profile.decoy) "decoy.txt" else "log.txt") }

    fun note(tag: String, message: String) = write("I", tag, message)
    fun warn(tag: String, message: String) = write("W", tag, message)
    fun error(tag: String, error: Throwable) = write("E", tag, error.stackTraceToString().take(6_000))

    private fun write(level: String, tag: String, message: String) {
        val f = file() ?: return
        val line = "${stamp()} $level/$tag: ${message.replace("\n", "\n    ")}\n"
        synchronized(lock) {
            runCatching {
                if (f.length() > MAX_BYTES) {
                    // Keep the newer half.
                    val text = f.readText()
                    f.writeText(text.substring(text.length / 2).substringAfter('\n'))
                }
                f.appendText(line)
            }
        }
    }

    fun read(): String = synchronized(lock) { file()?.takeIf { it.exists() }?.readText().orEmpty() }

    fun size(): Long = file()?.length() ?: 0L

    fun clear() = synchronized(lock) { file()?.delete(); Unit }

    /** The text to send: a short header about the phone, then the log. */
    fun report(): String = buildString {
        append("QsCrypt $version\n")
        append("Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n")
        append("${Build.MANUFACTURER} ${Build.MODEL}\n")
        append("ABI ${Build.SUPPORTED_ABIS.joinToString(",")}\n")
        append("----\n")
        append(read())
    }

    private fun stamp(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
}
