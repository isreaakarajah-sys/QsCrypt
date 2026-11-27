package com.qscrypt.app

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import android.widget.Toast
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** Every screen of the app. Navigation is a simple back stack. */
sealed interface Screen {
    data object Home : Screen
    data object Drives : Screen
    data object Contacts : Screen
    data object Settings : Screen
    data class Unlock(val container: Container, val usb: UsbTarget? = null) : Screen
    data class Vault(val handle: Long, val path: String = "/") : Screen
    /** Text files. */
    data class Viewer(val handle: Long, val path: String, val name: String, val size: Long) : Screen
    /** Pictures of a folder, swiped one after another, starting at `start`. */
    data class Gallery(val handle: Long, val dir: String, val start: String) : Screen
    /** Video and audio, streamed from the vault. */
    data class Media(val handle: Long, val path: String, val name: String, val size: Long) : Screen
    data class Pdf(val handle: Long, val path: String, val name: String, val size: Long) : Screen
    data object NewEncryption : Screen
    /** format: VeraCrypt, TrueCrypt, BitLocker or QsCrypt. */
    data class NewContainer(val format: String, val usb: UsbTarget? = null) : Screen
    data object QscEncrypt : Screen
    data class QscDecrypt(val uri: String, val name: String, val size: Long) : Screen
    data object About : Screen
    data object Stego : Screen
    data object JobsList : Screen
    data object Bench : Screen
    data object Message : Screen
    data object Attempts : Screen
    data object Diag : Screen
    data object Backup : Screen
    data object Phone : Screen
    data class PhoneDir(val path: String) : Screen
    data class PhoneCategory(val category: String) : Screen
    data object EncryptPhone : Screen
    data class Camera(val handle: Long, val dir: String) : Screen
    /** Files shared to QsCrypt from another app. */
    data object ShareIn : Screen
}

/** An unlocked volume. */
data class Session(val handle: Long, val container: Container, val info: VolumeInfo, val openedAt: Long, val usb: UsbTarget? = null) {
    val plain: Boolean get() = info.format == "Plain"

    /** The same for every opening of this container (USB handles change with each connection). */
    val stableKey: String get() = stableKeyOf(container, usb)
}

/** A key for favourites and resumable jobs that survives reconnecting a USB drive. */
fun stableKeyOf(container: Container, usb: UsbTarget?): String {
    if (usb == null) return container.uri
    val drive = UsbDrives.sessions.firstOrNull { it.handle == usb.handle }?.info
    val id = listOf(drive?.optString("vendor").orEmpty().trim(), drive?.optString("product").orEmpty().trim(), drive?.optLong("size")?.toString().orEmpty()).joinToString("|")
    return "usbdrive:$id:${usb.start}:${usb.size}"
}

/** Items copied or cut in one vault, to paste in another folder or vault. */
data class Clip(val handle: Long, val dir: String, val names: List<String>, val move: Boolean, val vaultName: String)

object AppState {
    val stack = mutableStateListOf<Screen>(Screen.Home)
    val sessions = mutableStateListOf<Session>()
    var containers by mutableStateOf<List<Container>>(emptyList())
    var locked by mutableStateOf(true)
    var selfTest by mutableStateOf<SelfTest?>(null)
    /** The opening screen is shown once per launch of the app process. */
    var splashDone by mutableStateOf(false)
    /** The PIN was entered on the disguise calculator; only a second factor may remain. */
    var pinPassed by mutableStateOf(false)
    var clip by mutableStateOf<Clip?>(null)
    /** Phone files copied or cut in «ملفاتي». */
    var phoneClip by mutableStateOf<PhoneClip?>(null)
    /** Documents shared to the app, waiting for a destination. */
    var shared by mutableStateOf<List<Uri>>(emptyList())
    /** Shared documents handed to the QsCrypt encryption screen. */
    var encryptShared: List<Uri> = emptyList()
    /** Failed attempts since the last unlock, to report once the app is open. */
    var attemptsToReport by mutableStateOf(0)
    /** Asks for the notification permission (Android 13+), set by the activity. */
    var askNotifications: (() -> Unit)? = null

    var inBackground = false
        private set
    private var backgroundAt = 0L
    var lastInteraction = SystemClock.elapsedRealtime()

    /** Set before launching a system picker so returning from it does not lock. */
    var pickerOpen = false

    private var app: Context? = null

    fun init(context: Context) {
        if (app == null) app = context.applicationContext
    }

    val top: Screen get() = stack.last()

    fun push(s: Screen) {
        stack.add(s)
    }

    fun pop(): Boolean {
        if (stack.size <= 1) return false
        stack.removeAt(stack.size - 1)
        return true
    }

    fun replaceTop(s: Screen) {
        stack[stack.size - 1] = s
    }

    /** Switches bottom-navigation tab. */
    fun tab(s: Screen) {
        stack.clear()
        stack.add(Screen.Home)
        if (s != Screen.Home) stack.add(s)
    }

    fun load() {
        containers = Prefs.containers()
    }

    /** The profile changed (see [Profile]): nothing of the previous one may stay on screen. */
    fun profileChanged() {
        stack.clear()
        stack.add(Screen.Home)
        clip = null
        phoneClip = null
        shared = emptyList()
        encryptShared = emptyList()
        attemptsToReport = 0
        load()
    }

    fun addContainer(c: Container): Container {
        val existing = containers.firstOrNull { it.uri == c.uri }
        if (existing != null) return existing
        containers = listOf(c) + containers
        Prefs.saveContainers(containers)
        return c
    }

    fun updateContainer(c: Container) {
        containers = containers.map { if (it.uri == c.uri) c else it }
        Prefs.saveContainers(containers)
    }

    fun removeContainer(c: Container) {
        containers = containers.filterNot { it.uri == c.uri }
        Prefs.saveContainers(containers)
    }

    fun session(handle: Long): Session? = sessions.firstOrNull { it.handle == handle }

    fun sessionFor(c: Container): Session? = sessions.firstOrNull { it.container.uri == c.uri }

    /** A vault was opened: register it, and continue its unfinished free-space fill. */
    fun opened(s: Session) {
        sessions.add(s)
        app?.let { Fill.resumeFor(it, s) }
    }

    /** Flushes and closes one vault (its jobs are cancelled first). */
    fun closeSession(handle: Long) {
        Jobs.cancelFor(handle)
        QsCore.closeVolume(handle)
        sessions.removeAll { it.handle == handle }
        if (clip?.handle == handle) clip = null
        Thumbs.forget(handle)
        stack.removeAll { it.usesVault(handle) }
        if (stack.isEmpty()) stack.add(Screen.Home)
        app?.let { JobService.vaultsNotice(it) }
    }

    private fun Screen.usesVault(handle: Long): Boolean = when (this) {
        is Screen.Vault -> this.handle == handle
        is Screen.Viewer -> this.handle == handle
        is Screen.Gallery -> this.handle == handle
        is Screen.Media -> this.handle == handle
        is Screen.Pdf -> this.handle == handle
        else -> false
    }

    /**
     * Closes every vault. With `keepBusy`, vaults a background job is using
     * stay open until the job ends (then close, see [jobEnded]).
     */
    fun closeAll(keepBusy: Boolean = true) {
        val all = sessions.toList()
        for (s in all) {
            if (keepBusy && Jobs.busy(s.handle)) continue
            closeSession(s.handle)
        }
        if (sessions.isEmpty()) {
            QsCore.closeAll()
            stack.removeAll { it is Screen.Unlock }
            if (stack.isEmpty()) stack.add(Screen.Home)
        }
    }

    /**
     * Closes one vault from its screen. On a USB drive, the drive is released
     * too once no vault on it is open, so it can be pulled out.
     */
    fun safeClose(context: Context, s: Session) {
        closeSession(s.handle)
        var text = "أُغلقت «${s.container.name.substringBeforeLast('.').ifBlank { s.container.name }}» بأمان"
        val usb = s.usb
        if (usb != null) {
            val drive = UsbDrives.sessions.firstOrNull { it.handle == usb.handle }
            if (drive != null && sessions.none { it.usb?.handle == usb.handle }) {
                UsbDrives.close(drive)
                text = "أُغلقت الخزنة وفُصل القرص بأمان. يمكنك نزعه الآن."
            }
        }
        runCatching { Toast.makeText(context, text, Toast.LENGTH_LONG).show() }
    }

    /** "Lock all": cancel what runs on the vaults, close them all, lock the app. */
    fun lockAll(context: Context, from: String) {
        init(context)
        Jobs.list.filter { it.active && it.vaults.isNotEmpty() }.forEach { it.interrupt() }
        val n = sessions.size
        closeAll(keepBusy = false)
        UsbDrives.sessions.toList().forEach { UsbDrives.close(it) }
        lock(force = true)
        if (from != "screen" && n > 0) runCatching { Toast.makeText(context, "أُغلقت الخزنات بأمان", Toast.LENGTH_SHORT).show() }
    }

    fun jobEnded(job: Jobs.Job) {
        // Locked while it ran: close the vaults it kept open.
        if (locked && Prefs.closeVaultsOnLock) {
            job.vaults.filter { !Jobs.busy(it) }.forEach { closeSession(it) }
        }
    }

    fun onBackground() {
        inBackground = true
        backgroundAt = SystemClock.elapsedRealtime()
        app?.let { JobService.vaultsNotice(it) }
    }

    fun onForeground() {
        inBackground = false
        app?.let { JobService.vaultsNotice(it) }
        if (!Prefs.lockConfigured() || backgroundAt == 0L) return
        val away = SystemClock.elapsedRealtime() - backgroundAt
        backgroundAt = 0L
        if (pickerOpen && away < 10 * 60_000) {
            pickerOpen = false
            return
        }
        pickerOpen = false
        if (Prefs.lockOnLeave && away >= Prefs.autoLockMs) lock()
    }

    /** Locks the app; vaults close too if the setting says so (or `force`). */
    fun lock(force: Boolean = false) {
        if (!Prefs.lockConfigured()) {
            if (force) closeAll(keepBusy = false)
            return
        }
        locked = true
        pinPassed = false
        if (force || Prefs.closeVaultsOnLock) {
            // A job the user paused would keep its vault open indefinitely: stop it
            // (copies and the free-space fill resume later); running jobs finish first.
            Jobs.list.filter { it.active && it.pauseFlag.get() && it.vaults.isNotEmpty() }.forEach { it.interrupt() }
            closeAll(keepBusy = !force)
        }
    }

    /** The user touched the app. */
    fun touched() {
        lastInteraction = SystemClock.elapsedRealtime()
    }

    /** Closes vaults left unused for the configured time (checked every half minute). */
    fun idleCheck() {
        val minutes = Prefs.idleCloseMinutes
        if (minutes <= 0 || sessions.isEmpty()) return
        val idle = SystemClock.elapsedRealtime() - maxOf(lastInteraction, if (inBackground) backgroundAt else 0L)
        if (idle >= minutes * 60_000L) {
            closeAll(keepBusy = true)
            lock()
        }
    }
}
