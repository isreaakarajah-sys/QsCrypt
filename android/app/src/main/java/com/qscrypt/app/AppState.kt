package com.qscrypt.app

import android.os.SystemClock
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
    data class Unlock(val container: Container) : Screen
    data class Vault(val handle: Long, val path: String = "/") : Screen
    data class Viewer(val handle: Long, val path: String, val name: String, val size: Long) : Screen
    data object NewEncryption : Screen
    data class NewContainer(val truecrypt: Boolean) : Screen
    data object QscEncrypt : Screen
    data class QscDecrypt(val uri: String, val name: String, val size: Long) : Screen
    data object About : Screen
}

/** An unlocked volume. */
data class Session(val handle: Long, val container: Container, val info: VolumeInfo, val openedAt: Long)

object AppState {
    val stack = mutableStateListOf<Screen>(Screen.Home)
    val sessions = mutableStateListOf<Session>()
    var containers by mutableStateOf<List<Container>>(emptyList())
    var locked by mutableStateOf(true)
    var selfTest by mutableStateOf<SelfTest?>(null)
    /** The opening screen is shown once per launch of the app process. */
    var splashDone by mutableStateOf(false)

    private var backgroundAt = 0L

    /** Set before launching a system picker so returning from it does not lock. */
    var pickerOpen = false

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

    fun closeSession(handle: Long) {
        QsCore.closeVolume(handle)
        sessions.removeAll { it.handle == handle }
        stack.removeAll { (it is Screen.Vault && it.handle == handle) || (it is Screen.Viewer && it.handle == handle) }
        if (stack.isEmpty()) stack.add(Screen.Home)
    }

    fun closeAll() {
        QsCore.closeAll()
        sessions.clear()
        stack.removeAll { it is Screen.Vault || it is Screen.Viewer || it is Screen.Unlock }
        if (stack.isEmpty()) stack.add(Screen.Home)
    }

    fun onBackground() {
        backgroundAt = SystemClock.elapsedRealtime()
    }

    fun onForeground() {
        if (!Prefs.hasPin() || backgroundAt == 0L) return
        val away = SystemClock.elapsedRealtime() - backgroundAt
        backgroundAt = 0L
        if (pickerOpen && away < 10 * 60_000) {
            pickerOpen = false
            return
        }
        pickerOpen = false
        if (away >= Prefs.autoLockMs) lock()
    }

    fun lock() {
        if (!Prefs.hasPin()) return
        locked = true
        if (Prefs.closeVaultsOnLock) closeAll()
    }
}
