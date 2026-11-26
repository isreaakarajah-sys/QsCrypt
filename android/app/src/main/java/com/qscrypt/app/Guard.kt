package com.qscrypt.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Process start: settings and the guards, before any screen, service or tile. */
class QsApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Prefs.init(this)
        Net.init(this)
        AppState.init(this)
        Jobs.init(this)
        Jobs.loadPending()
        UsbDrives.init(this)
        Guard.init(this)
        Guard.cleanCache(this)
    }
}

/**
 * Closes vaults automatically: when the screen turns off, and after a time
 * without use (both optional, in Settings). Also keeps the components that
 * would name the app (share target, quick settings tile) off in disguise mode.
 */
object Guard {
    private var started = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    fun init(context: Context) {
        if (started) return
        started = true
        val app = context.applicationContext
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                if (i.action == Intent.ACTION_SCREEN_OFF && Prefs.closeOnScreenOff && (AppState.sessions.isNotEmpty() || !AppState.locked)) {
                    AppState.closeAll(keepBusy = true)
                    AppState.lock()
                }
            }
        }
        ContextCompat.registerReceiver(app, r, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
        scope.launch {
            while (true) {
                delay(30_000)
                runCatching { AppState.idleCheck() }
            }
        }
        components(app, Prefs.disguised)
    }

    /**
     * Temporary files left by a run that was killed: copy buffers (encrypted
     * with a key that died with the process) and encrypted intermediates.
     */
    fun cleanCache(context: Context) {
        val dir = context.cacheDir ?: return
        runCatching {
            dir.listFiles()?.filter { f ->
                f.isFile && (f.name.startsWith("copy-") || f.name.startsWith("wrap-") || f.name in setOf("unwrap.qsc", "stego.qsc", "revealed.qsc"))
            }?.forEach { it.delete() }
        }
    }

    /** The share target and the tile exist only when the app is not disguised. */
    fun components(context: Context, disguised: Boolean) {
        val pm = context.packageManager
        val state = if (disguised) PackageManager.COMPONENT_ENABLED_STATE_DISABLED else PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
        for (name in listOf("com.qscrypt.app.ShareTarget", "com.qscrypt.app.LockTileService")) {
            runCatching { pm.setComponentEnabledSetting(ComponentName(context, name), state, PackageManager.DONT_KILL_APP) }
        }
    }
}

/** Quick settings tile: "lock all vaults" from anywhere. */
@RequiresApi(Build.VERSION_CODES.N)
class LockTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        qsTile?.apply {
            state = if (AppState.sessions.isNotEmpty()) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "أقفل الخزنات"
            updateTile()
        }
    }

    override fun onClick() {
        super.onClick()
        AppState.lockAll(applicationContext, "tile")
        onStartListening()
    }
}
