package com.qscrypt.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Which set of personal data the app shows.
 *
 * The duress code (Settings, app lock) opens the app on an empty profile that
 * looks like a fresh install: no vault list, no contacts or identity, no
 * fingerprint favourites, no logs. Nothing of the real profile is touched or
 * shown, and the decoy keeps its own data if it is used. The next unlock with
 * the real code returns to the real profile.
 *
 * Settings that change the whole app (the kind of lock, phone-lock modes,
 * disguise, the duress code itself) are hidden in the decoy profile, so it can
 * never alter the real one. Changing "the code" there changes the duress code.
 */
object Profile {
    var decoy by mutableStateOf(false)
        private set

    /** Storage names for the current profile: "name" or "name_decoy". */
    fun name(base: String): String = if (decoy) base + "_decoy" else base

    /** Switches profile after an unlock. Everything of the other profile is closed first. */
    fun enter(decoy: Boolean) {
        if (this.decoy == decoy) return
        // Running work belongs to the profile that started it: resumable jobs
        // are stopped (they resume when their profile comes back), others end.
        Jobs.list.filter { it.active }.forEach { if (it.spec != null) it.interrupt() else it.cancel() }
        AppState.closeAll(keepBusy = false)
        this.decoy = decoy
        Jobs.list.removeAll { !it.active }
        Jobs.loadPending()
        Thumbs.clearAll()
        AppState.profileChanged()
    }
}
