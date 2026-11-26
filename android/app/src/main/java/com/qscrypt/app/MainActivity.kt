package com.qscrypt.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.qscrypt.app.ui.AboutScreen
import com.qscrypt.app.ui.ActivationScreen
import com.qscrypt.app.ui.AttemptsReport
import com.qscrypt.app.ui.AttemptsScreen
import com.qscrypt.app.ui.BenchScreen
import com.qscrypt.app.ui.CalculatorScreen
import com.qscrypt.app.ui.ContactsScreen
import com.qscrypt.app.ui.DrivesScreen
import com.qscrypt.app.ui.GalleryScreen
import com.qscrypt.app.ui.HomeScreen
import com.qscrypt.app.ui.JobsScreen
import com.qscrypt.app.ui.LockScreen
import com.qscrypt.app.ui.LockSetupScreen
import com.qscrypt.app.ui.MediaScreen
import com.qscrypt.app.ui.MessageScreen
import com.qscrypt.app.ui.NewContainerScreen
import com.qscrypt.app.ui.NewEncryptionScreen
import com.qscrypt.app.ui.PdfScreen
import com.qscrypt.app.ui.QscDecryptScreen
import com.qscrypt.app.ui.QscEncryptScreen
import com.qscrypt.app.ui.Qs
import com.qscrypt.app.ui.QsTheme
import com.qscrypt.app.ui.SettingsScreen
import com.qscrypt.app.ui.ShareInScreen
import com.qscrypt.app.ui.SplashScreen
import com.qscrypt.app.ui.StegoScreen
import com.qscrypt.app.ui.TwoFactorSetupScreen
import com.qscrypt.app.ui.UnlockScreen
import com.qscrypt.app.ui.VaultScreen
import com.qscrypt.app.ui.ViewerScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        // No screenshots, no previews in the recent-apps list.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        Prefs.init(applicationContext)
        Net.init(applicationContext)
        AppState.init(applicationContext)
        UsbDrives.init(applicationContext)
        if (Activation.isActive(applicationContext)) Fonts.load(applicationContext)
        AppState.load()
        if (!Prefs.lockConfigured()) AppState.locked = false
        AppState.askNotifications = { askNotifications() }
        takeShared(intent)
        setContent { QsApp() }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeShared(intent)
    }

    /** Files shared from another app wait until the app is unlocked. */
    private fun takeShared(intent: Intent?) {
        intent ?: return
        val uris = mutableListOf<Uri>()
        @Suppress("DEPRECATION")
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val u: Uri? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java) else intent.getParcelableExtra(Intent.EXTRA_STREAM)
                u?.let { uris += it }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val list: List<Uri>? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java) else intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                list?.let { uris += it }
            }
        }
        if (uris.isNotEmpty() && !Prefs.disguised) AppState.shared = uris
    }

    private fun askNotifications() {
        if (Build.VERSION.SDK_INT < 33 || Prefs.disguised || Prefs.notificationsAsked) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        Prefs.notificationsAsked = true
        AppState.pickerOpen = true
        runCatching { notifications.launch(Manifest.permission.POST_NOTIFICATIONS) }
    }

    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        AppState.touched()
        return super.dispatchTouchEvent(ev)
    }

    override fun onStart() {
        super.onStart()
        AppState.onForeground()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) AppState.onBackground()
    }

    override fun onDestroy() {
        if (AppState.askNotifications != null && isFinishing) AppState.askNotifications = null
        super.onDestroy()
    }
}

@Composable
fun QsApp() {
    QsTheme {
        // Disguise mode: a working calculator until the PIN (or the pattern's dots) and "=" are typed.
        if (Prefs.disguised && Prefs.hasPin() && AppState.locked && !AppState.pinPassed) {
            CalculatorScreen()
            return@QsTheme
        }
        // The interface is Arabic: right-to-left whatever the system language.
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
            Box(Modifier.fillMaxSize().background(Qs.base).systemBarsPadding().imePadding()) {
                val context = LocalContext.current
                var active by remember { mutableStateOf(Activation.isActive(context)) }
                var configured by remember { mutableStateOf(Prefs.lockConfigured()) }
                var lockChosen by remember { mutableStateOf(Prefs.lockMode >= 0 || Prefs.secretKind == SECRET_NONE || !PhoneAuth.available(context)) }
                LaunchedEffect(Unit) {
                    if (AppState.selfTest == null) {
                        AppState.selfTest = withContext(Dispatchers.Default) { runCatching { SelfTest.run() }.getOrNull() }
                    }
                }
                when {
                    // The Hacen fonts are sealed with the activation password, so on the
                    // very first launch activation comes first: the opening screen then
                    // always appears in the app's own fonts.
                    !active -> ActivationScreen(onDone = { active = true })
                    !AppState.splashDone -> SplashScreen(onDone = { AppState.splashDone = true })
                    !configured -> LockSetupScreen(onDone = {
                        configured = true
                        lockChosen = Prefs.lockMode >= 0 || Prefs.secretKind == SECRET_NONE || !PhoneAuth.available(context)
                        AppState.locked = false
                    })
                    !lockChosen -> TwoFactorSetupScreen(onDone = { lockChosen = true })
                    AppState.locked -> LockScreen(onReset = { configured = Prefs.lockConfigured() })
                    else -> Router()
                }
            }
        }
    }
}

@Composable
private fun Router() {
    val screen = AppState.top
    BackHandler(enabled = AppState.stack.size > 1) { AppState.pop() }
    // Shared files go to their own screen once the app is open.
    LaunchedEffect(AppState.shared) {
        if (AppState.shared.isNotEmpty() && AppState.top != Screen.ShareIn) AppState.push(Screen.ShareIn)
    }
    key(screen) {
        when (screen) {
            Screen.Home -> HomeScreen()
            Screen.Drives -> DrivesScreen()
            Screen.Contacts -> ContactsScreen()
            Screen.Settings -> SettingsScreen()
            Screen.About -> AboutScreen()
            Screen.NewEncryption -> NewEncryptionScreen()
            Screen.QscEncrypt -> QscEncryptScreen()
            is Screen.NewContainer -> NewContainerScreen(screen.format, screen.usb)
            Screen.Stego -> StegoScreen()
            is Screen.QscDecrypt -> QscDecryptScreen(screen.uri, screen.name, screen.size)
            is Screen.Unlock -> UnlockScreen(screen.container, screen.usb)
            is Screen.Vault -> VaultScreen(screen.handle, screen.path)
            is Screen.Viewer -> ViewerScreen(screen.handle, screen.path, screen.name, screen.size)
            is Screen.Gallery -> GalleryScreen(screen.handle, screen.dir, screen.start)
            is Screen.Media -> MediaScreen(screen.handle, screen.path, screen.name, screen.size)
            is Screen.Pdf -> PdfScreen(screen.handle, screen.path, screen.name, screen.size)
            Screen.JobsList -> JobsScreen()
            Screen.Bench -> BenchScreen()
            Screen.Message -> MessageScreen()
            Screen.Attempts -> AttemptsScreen()
            Screen.ShareIn -> ShareInScreen()
        }
    }
    AttemptsReport()
}
