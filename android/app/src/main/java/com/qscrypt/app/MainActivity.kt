package com.qscrypt.app

import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.fragment.app.FragmentActivity
import com.qscrypt.app.ui.AboutScreen
import com.qscrypt.app.ui.ActivationScreen
import com.qscrypt.app.ui.CalculatorScreen
import com.qscrypt.app.ui.ContactsScreen
import com.qscrypt.app.ui.DrivesScreen
import com.qscrypt.app.ui.HomeScreen
import com.qscrypt.app.ui.LockScreen
import com.qscrypt.app.ui.NewContainerScreen
import com.qscrypt.app.ui.NewEncryptionScreen
import com.qscrypt.app.ui.PinSetupScreen
import com.qscrypt.app.ui.QscDecryptScreen
import com.qscrypt.app.ui.QscEncryptScreen
import com.qscrypt.app.ui.Qs
import com.qscrypt.app.ui.QsTheme
import com.qscrypt.app.ui.SettingsScreen
import com.qscrypt.app.ui.SplashScreen
import com.qscrypt.app.ui.StegoScreen
import com.qscrypt.app.ui.TwoFactorSetupScreen
import com.qscrypt.app.ui.UnlockScreen
import com.qscrypt.app.ui.VaultScreen
import com.qscrypt.app.ui.ViewerScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
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
        UsbDrives.init(applicationContext)
        if (Activation.isActive(applicationContext)) Fonts.load(applicationContext)
        AppState.load()
        if (!Prefs.hasPin()) AppState.locked = false
        setContent { QsApp() }
    }

    override fun onStart() {
        super.onStart()
        AppState.onForeground()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) AppState.onBackground()
    }
}

@Composable
fun QsApp() {
    QsTheme {
        // Disguise mode: a working calculator until the PIN and "=" are typed.
        if (Prefs.disguised && Prefs.hasPin() && AppState.locked && !AppState.pinPassed) {
            CalculatorScreen()
            return@QsTheme
        }
        // The interface is Arabic: right-to-left whatever the system language.
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
            Box(Modifier.fillMaxSize().background(Qs.base).systemBarsPadding().imePadding()) {
                val context = LocalContext.current
                var active by remember { mutableStateOf(Activation.isActive(context)) }
                var hasPin by remember { mutableStateOf(Prefs.hasPin()) }
                var lockChosen by remember { mutableStateOf(Prefs.lockMode >= 0 || !PhoneAuth.available(context)) }
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
                    !hasPin -> PinSetupScreen(onDone = {
                        hasPin = true
                        AppState.locked = false
                    })
                    !lockChosen -> TwoFactorSetupScreen(onDone = { lockChosen = true })
                    AppState.locked -> LockScreen()
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
        }
    }
}
