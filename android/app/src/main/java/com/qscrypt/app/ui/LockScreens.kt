package com.qscrypt.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val PIN_LENGTH = 6

@Composable
private fun PinDots(count: Int, error: Boolean) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        modifier = Modifier.semantics { contentDescription = "تم إدخال $count أرقام من $PIN_LENGTH" },
    ) {
        repeat(PIN_LENGTH) { i ->
            val filled = i < count
            val color = if (error) Qs.coral else Qs.brass
            Box(
                Modifier
                    .size(14.dp)
                    .clip(CircleShape)
                    .then(if (filled) Modifier.background(color) else Modifier.border(1.5.dp, if (error) Qs.coral else Qs.muted, CircleShape)),
            )
        }
    }
}

@Composable
private fun Key(label: String? = null, icon: Int? = null, iconTint: androidx.compose.ui.graphics.Color = Qs.ivory, description: String? = null, enabled: Boolean = true, onClick: () -> Unit) {
    Box(
        Modifier
            .size(72.dp)
            .clip(CircleShape)
            .background(Qs.surface)
            .border(1.dp, Qs.line, CircleShape)
            .clickable(enabled = enabled, onClick = onClick)
            .alpha(if (enabled) 1f else 0.35f)
            .semantics { if (description != null) contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        if (label != null) Text(label, style = T.title.copy(fontSize = 28.sp, lineHeight = 32.sp))
        if (icon != null) QsIcon(icon, iconTint, 26.dp)
    }
}

/** Digits laid out left-to-right like a phone keypad, even in RTL. */
@Composable
private fun PinPad(enabled: Boolean, onDigit: (Char) -> Unit, onBackspace: () -> Unit, onBiometric: () -> Unit) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            for (row in listOf("123", "456", "789")) {
                Row(horizontalArrangement = Arrangement.spacedBy(30.dp)) {
                    row.forEach { d -> Key(label = d.toString(), enabled = enabled) { onDigit(d) } }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(30.dp)) {
                Key(icon = R.drawable.ic_finger, iconTint = Qs.brass, description = "البصمة", enabled = enabled, onClick = onBiometric)
                Key(label = "0", enabled = enabled) { onDigit('0') }
                Key(icon = R.drawable.ic_backspace, description = "حذف", enabled = enabled, onClick = onBackspace)
            }
        }
    }
}

@Composable
private fun PinLayout(title: String, subtitle: String, pin: String, error: Boolean, busy: Boolean, padEnabled: Boolean, footer: @Composable () -> Unit, onDigit: (Char) -> Unit, onBackspace: () -> Unit, onBiometric: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Gap(72.dp)
        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(92.dp))
        Gap(24.dp)
        Text(title, style = T.display, textAlign = TextAlign.Center)
        Gap(6.dp)
        Text(subtitle, style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = if (error) Qs.coral else Qs.muted), textAlign = TextAlign.Center)
        Gap(34.dp)
        Box(Modifier.height(24.dp), contentAlignment = Alignment.Center) {
            if (busy) CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp)) else PinDots(pin.length, error)
        }
        Gap(36.dp)
        PinPad(enabled = padEnabled && !busy, onDigit = onDigit, onBackspace = onBackspace, onBiometric = onBiometric)
        Gap(28.dp)
        footer()
        Gap(24.dp)
    }
}

/** First launch: create the app PIN (entered twice). */
@Composable
fun PinSetupScreen(onDone: () -> Unit) {
    var first by remember { mutableStateOf<String?>(null) }
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val subtitle = when {
        error -> "الرمزان غير متطابقين. أعد المحاولة"
        first == null -> "اختر رمزاً من $PIN_LENGTH أرقام لقفل التطبيق"
        else -> "أعد إدخال الرمز للتأكيد"
    }
    PinLayout(
        title = if (first == null) "أهلاً بك في QsCrypt" else "تأكيد الرمز",
        subtitle = subtitle,
        pin = pin,
        error = error,
        busy = busy,
        padEnabled = true,
        footer = {
            Text("لماذا الرمز السري؟", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable { info = true }.padding(8.dp))
        },
        onDigit = { d ->
            if (pin.length >= PIN_LENGTH) return@PinLayout
            error = false
            pin += d
            if (pin.length == PIN_LENGTH) {
                val f = first
                if (f == null) {
                    first = pin
                    pin = ""
                } else if (f == pin) {
                    busy = true
                    scope.launch {
                        val ok = withContext(Dispatchers.Default) { Prefs.setPin(pin) }
                        busy = false
                        if (ok) onDone() else {
                            error = true
                            pin = ""
                        }
                    }
                } else {
                    error = true
                    first = null
                    pin = ""
                }
            }
        },
        onBackspace = { if (pin.isNotEmpty()) pin = pin.dropLast(1) },
        onBiometric = {},
    )
    if (info) {
        QsAlert(
            title = "قفل التطبيق",
            text = "الرمز يمنع أي شخص يمسك جوالك من رؤية قائمة خزناتك أو فتح ما هو مفتوح منها. هو لا يغني عن كلمة مرور كل حاوية، ولا يُخزَّن إلا كبصمة مشتقّة منه.",
            confirm = "فهمت",
            dismiss = null,
            onConfirm = { info = false },
            onDismiss = { info = false },
        )
    }
}

/** Unlocks the app. Repeated failures lock entry out for growing periods. */
@Composable
fun LockScreen() {
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var recovery by remember { mutableStateOf(false) }
    var biometric by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val lockedFor = (Prefs.lockUntil - now).coerceAtLeast(0)

    LaunchedEffect(lockedFor > 0) {
        while (Prefs.lockUntil > System.currentTimeMillis()) {
            now = System.currentTimeMillis()
            delay(500)
        }
        now = System.currentTimeMillis()
    }

    val subtitle = when {
        lockedFor > 0 -> "محاولات كثيرة خاطئة. انتظر ${(lockedFor + 999) / 1000} ثانية"
        error -> "رمز خاطئ. بقيت ${(5 - Prefs.failCount).coerceAtLeast(0)} محاولات قبل الانتظار"
        else -> "افتح QsCrypt بالرمز السري"
    }
    PinLayout(
        title = "أهلاً من جديد",
        subtitle = subtitle,
        pin = pin,
        error = error || lockedFor > 0,
        busy = busy,
        padEnabled = lockedFor == 0L,
        footer = {
            Text("نسيت الرمز؟", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable { recovery = true }.padding(8.dp))
        },
        onDigit = { d ->
            if (pin.length >= PIN_LENGTH || busy) return@PinLayout
            error = false
            pin += d
            if (pin.length == PIN_LENGTH) {
                busy = true
                val attempt = pin
                scope.launch {
                    val ok = withContext(Dispatchers.Default) { Prefs.checkPin(attempt) }
                    busy = false
                    pin = ""
                    if (ok) {
                        Prefs.failCount = 0
                        Prefs.lockUntil = 0
                        AppState.locked = false
                    } else {
                        val n = Prefs.failCount + 1
                        Prefs.failCount = n
                        if (n >= 5) {
                            val seconds = (30L shl (n - 5).coerceAtMost(7)).coerceAtMost(3600)
                            Prefs.lockUntil = System.currentTimeMillis() + seconds * 1000
                        }
                        now = System.currentTimeMillis()
                        error = true
                    }
                }
            }
        },
        onBackspace = { if (pin.isNotEmpty()) pin = pin.dropLast(1) },
        onBiometric = { biometric = true },
    )
    if (recovery) {
        QsAlert(
            title = "نسيت الرمز؟",
            text = "مفتاح الاسترداد قادم في الإصدار التالي. حالياً يمكنك مسح بيانات التطبيق من إعدادات أندرويد: تُحذف قائمة الخزنات والرمز فقط، وتبقى حاوياتك وملفاتك المشفّرة سليمة وتفتحها بكلمات مرورها.",
            confirm = "حسناً",
            dismiss = null,
            onConfirm = { recovery = false },
            onDismiss = { recovery = false },
        )
    }
    if (biometric) {
        QsAlert(
            title = "البصمة",
            text = "الفتح بالبصمة قادم في الإصدار التالي.",
            confirm = "حسناً",
            dismiss = null,
            onConfirm = { biometric = false },
            onDismiss = { biometric = false },
        )
    }
}
