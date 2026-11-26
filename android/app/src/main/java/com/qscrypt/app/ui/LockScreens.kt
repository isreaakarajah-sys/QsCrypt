package com.qscrypt.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.qscrypt.app.AppState
import com.qscrypt.app.PhoneAuth
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import com.qscrypt.app.SECRET_NONE
import com.qscrypt.app.SECRET_PATTERN
import com.qscrypt.app.SECRET_PIN
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val PIN_LENGTH = 6
const val PATTERN_MIN = 4

/** "the PIN" or "the pattern", for messages. */
fun secretWord(): String = if (Prefs.secretKind == SECRET_PATTERN) "النمط" else "الرمز"

/** After a wrong PIN or pattern: count it, and block entry for growing periods after 5. */
fun noteFailure(kind: String) {
    val n = Prefs.failCount + 1
    Prefs.failCount = n
    if (n >= 5) {
        val seconds = (30L shl (n - 5).coerceAtMost(7)).coerceAtMost(3600)
        Prefs.lockUntil = System.currentTimeMillis() + seconds * 1000
    }
    Prefs.logAttempt(kind)
}

/** The app is open: report failed attempts made since the last time. */
fun noteUnlocked() {
    Prefs.failCount = 0
    Prefs.lockUntil = 0
    val since = Prefs.attemptsSeen
    AppState.attemptsToReport = Prefs.attemptsLog().count { it.time > since && (it.kind == "app" || it.kind == "calc") }
    if (AppState.attemptsToReport == 0) Prefs.attemptsSeen = System.currentTimeMillis()
    AppState.pinPassed = false
    AppState.locked = false
}

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
private fun PinPad(enabled: Boolean, showBiometric: Boolean, onDigit: (Char) -> Unit, onBackspace: () -> Unit, onBiometric: () -> Unit) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            for (row in listOf("123", "456", "789")) {
                Row(horizontalArrangement = Arrangement.spacedBy(30.dp)) {
                    row.forEach { d -> Key(label = d.toString(), enabled = enabled) { onDigit(d) } }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(30.dp)) {
                if (showBiometric) {
                    Key(icon = R.drawable.ic_finger, iconTint = Qs.brass, description = "بصمة الهاتف", enabled = enabled, onClick = onBiometric)
                } else {
                    Box(Modifier.size(72.dp))
                }
                Key(label = "0", enabled = enabled) { onDigit('0') }
                Key(icon = R.drawable.ic_backspace, description = "حذف", enabled = enabled, onClick = onBackspace)
            }
        }
    }
}

/**
 * A 3x3 pattern. Dots are numbered 1-9 like a phone keypad (left to right,
 * top to bottom); passing over a dot between two others adds it, as Android
 * does. `onDone` gets the dots as digits. Changing `clearKey` clears it.
 */
@Composable
fun PatternPad(enabled: Boolean, error: Boolean, clearKey: Int, size: Dp = 276.dp, onDone: (String) -> Unit) {
    val dots = remember { mutableStateListOf<Int>() }
    var finger by remember { mutableStateOf<Offset?>(null) }
    val done by rememberUpdatedState(onDone)
    LaunchedEffect(clearKey) { dots.clear() }
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Canvas(
            Modifier
                .size(size)
                .semantics { contentDescription = "نمط من تسع نقاط، ${dots.size} موصولة" }
                .pointerInput(enabled) {
                    if (!enabled) return@pointerInput
                    val cell = this.size.width / 3f
                    fun hit(p: Offset): Int? {
                        val col = (p.x / cell).toInt()
                        val row = (p.y / cell).toInt()
                        if (p.x < 0 || p.y < 0 || col !in 0..2 || row !in 0..2) return null
                        val center = Offset((col + 0.5f) * cell, (row + 0.5f) * cell)
                        return if ((p - center).getDistance() <= cell * 0.36f) row * 3 + col else null
                    }
                    fun add(i: Int) {
                        if (i in dots) return
                        val last = dots.lastOrNull()
                        if (last != null) {
                            val r1 = last / 3
                            val c1 = last % 3
                            val r2 = i / 3
                            val c2 = i % 3
                            if ((r1 + r2) % 2 == 0 && (c1 + c2) % 2 == 0) {
                                val mid = ((r1 + r2) / 2) * 3 + (c1 + c2) / 2
                                if (mid !in dots && mid != i) dots.add(mid)
                            }
                        }
                        dots.add(i)
                    }
                    detectDragGestures(
                        onDragStart = { p ->
                            dots.clear()
                            finger = p
                            hit(p)?.let { add(it) }
                        },
                        onDrag = { change, _ ->
                            change.consume()
                            finger = change.position
                            hit(change.position)?.let { add(it) }
                        },
                        onDragEnd = {
                            finger = null
                            if (dots.isNotEmpty()) done(dots.joinToString("") { (it + 1).toString() })
                        },
                        onDragCancel = {
                            finger = null
                            dots.clear()
                        },
                    )
                },
        ) {
            val cell = this.size.width / 3f
            val color = if (error) Qs.coral else Qs.brass
            fun center(i: Int) = Offset((i % 3 + 0.5f) * cell, (i / 3 + 0.5f) * cell)
            for (k in 1 until dots.size) {
                drawLine(color.copy(alpha = 0.85f), center(dots[k - 1]), center(dots[k]), strokeWidth = cell * 0.055f, cap = StrokeCap.Round)
            }
            val f = finger
            val last = dots.lastOrNull()
            if (f != null && last != null) drawLine(color.copy(alpha = 0.45f), center(last), f, strokeWidth = cell * 0.045f, cap = StrokeCap.Round)
            for (i in 0 until 9) {
                val on = i in dots
                drawCircle(if (on) color.copy(alpha = 0.16f) else Qs.surface, radius = cell * 0.30f, center = center(i))
                drawCircle(if (on) color else Qs.muted, radius = if (on) cell * 0.10f else cell * 0.065f, center = center(i))
            }
        }
    }
}

@Composable
private fun LockHeader(title: String, subtitle: String, error: Boolean, top: Dp = 72.dp) {
    Gap(top)
    Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(92.dp))
    Gap(24.dp)
    Text(title, style = T.display, textAlign = TextAlign.Center)
    Gap(6.dp)
    Text(subtitle, style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = if (error) Qs.coral else Qs.muted), textAlign = TextAlign.Center)
}

@Composable
private fun PinLayout(title: String, subtitle: String, pin: String, error: Boolean, busy: Boolean, padEnabled: Boolean, footer: @Composable () -> Unit, onDigit: (Char) -> Unit, onBackspace: () -> Unit, onBiometric: () -> Unit, showBiometric: Boolean = false) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LockHeader(title, subtitle, error)
        Gap(34.dp)
        Box(Modifier.height(24.dp), contentAlignment = Alignment.Center) {
            if (busy) CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp)) else PinDots(pin.length, error)
        }
        Gap(36.dp)
        PinPad(enabled = padEnabled && !busy, showBiometric = showBiometric, onDigit = onDigit, onBackspace = onBackspace, onBiometric = onBiometric)
        Gap(28.dp)
        footer()
        Gap(24.dp)
    }
}

@Composable
private fun PatternLayout(title: String, subtitle: String, error: Boolean, busy: Boolean, enabled: Boolean, clearKey: Int, footer: @Composable () -> Unit, onPattern: (String) -> Unit, showBiometric: Boolean = false, onBiometric: () -> Unit = {}) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LockHeader(title, subtitle, error, top = 56.dp)
        Gap(28.dp)
        Box(contentAlignment = Alignment.Center) {
            PatternPad(enabled = enabled && !busy, error = error, clearKey = clearKey, onDone = onPattern)
            if (busy) CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(26.dp))
        }
        Gap(20.dp)
        if (showBiometric) {
            IconBtn(R.drawable.ic_finger, "بصمة الهاتف", tint = Qs.brass, border = Qs.brass, enabled = enabled, onClick = onBiometric)
            Gap(16.dp)
        }
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
        title = if (first == null) "رمز QsCrypt" else "تأكيد الرمز",
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
                        val ok = withContext(Dispatchers.Default) { Prefs.setSecret(SECRET_PIN, pin) }
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

/** Create the app pattern (drawn twice). */
@Composable
fun PatternSetupScreen(onDone: () -> Unit, onCancel: (() -> Unit)? = null) {
    var first by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var clearKey by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    PatternLayout(
        title = if (first == null) "نمط QsCrypt" else "تأكيد النمط",
        subtitle = error ?: if (first == null) "صِل $PATTERN_MIN نقاط على الأقل دون رفع إصبعك" else "ارسم النمط نفسه مرة أخرى",
        error = error != null,
        busy = busy,
        enabled = true,
        clearKey = clearKey,
        footer = {
            Text(
                "رقّم النقاط كلوحة الأرقام: 1 2 3 في الأعلى، 7 8 9 في الأسفل. في وضع التمويه تكتب أرقام نقاطك ثم «=».",
                style = T.small,
                textAlign = TextAlign.Center,
            )
            if (onCancel != null) {
                Gap(10.dp)
                Text("إلغاء", style = T.label.copy(color = Qs.muted), modifier = Modifier.clickable(onClick = onCancel).padding(8.dp))
            }
        },
        onPattern = { p ->
            when {
                p.length < PATTERN_MIN -> {
                    error = "النمط قصير: صِل $PATTERN_MIN نقاط على الأقل"
                    scope.launch { delay(900); clearKey++ }
                }
                first == null -> {
                    first = p
                    error = null
                    scope.launch { delay(350); clearKey++ }
                }
                first == p -> {
                    busy = true
                    scope.launch {
                        val ok = withContext(Dispatchers.Default) { Prefs.setSecret(SECRET_PATTERN, p) }
                        busy = false
                        if (ok) onDone() else {
                            error = "تعذّر الحفظ"
                            first = null
                            clearKey++
                        }
                    }
                }
                else -> {
                    error = "النمطان مختلفان. ابدأ من جديد"
                    first = null
                    scope.launch { delay(900); clearKey++ }
                }
            }
        },
    )
}

/** First launch: how the app is locked (PIN, pattern, or the phone's lock alone), then set it up. */
@Composable
fun LockSetupScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    val phone = remember { PhoneAuth.available(context) }
    var kind by remember { mutableIntStateOf(-1) }
    var error by remember { mutableStateOf<String?>(null) }
    when (kind) {
        SECRET_PIN -> {
            PinSetupScreen(onDone = onDone)
            return
        }
        SECRET_PATTERN -> {
            PatternSetupScreen(onDone = onDone, onCancel = { kind = -1 })
            return
        }
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Gap(56.dp)
        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(88.dp))
        Gap(20.dp)
        Text("أهلاً بك في QsCrypt", style = T.display, textAlign = TextAlign.Center)
        Gap(6.dp)
        Text("كيف تريد قفل التطبيق؟", style = T.body.copy(fontSize = 15.sp, color = Qs.muted), textAlign = TextAlign.Center)
        Gap(24.dp)
        for ((k, title, sub) in listOf(
            Triple(SECRET_PIN, "رمز من 6 أرقام", "الأكثر شيوعاً، ويعمل مع وضع التمويه"),
            Triple(SECRET_PATTERN, "نمط", "ارسم خطاً يصل بين النقاط"),
            Triple(SECRET_NONE, "البصمة أو الوجه فقط", if (phone) "بلا رمز داخلي: قفل الهاتف وحده يفتح التطبيق" else "يتطلب قفل شاشة على الهاتف"),
        )) {
            QsCard(Modifier.fillMaxWidth().padding(vertical = 5.dp), onClick = {
                error = null
                if (k == SECRET_NONE) {
                    if (!phone || activity == null) {
                        error = "فعّل قفل الشاشة أو البصمة في إعدادات الهاتف أولاً."
                    } else {
                        PhoneAuth.prompt(activity, "QsCrypt", "تأكيد الفتح بقفل الهاتف") { ok, msg ->
                            if (ok) {
                                Prefs.clearSecret()
                                Prefs.lockMode = PhoneAuth.Mode.PhoneOnly.id
                                onDone()
                            } else {
                                error = msg ?: "لم يتم التأكيد"
                            }
                        }
                    }
                } else {
                    kind = k
                }
            }) {
                Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Tile(
                        when (k) {
                            SECRET_PIN -> R.drawable.ic_key
                            SECRET_PATTERN -> R.drawable.ic_sliders
                            else -> R.drawable.ic_finger
                        },
                        if (k == SECRET_NONE && !phone) Qs.muted else Qs.brass,
                        size = 42.dp, radius = 14.dp, iconSize = 21.dp,
                    )
                    androidx.compose.foundation.layout.Spacer(Modifier.size(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(title, style = T.item)
                        Text(sub, style = T.small)
                    }
                    QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
                }
            }
        }
        error?.let {
            Gap(10.dp)
            Text(it, style = T.small.copy(color = Qs.coral), textAlign = TextAlign.Center)
        }
        Gap(14.dp)
        Text("يمكنك تغيير ذلك لاحقاً من الإعدادات. الرمز أو النمط لا يغني عن كلمة مرور كل حاوية.", style = T.small, textAlign = TextAlign.Center)
        Gap(24.dp)
    }
}

/** Unlocks the app. Repeated failures lock entry out for growing periods. */
@Composable
fun LockScreen(onReset: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    val mode = remember { PhoneAuth.mode(context) }
    val kind = remember { Prefs.secretKind }
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var recovery by remember { mutableStateOf(false) }
    var clearKey by remember { mutableIntStateOf(0) }
    var short by remember { mutableStateOf(false) }
    // Two-factor: the PIN was right, the phone's lock is next.
    var secondStep by remember { mutableStateOf(AppState.pinPassed && mode == PhoneAuth.Mode.TwoFactor) }
    var phoneError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val lockedFor = (Prefs.lockUntil - now).coerceAtLeast(0)

    fun askPhone() {
        val a = activity ?: return
        phoneError = null
        PhoneAuth.prompt(a, "QsCrypt", if (secondStep) "الخطوة الثانية: قفل الهاتف" else "افتح بقفل الهاتف") { ok, msg ->
            if (ok) noteUnlocked() else phoneError = msg ?: "لم يتم التأكيد"
        }
    }

    fun check(attempt: String) {
        busy = true
        scope.launch {
            val ok = withContext(Dispatchers.Default) { Prefs.checkPin(attempt) }
            busy = false
            pin = ""
            if (ok) {
                if (mode == PhoneAuth.Mode.TwoFactor) {
                    Prefs.failCount = 0
                    secondStep = true
                } else {
                    noteUnlocked()
                }
            } else {
                noteFailure("app")
                now = System.currentTimeMillis()
                error = true
                if (kind == SECRET_PATTERN) {
                    delay(900)
                    clearKey++
                }
            }
        }
    }

    LaunchedEffect(lockedFor > 0) {
        while (Prefs.lockUntil > System.currentTimeMillis()) {
            now = System.currentTimeMillis()
            delay(500)
        }
        now = System.currentTimeMillis()
    }
    LaunchedEffect(Unit) {
        if ((mode == PhoneAuth.Mode.Either || mode == PhoneAuth.Mode.PhoneOnly) && Prefs.lockUntil <= System.currentTimeMillis() && PhoneAuth.available(context)) askPhone()
    }

    if (mode == PhoneAuth.Mode.PhoneOnly) {
        val phone = remember { PhoneAuth.available(context) }
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Gap(96.dp)
            Box(Modifier.size(112.dp).clip(CircleShape).background(Qs.surface).border(1.dp, Qs.brass, CircleShape), contentAlignment = Alignment.Center) {
                QsIcon(R.drawable.ic_finger, Qs.brass, 52.dp)
            }
            Gap(26.dp)
            Text("أهلاً من جديد", style = T.display, textAlign = TextAlign.Center)
            Gap(8.dp)
            Text(
                if (phone) "افتح QsCrypt ببصمتك أو وجهك أو قفل الهاتف." else "قفل شاشة الهاتف لم يعد مفعّلاً، فلا شيء يحمي QsCrypt الآن. أنشئ رمزاً أو نمطاً، أو فعّل قفل الهاتف من جديد.",
                style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = Qs.muted),
                textAlign = TextAlign.Center,
            )
            if (phoneError != null) {
                Gap(12.dp)
                Text(phoneError ?: "", style = T.small.copy(color = Qs.coral), textAlign = TextAlign.Center)
            }
            Gap(32.dp)
            if (phone) {
                PrimaryButton("افتح بقفل الهاتف", icon = R.drawable.ic_finger) { askPhone() }
            } else {
                PrimaryButton("أنشئ قفلاً للتطبيق", icon = R.drawable.ic_key) {
                    Prefs.secretKind = -1
                    Prefs.lockMode = -1
                    AppState.locked = false
                    onReset()
                }
            }
        }
        return
    }

    if (secondStep) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Gap(96.dp)
            Box(Modifier.size(112.dp).clip(CircleShape).background(Qs.surface).border(1.dp, Qs.brass, CircleShape), contentAlignment = Alignment.Center) {
                QsIcon(R.drawable.ic_finger, Qs.brass, 52.dp)
            }
            Gap(26.dp)
            Text("الخطوة الثانية", style = T.display, textAlign = TextAlign.Center)
            Gap(8.dp)
            Text(
                "${secretWord()} صحيح. أكّد هويتك ببصمة الهاتف أو وجهك أو رمز قفل الهاتف.",
                style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = Qs.muted),
                textAlign = TextAlign.Center,
            )
            if (phoneError != null) {
                Gap(12.dp)
                Text(phoneError ?: "", style = T.small.copy(color = Qs.coral), textAlign = TextAlign.Center)
            }
            Gap(32.dp)
            PrimaryButton("تأكيد بقفل الهاتف", icon = R.drawable.ic_finger) { askPhone() }
            Gap(12.dp)
            SecondaryButton("رجوع") {
                secondStep = false
                phoneError = null
                AppState.pinPassed = false
            }
        }
        LaunchedEffect(Unit) { askPhone() }
        return
    }

    val word = if (kind == SECRET_PATTERN) "نمط" else "رمز"
    val subtitle = when {
        lockedFor > 0 -> "محاولات كثيرة خاطئة. انتظر ${(lockedFor + 999) / 1000} ثانية"
        short -> "النمط قصير: صِل $PATTERN_MIN نقاط على الأقل"
        error -> "$word خاطئ. بقيت ${(5 - Prefs.failCount).coerceAtLeast(0)} محاولات قبل الانتظار"
        mode == PhoneAuth.Mode.TwoFactor -> "الخطوة الأولى: $word QsCrypt، ثم قفل الهاتف"
        mode == PhoneAuth.Mode.Either -> "افتح بقفل الهاتف أو بال$word"
        kind == SECRET_PATTERN -> "ارسم نمط QsCrypt"
        else -> "افتح QsCrypt بالرمز السري"
    }
    val footer: @Composable () -> Unit = {
        Text("نسيت $word؟", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable { recovery = true }.padding(8.dp))
    }
    if (kind == SECRET_PATTERN) {
        PatternLayout(
            title = "أهلاً من جديد",
            subtitle = subtitle,
            error = error || lockedFor > 0 || short,
            busy = busy,
            enabled = lockedFor == 0L,
            clearKey = clearKey,
            footer = footer,
            showBiometric = mode == PhoneAuth.Mode.Either,
            onBiometric = { askPhone() },
            onPattern = { p ->
                if (p.length < PATTERN_MIN) {
                    short = true
                    scope.launch {
                        delay(900)
                        short = false
                        clearKey++
                    }
                } else {
                    error = false
                    check(p)
                }
            },
        )
    } else {
        PinLayout(
            title = "أهلاً من جديد",
            subtitle = subtitle,
            pin = pin,
            error = error || lockedFor > 0,
            busy = busy,
            padEnabled = lockedFor == 0L,
            showBiometric = mode == PhoneAuth.Mode.Either,
            footer = footer,
            onDigit = { d ->
                if (pin.length >= PIN_LENGTH || busy) return@PinLayout
                error = false
                pin += d
                if (pin.length == PIN_LENGTH) check(pin)
            },
            onBackspace = { if (pin.isNotEmpty()) pin = pin.dropLast(1) },
            onBiometric = { askPhone() },
        )
    }
    if (recovery) {
        QsAlert(
            title = "نسيت $word؟",
            text = if (mode == PhoneAuth.Mode.Either) {
                "يمكنك الدخول بقفل الهاتف، ثم تغيير $word من الإعدادات."
            } else {
                "امسح بيانات التطبيق من إعدادات أندرويد: تُحذف قائمة الخزنات و$word وجهات الاتصال فقط، وتبقى حاوياتك وملفاتك المشفّرة سليمة وتفتحها بكلمات مرورها أو بمفاتيح الاسترداد."
            },
            confirm = "حسناً",
            dismiss = null,
            onConfirm = { recovery = false },
            onDismiss = { recovery = false },
        )
    }
}

/** After the PIN or pattern is created: offer the phone's lock as a second factor. */
@Composable
fun TwoFactorSetupScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    var choice by remember { mutableStateOf(PhoneAuth.Mode.TwoFactor) }
    var error by remember { mutableStateOf<String?>(null) }
    val word = secretWord()
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Gap(64.dp)
        Box(Modifier.size(96.dp).clip(CircleShape).background(Qs.surface).border(1.dp, Qs.brass, CircleShape), contentAlignment = Alignment.Center) {
            QsIcon(R.drawable.ic_finger, Qs.brass, 44.dp)
        }
        Gap(22.dp)
        Text("المصادقة الثنائية", style = T.display, textAlign = TextAlign.Center)
        Gap(8.dp)
        Text(
            "اربط قفل QsCrypt بقفل هاتفك: بصمة أو وجه، ورمز قفل الهاتف احتياطاً. لا يغادر شيء من ذلك الهاتف، وQsCrypt لا يرى بصمتك.",
            style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = Qs.muted),
            textAlign = TextAlign.Center,
        )
        Gap(26.dp)
        for ((m, title, sub) in listOf(
            Triple(PhoneAuth.Mode.TwoFactor, "$word + قفل الهاتف", "الأقوى: يلزم الاثنان معاً (موصى به)"),
            Triple(PhoneAuth.Mode.Either, "قفل الهاتف أو $word", "الأسرع: أيّهما يكفي"),
            Triple(PhoneAuth.Mode.Pin, "$word فقط", "بدون قفل الهاتف"),
        )) {
            QsCard(Modifier.fillMaxWidth().padding(vertical = 5.dp), glow = choice == m, onClick = { choice = m }) {
                Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(title, style = T.item)
                        Text(sub, style = T.small)
                    }
                    Box(Modifier.size(22.dp).clip(CircleShape).border(2.dp, if (choice == m) Qs.brass else Qs.muted, CircleShape), contentAlignment = Alignment.Center) {
                        if (choice == m) Box(Modifier.size(11.dp).clip(CircleShape).background(Qs.brass))
                    }
                }
            }
        }
        if (error != null) {
            Gap(10.dp)
            Text(error ?: "", style = T.small.copy(color = Qs.coral), textAlign = TextAlign.Center)
        }
        Gap(22.dp)
        PrimaryButton("متابعة") {
            if (choice == PhoneAuth.Mode.Pin || activity == null) {
                Prefs.lockMode = PhoneAuth.Mode.Pin.id
                onDone()
            } else {
                // Confirm once now, so the user knows it works.
                PhoneAuth.prompt(activity, "QsCrypt", "تأكيد ربط قفل الهاتف") { ok, msg ->
                    if (ok) {
                        Prefs.lockMode = choice.id
                        onDone()
                    } else {
                        error = msg ?: "لم يتم التأكيد"
                    }
                }
            }
        }
        Gap(24.dp)
    }
}

/**
 * Confirms the current app lock before changing it: the PIN, the pattern,
 * or the phone's lock when there is no internal secret.
 */
@Composable
fun VerifyLockDialog(onVerified: () -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val kind = remember { Prefs.secretKind }
    var pin by remember { mutableStateOf("") }
    var wrong by remember { mutableStateOf(false) }
    var clearKey by remember { mutableIntStateOf(0) }
    if (kind == SECRET_NONE || !Prefs.hasPin()) {
        LaunchedEffect(Unit) {
            val a = context as? FragmentActivity
            if (a == null) onDismiss() else PhoneAuth.prompt(a, "QsCrypt", "تأكيد هويتك") { ok, _ -> if (ok) onVerified() else onDismiss() }
        }
        return
    }
    fun attempt(s: String) {
        scope.launch {
            val ok = withContext(Dispatchers.Default) { Prefs.checkPin(s) }
            if (ok) onVerified() else {
                wrong = true
                Prefs.logAttempt("app")
                delay(800)
                clearKey++
            }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Qs.surface,
        title = { Text(if (kind == SECRET_PATTERN) "النمط الحالي" else "الرمز الحالي", style = T.title) },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                if (kind == SECRET_PATTERN) {
                    PatternPad(enabled = true, error = wrong, clearKey = clearKey, size = 220.dp) { p ->
                        wrong = false
                        if (p.length >= PATTERN_MIN) attempt(p) else clearKey++
                    }
                } else {
                    QsField(
                        value = pin,
                        onValueChange = { v ->
                            pin = v.filter { it.isDigit() }.take(PIN_LENGTH)
                            wrong = false
                        },
                        placeholder = "••••••", password = true, highlighted = true, keyboardType = KeyboardType.NumberPassword,
                    )
                }
                if (wrong) {
                    Gap(8.dp)
                    Text(if (kind == SECRET_PATTERN) "نمط خاطئ" else "رمز خاطئ", style = T.small.copy(color = Qs.coral))
                }
            }
        },
        confirmButton = {
            if (kind != SECRET_PATTERN) {
                TextButton(onClick = { attempt(pin) }, enabled = pin.length == PIN_LENGTH) { Text("متابعة", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
    )
}
