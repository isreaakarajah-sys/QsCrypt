package com.qscrypt.app.ui

import android.content.Context
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Container
import com.qscrypt.app.Progress
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.Session
import com.qscrypt.app.VolumeInfo
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicBoolean

// ------------------------------------------------------------------ shared

/** 0 (weak) .. 4 (strong), a rough entropy estimate. */
fun passwordScore(p: String): Int {
    if (p.isEmpty()) return 0
    var classes = 0
    if (p.any { it.isLowerCase() }) classes++
    if (p.any { it.isUpperCase() }) classes++
    if (p.any { it.isDigit() }) classes++
    if (p.any { !it.isLetterOrDigit() }) classes++
    if (p.any { it.code > 0x7F && it.isLetter() }) classes++
    val bits = p.length * (when (classes) { 1 -> 3.5; 2 -> 4.7; 3 -> 5.4; else -> 6.0 })
    return when {
        bits < 40 -> 1
        bits < 60 -> 2
        bits < 80 -> 3
        else -> 4
    }
}

@Composable
fun PasswordPair(password: String, confirm: String, onPassword: (String) -> Unit, onConfirm: (String) -> Unit) {
    Text("كلمة المرور", style = T.label)
    Gap(8.dp)
    QsField(value = password, onValueChange = onPassword, placeholder = "اختر كلمة مرور قوية", password = true, highlighted = true)
    Gap(8.dp)
    val score = passwordScore(password)
    val (label, color) = when (score) {
        0 -> "" to Qs.line
        1 -> "ضعيفة" to Qs.coral
        2 -> "متوسطة" to Qs.brass
        3 -> "جيدة" to Qs.mint
        else -> "قوية جداً" to Qs.mint
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(4) { i -> Box(Modifier.weight(1f).height(4.dp).clip(RoundedCornerShape(2.dp)).background(if (i < score) color else Qs.surface2)) }
        }
        Spacer(Modifier.width(10.dp))
        Text(label, style = T.small.copy(color = color), modifier = Modifier.width(64.dp))
    }
    if (password.isNotEmpty() && password.length < 12) {
        Gap(4.dp)
        Text("ننصح بـ 12 حرفاً على الأقل، أو عبارة من عدة كلمات.", style = T.small)
    }
    Gap(14.dp)
    Text("تأكيد كلمة المرور", style = T.label)
    Gap(8.dp)
    QsField(value = confirm, onValueChange = onConfirm, placeholder = "أعد كتابتها", password = true)
    if (confirm.isNotEmpty() && confirm != password) {
        Gap(6.dp)
        Text("كلمتا المرور غير متطابقتين", style = T.small.copy(color = Qs.coral))
    }
    Gap(10.dp)
    Note("لا توجد أي طريقة لاسترجاع البيانات إن نسيت كلمة المرور. احفظها في مكان آمن.", icon = R.drawable.ic_alert, color = Qs.coral)
}

@Composable
private fun Choice(selected: Boolean, enabled: Boolean = true, onClick: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(20.dp)
    Column(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(if (selected) Qs.surface else Color.Transparent)
            .border(if (selected) 1.5.dp else 1.dp, if (selected) Qs.brass else Qs.line, shape)
            .clickable(enabled = enabled, onClick = onClick)
            .alpha(if (enabled) 1f else 0.55f)
            .padding(14.dp),
        content = content,
    )
}

@Composable
private fun Radio(selected: Boolean) {
    Box(
        Modifier.size(22.dp).clip(CircleShape).border(2.dp, if (selected) Qs.brass else Qs.line, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        if (selected) Box(Modifier.size(10.dp).clip(CircleShape).background(Qs.brass))
    }
}

@Composable
private fun FormatOption(name: String, desc: String, selected: Boolean, enabled: Boolean = true, badge: @Composable () -> Unit = {}, onClick: () -> Unit) {
    Choice(selected = selected, enabled = enabled, onClick = onClick) {
        Row(verticalAlignment = Alignment.Top) {
            Box(Modifier.padding(top = 1.dp)) { Radio(selected) }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(name, style = T.item.copy(fontSize = 16.sp, lineHeight = 22.sp))
                    Spacer(Modifier.width(8.dp))
                    badge()
                }
                Text(desc, style = T.body.copy(fontSize = 13.sp, lineHeight = 20.sp, color = Qs.muted))
            }
        }
    }
}

@Composable
private fun TargetCard(modifier: Modifier, icon: Int, title: String, sub: String, selected: Boolean, soon: Boolean = false, onClick: () -> Unit) {
    val shape = RoundedCornerShape(20.dp)
    Column(
        modifier
            .clip(shape)
            .background(if (selected) Qs.surface else Color.Transparent)
            .border(if (selected) 1.5.dp else 1.dp, if (selected) Qs.brass else Qs.line, shape)
            .clickable(onClick = onClick)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            QsIcon(icon, if (selected) Qs.brass else Qs.muted, 24.dp)
            Spacer(Modifier.weight(1f))
            if (soon) ComingSoonTag()
        }
        Text(title, style = T.item, maxLines = 1)
        Text(sub, style = T.small, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

// ------------------------------------------------------------------ step 1

@Composable
fun NewEncryptionScreen() {
    var target by remember { mutableIntStateOf(0) } // 0 container, 1 files, 2 disk
    var format by remember { mutableStateOf("VeraCrypt") }
    var soon by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Gap(20.dp)
            TopBar("تشفير جديد", onBack = { AppState.pop() }) { Text("1/3", style = T.mono.copy(fontSize = 12.sp)) }
            Gap(10.dp)
            StepBar(1, 3)
            Gap(22.dp)
            Text("ماذا تريد أن تشفّر؟", style = T.h1)
            Gap(14.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                TargetCard(Modifier.weight(1f), R.drawable.ic_file, "حاوية جديدة", "ملف مشفّر تضع فيه ملفاتك", target == 0) {
                    target = 0
                    format = "VeraCrypt"
                }
                TargetCard(Modifier.weight(1f), R.drawable.ic_doc, "ملفات", "شفّر ملفات بعينها لترسلها", target == 1) {
                    target = 1
                    format = "QsCrypt"
                }
                TargetCard(Modifier.weight(1f), R.drawable.ic_usb, "قرص كامل", "فلاشة أو هارد خارجي", target == 2, soon = true) {
                    soon = "تشفير فلاشة أو هارد بالكامل قادم في الإصدار التالي. يمكنك الآن إنشاء حاوية على الفلاشة نفسها: اختر «حاوية جديدة» واحفظها هناك."
                }
            }
            Gap(22.dp)
            Text("الصيغة", style = T.label)
            Gap(10.dp)
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (target == 0) {
                    FormatOption("VeraCrypt", "يُفتح على أي حاسوب ببرنامج VeraCrypt، وعلى هذا التطبيق.", format == "VeraCrypt", badge = { Tag("موصى به", TagKind.Brass) }) { format = "VeraCrypt" }
                    FormatOption("QsCrypt", "الأقوى: ثلاث طبقات تشفير ومزايا حماية متقدمة. حاويات QsCrypt قادمة، ويمكنك الآن تشفير ملفاتك بها من «ملفات».", false, enabled = false, badge = { ComingSoonTag() }) {}
                    FormatOption("BitLocker", "يُفتح مباشرة على Windows دون أي برنامج.", false, enabled = false, badge = { ComingSoonTag() }) {}
                    FormatOption("TrueCrypt", "للتوافق مع الأنظمة القديمة فقط. اشتقاق مفتاحه أضعف بكثير.", format == "TrueCrypt", badge = { Tag("حماية أضعف", TagKind.Coral) }) { format = "TrueCrypt" }
                } else {
                    FormatOption("QsCrypt", "AES ثم Twofish ثم XChaCha20-Poly1305 مع Argon2id. يُفتح بتطبيق QsCrypt فقط، ويكشف أي تعديل على الملف.", true, badge = { Tag("موصى به", TagKind.Brass) }) {}
                    Note("تريد أن يفتحها شخص على حاسوبه دون QsCrypt؟ أنشئ «حاوية جديدة» بصيغة VeraCrypt وضع الملفات داخلها.", icon = R.drawable.ic_info)
                }
            }
            Gap(20.dp)
        }
        PrimaryButton("التالي") {
            when {
                target == 1 -> AppState.push(Screen.QscEncrypt)
                format == "TrueCrypt" -> AppState.push(Screen.NewContainer(truecrypt = true))
                else -> AppState.push(Screen.NewContainer(truecrypt = false))
            }
        }
        Gap(24.dp)
    }
    soon?.let { s -> QsAlert("قريباً", s, "حسناً", { soon = null }, { soon = null }, dismiss = null) }
}

// ------------------------------------------------------------------ containers

private val SIZES = listOf(100L to "100 MB", 500L to "500 MB", 1024L to "1 GB", 4096L to "4 GB")
private val VC_PRFS = listOf(1 to "SHA-512", 2 to "SHA-256", 3 to "Whirlpool")
private val TC_PRFS = listOf(1 to "SHA-512", 4 to "RIPEMD-160", 3 to "Whirlpool")
private val EAS = listOf(1 to "AES", 2 to "Serpent", 3 to "Twofish", 4 to "AES-Twofish", 5 to "AES-Twofish-Serpent", 6 to "Serpent-AES", 7 to "Serpent-Twofish-AES", 8 to "Twofish-Serpent")

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun NewContainerScreen(truecrypt: Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("خزنتي") }
    var sizeMb by remember { mutableStateOf(500L) }
    var custom by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var ea by remember { mutableIntStateOf(1) }
    var prf by remember { mutableIntStateOf(1) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    val selfTest = AppState.selfTest
    val formatName = if (truecrypt) "TrueCrypt" else "VeraCrypt"
    val extension = if (truecrypt) ".tc" else ".hc"
    val bytes = (custom.toLongOrNull() ?: sizeMb) * 1024 * 1024
    val valid = name.isNotBlank() && password.isNotEmpty() && password == confirm && bytes >= 2L * 1024 * 1024

    val creator = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        val pw = password.toByteArray(Charsets.UTF_8)
        val pimValue = if (truecrypt) 0 else pim.toIntOrNull() ?: 0
        busy = Busy("إنشاء الحاوية", 0f, "تُكتب الحاوية كاملة مشفّرة، وقد يستغرق ذلك دقائق للأحجام الكبيرة.")
        scope.launch {
            val created = withContext(Dispatchers.IO) {
                val pfd = Saf.open(context, uri, "rw") ?: return@withContext Reply("{\"ok\":false,\"code\":\"io\",\"message\":\"open\"}")
                pfd.use {
                    Reply(QsCore.createVolume(it.fd, bytes, pw, pimValue, prf, ea, if (truecrypt) 2 else 1, name, Progress { d, t ->
                        busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null)
                        !cancel.get()
                    }))
                }
            }
            if (!created.ok) {
                pw.fill(0)
                busy = null
                Saf.delete(context, uri)
                message = if (created.code == "cancelled") null else "تعذّر إنشاء الحاوية: ${created.error}\nتأكد من وجود مساحة كافية واختر موقعاً على الجهاز أو الفلاشة."
                return@launch
            }
            Saf.persist(context, uri)
            val meta = Saf.meta(context, uri)
            val container = AppState.addContainer(Container(uri.toString(), meta.name, bytes, System.currentTimeMillis(), formatName, created.json.optString("ea"), ""))
            busy = Busy("فتح الحاوية", null)
            val tz = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000
            val opened = withContext(Dispatchers.IO) {
                Saf.open(context, uri, "rw")?.use { Reply(QsCore.openVolume(it.fd, pw, pimValue, prf, if (truecrypt) 2 else 1, false, tz)) }
            }
            pw.fill(0)
            busy = null
            password = ""
            confirm = ""
            if (opened != null && opened.ok) {
                val info = VolumeInfo.from(opened.json)
                val c = container.copy(fs = info.fs)
                AppState.updateContainer(c)
                AppState.sessions.add(Session(info.handle, c, info, System.currentTimeMillis()))
                AppState.stack.clear()
                AppState.stack.add(Screen.Home)
                AppState.stack.add(Screen.Vault(info.handle))
            } else {
                AppState.stack.clear()
                AppState.stack.add(Screen.Home)
                AppState.stack.add(Screen.Unlock(container))
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Gap(20.dp)
            TopBar("حاوية $formatName جديدة", onBack = { AppState.pop() }) { Text("2/3", style = T.mono.copy(fontSize = 12.sp)) }
            Gap(10.dp)
            StepBar(2, 3)
            Gap(20.dp)
            Text("اسم الحاوية", style = T.label)
            Gap(8.dp)
            QsField(value = name, onValueChange = { name = it.take(60) }, placeholder = "خزنتي")
            Gap(18.dp)
            Text("الحجم", style = T.label)
            Gap(8.dp)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SIZES.forEach { (mb, label) ->
                    Chip(label, custom.isEmpty() && sizeMb == mb) {
                        sizeMb = mb
                        custom = ""
                    }
                }
            }
            Gap(10.dp)
            QsField(
                value = custom,
                onValueChange = { v -> custom = v.filter { it.isDigit() }.take(7) },
                placeholder = "حجم مخصص بالميغابايت",
                keyboardType = KeyboardType.Number,
                height = 48.dp,
                trailing = { Text("MB", style = T.mono, modifier = Modifier.padding(end = 12.dp)) },
            )
            Gap(6.dp)
            Text("نظام الملفات: FAT (أقصى حجم للملف الواحد 4GB). exFAT قادم.", style = T.small)
            Gap(20.dp)
            PasswordPair(password, confirm, { password = it }, { confirm = it })
            Gap(20.dp)
            Text("الخوارزمية", style = T.label)
            Gap(8.dp)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                EAS.forEach { (id, label) ->
                    // Only offer algorithms that passed VeraCrypt's own known-answer test on this device.
                    val ok = id == 1 || selfTest?.passed(label) == true
                    if (ok) Chip(label, ea == id) { ea = id }
                }
            }
            Gap(16.dp)
            Text("اشتقاق المفتاح (PRF)", style = T.label)
            Gap(8.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                (if (truecrypt) TC_PRFS else VC_PRFS).forEach { (id, label) -> Chip(label, prf == id) { prf = id } }
            }
            if (!truecrypt) {
                Gap(16.dp)
                OptionRow(R.drawable.ic_key, "PIM (اختياري)", "رقم يزيد قوة الاشتقاق، ويجب إدخاله عند كل فتح") {
                    QsField(
                        value = pim,
                        onValueChange = { v -> pim = v.filter { it.isDigit() }.take(5) },
                        placeholder = "—",
                        keyboardType = KeyboardType.NumberPassword,
                        height = 40.dp,
                        modifier = Modifier.width(92.dp),
                        textStyle = T.monoLarge,
                    )
                }
            } else {
                Gap(12.dp)
                Note("TrueCrypt يستخدم 1000 دورة اشتقاق فقط، فكلمة المرور أسهل تخميناً بكثير من VeraCrypt. استخدمه للتوافق فقط.", icon = R.drawable.ic_alert, color = Qs.coral)
            }
            Gap(20.dp)
        }
        PrimaryButton("إنشاء الحاوية (${humanSize(bytes)})", icon = R.drawable.ic_lock, enabled = valid) {
            AppState.pickerOpen = true
            val file = name.trim().let { if (it.endsWith(extension, ignoreCase = true)) it else it + extension }
            creator.launch(file)
        }
        Gap(24.dp)
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = if (b.fraction != null) ({ cancel.set(true) }) else null) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}

// ------------------------------------------------------------------ QsCrypt files

private data class Picked(val uri: Uri, val name: String, val size: Long)

private data class Policy(val icon: Int, val title: String, val desc: String, val risk: String, val destroys: Boolean)

private val POLICIES = listOf(
    Policy(R.drawable.ic_wifioff, "بلا إنترنت فقط", "تُتلف إذا فُتحت والجهاز متصل بالشبكة", "إن فتحها المستلم وجواله متصل بالإنترنت، تُتلف المفاتيح فوراً ولا يمكن استرجاع الملف أبداً، حتى لو كان الاتصال غير مقصود.", true),
    Policy(R.drawable.ic_eye, "فتح لمرة واحدة", "يُتلف المفتاح نهائياً بعد أول فتح", "بعد أول فتح ناجح يُتلف مفتاح الفك المخزّن في عتاد جهاز المستلم، فلا يمكن فتح الملف مرة ثانية على أي جهاز.", true),
    Policy(R.drawable.ic_clock, "مدة الصلاحية", "تُحسب من وقت الإصدار، والتلاعب بالوقت يُتلفها", "بعد انتهاء المدة، أو إن اكتُشف تغيير ساعة الجهاز للخلف، يُتلف المفتاح.", true),
    Policy(R.drawable.ic_key, "عدد المحاولات", "إتلاف بعد عدد محاولات خاطئة تحدده أنت", "يحمي من التخمين، لكن صاحب الحق قد يُتلف الملف بنفسه إن أخطأ كلمة المرور مرات كثيرة.", true),
    Policy(R.drawable.ic_shield, "كلمة مرور الطوارئ", "تفتح حاوية تمويه أو تُتلف المفاتيح بصمت", "إن أُجبرت على كشف كلمة المرور، تعطي كلمة الطوارئ فتنفتح بيانات تمويه أو تُتلف الحقيقية دون أي إشارة.", true),
    Policy(R.drawable.ic_unlock, "الفتح التلقائي", "بعد أول فتح ناجح على جهاز المستلم", "يريح المستلم، لكن من يمسك جواله مفتوحاً يستطيع فتح الملف دون كلمة مرور.", false),
)

@Composable
fun QscEncryptScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by remember { mutableIntStateOf(2) }
    val files = remember { mutableStateListOf<Picked>() }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var policy by remember { mutableStateOf<Policy?>(null) }
    val cancel = remember { AtomicBoolean(false) }

    BackHandler(enabled = step == 3) { step = 2 }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        for (u in uris) {
            if (files.none { it.uri == u }) {
                val m = Saf.meta(context, u)
                files.add(Picked(u, m.name, m.size))
            }
        }
    }

    val folder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        if (tree == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        val pw = password.toByteArray(Charsets.UTF_8)
        scope.launch {
            var done = 0
            var failure: String? = null
            for ((i, f) in files.withIndex()) {
                busy = Busy("تشفير (${i + 1}/${files.size})", 0f, f.name)
                val r = withContext(Dispatchers.IO) { encryptOne(context, tree, f, pw, cancel) { d, t -> busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null) } }
                if (!r.ok) {
                    failure = if (r.code == "cancelled") null else "«${f.name}»: ${r.error}"
                    break
                }
                done++
            }
            pw.fill(0)
            busy = null
            if (failure != null) {
                message = failure
            } else if (done > 0) {
                password = ""
                confirm = ""
                files.clear()
                message = "تم تشفير $done ${if (done == 1) "ملف" else "ملفات"} بصيغة QsCrypt.\nالملفات الأصلية لم تُحذف؛ احذفها بنفسك إن لم تعد تحتاجها."
                step = 2
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Gap(20.dp)
            TopBar(if (step == 2) "تشفير ملفات" else "مزايا الحماية", onBack = { if (step == 3) step = 2 else AppState.pop() }) {
                Text("$step/3", style = T.mono.copy(fontSize = 12.sp))
            }
            Gap(10.dp)
            StepBar(step, 3)
            Gap(18.dp)
            if (step == 2) {
                Text("الملفات", style = T.label)
                Gap(8.dp)
                files.forEach { f ->
                    Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                        Tile(R.drawable.ic_file, Qs.ivory, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(f.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(humanSize(f.size), style = T.mono)
                        }
                        IconBtn(R.drawable.ic_close, "إزالة", tint = Qs.muted) { files.remove(f) }
                    }
                }
                SecondaryButton(if (files.isEmpty()) "اختر الملفات" else "أضف ملفات أخرى", icon = R.drawable.ic_plus) {
                    AppState.pickerOpen = true
                    picker.launch(arrayOf("*/*"))
                }
                Gap(22.dp)
                PasswordPair(password, confirm, { password = it }, { confirm = it })
            } else {
                Text("كل المزايا مطفأة افتراضياً. فعّل ما تحتاجه فقط، وسيشرح لك التطبيق عواقب كل ميزة قبل تفعيلها.", style = T.body.copy(color = Qs.muted))
                Gap(18.dp)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("يفتحها فقط", style = T.label, modifier = Modifier.weight(1f))
                    ComingSoonTag()
                }
                Gap(8.dp)
                Text("ربط الملف بجهات اتصال محددة عبر رمز QR يأتي مع شاشة جهات الاتصال.", style = T.small)
                Gap(16.dp)
                Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(Qs.surface)) {
                    POLICIES.forEachIndexed { i, p ->
                        Row(
                            Modifier.fillMaxWidth().clickable { policy = p }.padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Tile(p.icon, Qs.muted, size = 40.dp, radius = 13.dp, iconSize = 20.dp)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(p.title, style = T.item)
                                    if (p.destroys) {
                                        Spacer(Modifier.width(8.dp))
                                        Tag("إتلاف", TagKind.Coral)
                                    }
                                }
                                Text(p.desc, style = T.small)
                            }
                            Spacer(Modifier.width(8.dp))
                            QsSwitch(false, enabled = false) {}
                        }
                        if (i < POLICIES.size - 1) Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))
                    }
                }
                Gap(12.dp)
                Note("هذه المزايا قيد البناء وستُفعَّل في الإصدارات القادمة. الملف الآن يُشفَّر بكلمة المرور وحدها.", icon = R.drawable.ic_info)
            }
            Gap(20.dp)
        }
        if (step == 2) {
            PrimaryButton("التالي", enabled = files.isNotEmpty() && password.isNotEmpty() && password == confirm) { step = 3 }
        } else {
            PrimaryButton("اختر مكان الحفظ وشفّر", icon = R.drawable.ic_lock) {
                AppState.pickerOpen = true
                folder.launch(null)
            }
        }
        Gap(24.dp)
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = { cancel.set(true) }) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
    policy?.let { p -> QsAlert(p.title, p.risk + "\n\nهذه الميزة قادمة في الإصدار التالي.", "فهمت", { policy = null }, { policy = null }, dismiss = null) }
}

private fun encryptOne(context: Context, tree: Uri, f: Picked, pw: ByteArray, cancel: AtomicBoolean, onProgress: (Long, Long) -> Unit): Reply {
    val out = Saf.createInTree(context, tree, f.name + ".qsc") ?: return Reply("{\"ok\":false,\"code\":\"io\",\"message\":\"create\"}")
    val input = Saf.open(context, f.uri, "r")
    val output = Saf.open(context, out, "w")
    if (input == null || output == null) {
        input?.close()
        output?.close()
        Saf.delete(context, out)
        return Reply("{\"ok\":false,\"code\":\"io\"}")
    }
    val r = input.use { i ->
        output.use { o ->
            Reply(QsCore.qscEncrypt(i.fd, f.size, o.fd, f.name, System.currentTimeMillis() / 1000, pw, Progress { d, t ->
                onProgress(d, t)
                !cancel.get()
            }))
        }
    }
    if (!r.ok) Saf.delete(context, out)
    return r
}

@Composable
fun QscDecryptScreen(uriString: String, name: String, size: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val uri = remember(uriString) { Uri.parse(uriString) }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    var original by remember { mutableStateOf<String?>(null) }

    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { out ->
        if (out == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        val pw = password.toByteArray(Charsets.UTF_8)
        busy = Busy("فك التشفير", 0f, original ?: name)
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                val input = Saf.open(context, uri, "r")
                val output = Saf.open(context, out, "w")
                if (input == null || output == null) {
                    input?.close()
                    output?.close()
                    Reply("{\"ok\":false,\"code\":\"io\"}")
                } else {
                    input.use { i -> output.use { o -> Reply(QsCore.qscDecrypt(i.fd, o.fd, pw, Progress { d, t -> busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null); !cancel.get() })) } }
                }
            }
            pw.fill(0)
            busy = null
            if (r.ok) {
                password = ""
                message = "تم فك التشفير وحفظ «${r.json.optString("name")}». النسخة المحفوظة غير مشفّرة."
            } else {
                Saf.delete(context, out)
                if (r.code != "cancelled") error = r.error
            }
        }
    }

    fun start() {
        if (password.isEmpty()) return
        error = null
        busy = Busy("التحقق من كلمة المرور", null)
        val pw = password.toByteArray(Charsets.UTF_8)
        scope.launch {
            val r = withContext(Dispatchers.IO) { Saf.open(context, uri, "r")?.use { Reply(QsCore.qscDecrypt(it.fd, -1, pw, null)) } }
            pw.fill(0)
            busy = null
            when {
                r == null -> error = "تعذّر فتح الملف."
                !r.ok -> error = if (r.code == "wrong_password") "كلمة المرور غير صحيحة، أو أن الملف معدّل." else r.error
                else -> {
                    val suggested = r.json.optString("name").ifBlank { name.removeSuffix(".qsc") }
                    original = suggested
                    AppState.pickerOpen = true
                    saver.launch(suggested)
                }
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Gap(20.dp)
            TopBar("فك ملف QsCrypt", onBack = { AppState.pop() })
            Gap(18.dp)
            QsCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_shield, Qs.brass, size = 50.dp, radius = 16.dp, iconSize = 24.dp)
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(name, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(Saf.location(uri), style = T.small, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text(humanSize(size), style = T.mono.copy(fontSize = 12.sp))
                }
            }
            Gap(12.dp)
            Note("ملف بصيغة QsCrypt: اسمه الأصلي ومحتواه مشفّران بثلاث طبقات. بعد التحقق من كلمة المرور ستختار أين تحفظ النسخة المفكوكة.")
            Gap(22.dp)
            Text("كلمة المرور", style = T.label)
            Gap(8.dp)
            QsField(value = password, onValueChange = { password = it; error = null }, placeholder = "••••••••••••", password = true, highlighted = true)
            if (error != null) {
                Gap(10.dp)
                Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
            }
            Gap(20.dp)
        }
        PrimaryButton("فك التشفير", icon = R.drawable.ic_unlock, enabled = password.isNotEmpty()) { start() }
        Gap(24.dp)
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = if (b.fraction != null) ({ cancel.set(true) }) else null) }
    message?.let { m ->
        QsAlert("QsCrypt", m, "حسناً", {
            message = null
            AppState.pop()
        }, { message = null }, dismiss = null)
    }
}
