package com.qscrypt.app.ui

import android.net.Uri
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
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
import com.qscrypt.app.Fill
import com.qscrypt.app.Call
import com.qscrypt.app.Container
import com.qscrypt.app.Identity
import com.qscrypt.app.Progress
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.Session
import com.qscrypt.app.UsbDrives
import com.qscrypt.app.UsbTarget
import com.qscrypt.app.VolumeInfo
import com.qscrypt.app.humanSize
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
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
internal fun Choice(selected: Boolean, enabled: Boolean = true, onClick: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
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
internal fun Radio(selected: Boolean) {
    Box(
        Modifier.size(22.dp).clip(CircleShape).border(2.dp, if (selected) Qs.brass else Qs.line, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        if (selected) Box(Modifier.size(10.dp).clip(CircleShape).background(Qs.brass))
    }
}

@Composable
internal fun FormatOption(name: String, desc: String, selected: Boolean, enabled: Boolean = true, badge: @Composable () -> Unit = {}, onClick: () -> Unit) {
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
internal fun TargetCard(modifier: Modifier, icon: Int, title: String, sub: String, selected: Boolean, onClick: () -> Unit) {
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
        QsIcon(icon, if (selected) Qs.brass else Qs.muted, 24.dp)
        Text(title, style = T.item, maxLines = 1)
        Text(sub, style = T.small, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

// ------------------------------------------------------------------ step 1

@Composable
fun NewEncryptionScreen() {
    var target by remember { mutableIntStateOf(0) }
    var format by remember { mutableStateOf("VeraCrypt") }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            TopBar("تشفير جديد", onBack = { AppState.pop() })
            Gap(10.dp)
            StepBar(1, 3)
            Gap(20.dp)
            Text("ماذا تريد أن تشفّر؟", style = T.h1)
            Gap(14.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                TargetCard(Modifier.weight(1f), R.drawable.ic_archive, "حاوية جديدة", "ملف مشفّر يعمل كقرص كامل", target == 0) { target = 0 }
                TargetCard(Modifier.weight(1f), R.drawable.ic_file, "ملفات", "تشفير ملفات بعينها بصيغة QsCrypt", target == 1) { target = 1 }
            }
            Gap(10.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                TargetCard(Modifier.weight(1f), R.drawable.ic_usb, "فلاشة أو هارد", "تشفير قرص USB كامل عبر OTG", target == 2) { target = 2 }
                TargetCard(Modifier.weight(1f), R.drawable.ic_image, "داخل صورة", "ملف مشفّر يبدو صورة عادية وتُفتح كصورة", target == 3) { target = 3 }
            }
            Gap(10.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                TargetCard(Modifier.weight(1f), R.drawable.ic_users, "رسالة QR", "نص سري ينتقل بين هاتفين بالتصوير", target == 4) { target = 4 }
                Spacer(Modifier.weight(1f))
            }
            Gap(22.dp)
            when (target) {
                0 -> {
                    Text("الصيغة", style = T.label)
                    Gap(10.dp)
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        FormatOption("VeraCrypt", "يُفتح على أي حاسوب ببرنامج VeraCrypt، وعلى هذا التطبيق. يدعم المجلد المخفي وملفات المفاتيح.", format == "VeraCrypt", badge = { Tag("موصى به", TagKind.Brass) }) { format = "VeraCrypt" }
                        FormatOption("QsCrypt", "الأقوى: AES وTwofish وSerpent معاً مع Argon2id، ومزايا الحماية كربط جهات الاتصال وكلمة الطوارئ. يُفتح بـ QsCrypt فقط.", format == "QsCrypt", badge = { Tag("الأقوى", TagKind.Mint) }) { format = "QsCrypt" }
                        FormatOption("BitLocker", "ملف VHD يفتحه ويندوز مباشرة دون أي برنامج: انقر عليه مرتين ثم أدخل كلمة المرور.", format == "BitLocker", badge = { Tag("ويندوز", TagKind.Outline) }) { format = "BitLocker" }
                        FormatOption("TrueCrypt", "للتوافق مع البرامج القديمة فقط. حمايته أضعف من VeraCrypt.", format == "TrueCrypt") { format = "TrueCrypt" }
                    }
                }
                1 -> Note("تُشفّر الملفات بصيغة QsCrypt بثلاث طبقات، ويمكنك ربطها بجهات اتصالك أو إضافة مزايا الحماية. يُنشأ لكل ملف نسخة ‎.qsc‎ ويبقى الأصل كما هو.")
                2 -> Note("وصّل الفلاشة أو الهارد بالجوال بوصلة OTG، ثم اختره من تبويب «الأقراص» واضغط «تشفير». تُدعم صيغ VeraCrypt وBitLocker وQsCrypt وTrueCrypt، والقرص يُمسح بالكامل.", icon = R.drawable.ic_usb)
                3 -> Note("يُشفَّر الملف بـ QsCrypt ثم يُخفى في صورة تختارها: تبقى صورة عادية تُفتح في أي معرض، ولأي حجم من الملفات. أرسلها «كملف» لا «كصورة»، لأن تطبيقات المراسلة تضغط الصور فيضيع المخفي.", icon = R.drawable.ic_image)
                else -> Note("رسالة نصية قصيرة تُشفَّر في رمز QR: يصوّره صديقك بكاميرا QsCrypt فيقرؤها، بلا إنترنت ولا بلوتوث. تُقرأ بكلمة مرور أو بهوية جهة الاتصال.", icon = R.drawable.ic_users)
            }
            Gap(20.dp)
        }
        Column(Modifier.padding(horizontal = 20.dp)) {
            PrimaryButton(if (target == 2) "اذهب إلى الأقراص" else "التالي") {
                when (target) {
                    0 -> AppState.push(Screen.NewContainer(format))
                    1 -> AppState.push(Screen.QscEncrypt)
                    2 -> AppState.tab(Screen.Drives)
                    3 -> AppState.push(Screen.Stego)
                    else -> AppState.push(Screen.Message)
                }
            }
            Gap(24.dp)
        }
    }
}

// ------------------------------------------------------------------ containers and drives

private val SIZES = listOf(100L to "100 MB", 500L to "500 MB", 1024L to "1 GB", 4096L to "4 GB", 16384L to "16 GB")
private val VC_PRFS = listOf(1 to "SHA-512", 2 to "SHA-256", 3 to "Whirlpool")
private val TC_PRFS = listOf(1 to "SHA-512", 4 to "RIPEMD-160", 3 to "Whirlpool")
private val EAS = listOf(1 to "AES", 2 to "Serpent", 3 to "Twofish", 4 to "AES-Twofish", 5 to "AES-Twofish-Serpent", 6 to "Serpent-AES", 7 to "Serpent-Twofish-AES", 8 to "Twofish-Serpent")
private val BDE_METHODS = listOf("xts128" to "XTS-AES 128", "xts256" to "XTS-AES 256", "cbc128" to "AES-CBC 128", "cbc256" to "AES-CBC 256")
private const val MIB = 1024L * 1024L
private const val MIN_HIDDEN = MIB + 131_072L

private fun extensionFor(format: String) = when (format) {
    "TrueCrypt" -> ".tc"
    "BitLocker" -> ".vhd"
    "QsCrypt" -> ".qsv"
    else -> ".hc"
}

/** Cards of everyone who may open a QsCrypt file or container (and mine, if asked). */
fun recipientCards(context: android.content.Context, p: Protection): JSONArray {
    val cards = JSONArray()
    p.recipients.forEach { cards.put(it.card) }
    if (p.recipients.isNotEmpty() && p.includeMe) Identity.public(context)?.optString("card")?.takeIf { it.isNotEmpty() }?.let { cards.put(it) }
    return cards
}

/** How the new volume's free space is written: now, in the background, or not at all. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FillChoice(mode: Int, hidden: Boolean, onChange: (Int) -> Unit) {
    Text("التهيئة", style = T.label)
    Gap(8.dp)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Chip("سريعة + ملء في الخلفية", mode == 1 && !hidden, enabled = !hidden) { onChange(1) }
        Chip("كاملة الآن", mode == 0 || hidden) { onChange(0) }
        Chip("سريعة فقط", mode == 2 && !hidden, enabled = !hidden) { onChange(2) }
    }
    Gap(6.dp)
    Text(
        when {
            hidden -> "المجلد المخفي يتطلب التهيئة الكاملة: يُكتب القرص كله الآن."
            mode == 1 -> "تُستخدم فوراً، وتُملأ المساحة الفارغة ببيانات مشفّرة في الخلفية: يمكن إيقافها مؤقتاً، وتُستأنف عند فتحها لاحقاً. الموصى به."
            mode == 0 -> "يُكتب القرص كله مشفّراً قبل الاستخدام. أبطأ، لكنه يمنع من البداية معرفة مقدار ما كُتب فيه."
            else -> "الأسرع، لكن المساحة الفارغة تبقى كما كانت (قد تكشف حجم ما كُتب، أو بيانات قديمة على فلاشة مستعملة)."
        },
        style = T.small,
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun NewContainerScreen(format: String, usb: UsbTarget? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tc = format == "TrueCrypt"
    val vc = format == "VeraCrypt" || tc
    val bitlocker = format == "BitLocker"
    val qs = format == "QsCrypt"
    val engineFormat = format.lowercase()
    var name by remember { mutableStateOf(if (bitlocker) "قرصي" else "خزنتي") }
    var sizeMb by remember { mutableLongStateOf(if (bitlocker) 1024L else 500L) }
    var custom by remember { mutableStateOf("") }
    var fs by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var ea by remember { mutableIntStateOf(1) }
    var prf by remember { mutableIntStateOf(1) }
    var method by remember { mutableStateOf("xts128") }
    /** 0: write the whole volume now; 1: quick format, then fill free space in the background; 2: quick only. */
    var fillMode by remember { mutableIntStateOf(1) }
    val keyfiles = remember { mutableStateListOf<Keyfile>() }
    var hidden by remember { mutableStateOf(false) }
    var hiddenMb by remember { mutableStateOf("") }
    var hiddenPassword by remember { mutableStateOf("") }
    var hiddenConfirm by remember { mutableStateOf("") }
    var hiddenPim by remember { mutableStateOf("") }
    val hiddenKeyfiles = remember { mutableStateListOf<Keyfile>() }
    var maxHidden by remember { mutableLongStateOf(0L) }
    val protection = remember { Protection() }
    var advanced by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var confirmErase by remember { mutableStateOf(false) }
    var recovery by remember { mutableStateOf<Pair<String, CompletableDeferred<Unit>>?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    val selfTest = AppState.selfTest
    val hasIdentity = remember { Identity.exists(context) }

    val bytes = usb?.size ?: ((custom.toLongOrNull() ?: sizeMb) * MIB)
    val fsChoice = fs.ifEmpty { if (bytes >= 4096L * MIB) "exfat" else "fat" }
    val minBytes = when {
        bitlocker -> 65L * MIB
        qs -> 4L * MIB
        else -> 2L * MIB
    }
    val hiddenBytes = (hiddenMb.toLongOrNull() ?: 0L) * MIB
    val pimValue = if (vc && !tc) pim.toIntOrNull() ?: 0 else 0
    val passwordOk = when {
        bitlocker -> password.length >= 8 && password == confirm
        qs -> password == confirm && (password.isNotEmpty() || protection.recipients.isNotEmpty())
        else -> password == confirm && (password.isNotEmpty() || keyfiles.isNotEmpty())
    }
    val hiddenOk = !hidden || (
        maxHidden > 0 && hiddenBytes >= MIN_HIDDEN && hiddenBytes <= maxHidden &&
            (hiddenPassword.isNotEmpty() || hiddenKeyfiles.isNotEmpty()) && hiddenPassword == hiddenConfirm && hiddenPassword != password
        )
    val duressOk = !qs || !protection.duress || (protection.duressPassword.isNotEmpty() && protection.duressPassword != password)
    val valid = (usb != null || name.isNotBlank()) && bytes >= minBytes && passwordOk && hiddenOk && duressOk

    LaunchedEffect(hidden, bytes, fsChoice) {
        if (!hidden || !vc) return@LaunchedEffect
        val r = withContext(Dispatchers.IO) { Call("volume.maxHidden").put("size", bytes).put("fs", fsChoice).run() }
        maxHidden = if (r.ok) r.json.optLong("max") else -1L
    }

    fun progress() = Progress { d, t ->
        busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null)
        !cancel.get()
    }

    fun create(uri: Uri?) {
        cancel.set(false)
        val pw = password.toByteArray(Charsets.UTF_8)
        val hpw = hiddenPassword.toByteArray(Charsets.UTF_8)
        busy = Busy(
            if (usb != null) "تشفير القرص" else "إنشاء الحاوية",
            0f,
            when {
                hidden || fillMode == 0 -> "يُكتب القرص كاملاً مشفّراً، وقد يستغرق ذلك دقائق للأحجام الكبيرة."
                fillMode == 1 -> "تهيئة سريعة الآن، ثم تُملأ المساحة الفارغة ببيانات مشفّرة في الخلفية."
                else -> "تهيئة سريعة: تُكتب البيانات الوصفية فقط."
            },
        )
        scope.launch {
            val target: UsbTarget? = if (usb != null && bitlocker && usb.start == 0L) {
                // BitLocker on a whole drive: Windows expects a partition.
                val s = UsbDrives.sessions.firstOrNull { it.handle == usb.handle }
                val r = withContext(Dispatchers.IO) { s?.let { UsbDrives.partition(it, 0x07) } }
                val p = r?.json?.optJSONArray("partitions")?.optJSONObject(0)
                if (r == null || !r.ok || p == null) {
                    busy = null
                    pw.fill(0)
                    hpw.fill(0)
                    message = "تعذّر إنشاء قسم على القرص: ${r?.error ?: "الفلاشة غير متصلة"}"
                    return@launch
                }
                UsbTarget(usb.handle, p.optLong("start"), p.optLong("size"), "القسم 1", "empty")
            } else {
                usb
            }
            val created = withContext(Dispatchers.IO) {
                val call = Call("volume.create").put("format", engineFormat).put("size", bytes).put("fs", fsChoice)
                    .put("label", if (usb != null) "QsCrypt" else name.trim()).put("quick", fillMode != 0 && !hidden)
                when {
                    vc -> {
                        call.put("ea", ea).put("prf", prf).put("pim", pimValue)
                            .blob("password", pw.copyOf()).blob("keyfiles", packKeyfiles(context, keyfiles))
                        if (hidden) {
                            val h = JSONObject().put("size", hiddenBytes).put("password", call.blobIndex(hpw.copyOf()))
                                .put("pim", hiddenPim.toIntOrNull() ?: 0).put("ea", ea)
                                .put("fs", if (hiddenBytes >= 4096L * MIB) "exfat" else "fat").put("label", "")
                            packKeyfiles(context, hiddenKeyfiles)?.let { h.put("keyfiles", call.blobIndex(it)) }
                            call.put("hidden", h)
                        }
                    }
                    bitlocker -> call.put("method", method).put("description", "QsCrypt").put("vhd", target == null).blob("password", pw.copyOf())
                    else -> {
                        call.blob("password", if (pw.isNotEmpty()) pw.copyOf() else null)
                            .put("recovery", protection.recovery).put("recipients", recipientCards(context, protection)).put("policy", protection.policy())
                        if (protection.duress && protection.duressPassword.isNotEmpty()) call.blob("duress", protection.duressPassword.toByteArray(Charsets.UTF_8))
                    }
                }
                if (target != null) {
                    call.srcUsb(target).run(progress())
                } else {
                    Saf.open(context, uri!!, "rw")?.use { call.src(it.fd).run(progress()) }
                        ?: Reply("""{"ok":false,"code":"io","message":"cannot open the new file"}""")
                }
            }
            if (!created.ok) {
                pw.fill(0)
                hpw.fill(0)
                busy = null
                if (uri != null) Saf.delete(context, uri)
                message = when (created.code) {
                    "cancelled" -> null
                    else -> "تعذّر الإنشاء: ${created.error}" + if (usb == null) "\nتأكد من وجود مساحة كافية واختر موقعاً على الجهاز أو الفلاشة." else ""
                }
                return@launch
            }
            val drive = target?.let { t -> UsbDrives.sessions.firstOrNull { it.handle == t.handle } }
            val container = if (target != null && drive != null) {
                withContext(Dispatchers.IO) { UsbDrives.refresh(drive) }
                UsbDrives.container(drive, target).copy(format = format, ea = created.json.optString("ea"))
            } else {
                Saf.persist(context, uri!!)
                val meta = Saf.meta(context, uri)
                AppState.addContainer(Container(uri.toString(), meta.name, meta.size.takeIf { it > 0 } ?: bytes, System.currentTimeMillis(), format, created.json.optString("ea"), fsChoice))
            }
            val key = created.json.optString("recovery")
            if (key.isNotEmpty()) {
                busy = null
                val ack = CompletableDeferred<Unit>()
                recovery = key to ack
                ack.await()
                recovery = null
            }
            if (qs && pw.isEmpty() && !(protection.includeMe && hasIdentity && protection.recipients.isNotEmpty())) {
                // Only the recipients can open it; nothing more to do here.
                busy = null
                message = "تم إنشاء الحاوية. لا يفتحها إلا من اخترتهم من جهات الاتصال."
                AppState.replaceTop(Screen.Home)
                return@launch
            }
            busy = Busy(if (usb != null) "فتح القرص" else "فتح الحاوية", null)
            val opened = withContext(Dispatchers.IO) {
                val call = Call("volume.open").put("readOnly", false).put("tz", tzMinutes()).put("format", engineFormat)
                    .put("pim", pimValue).put("prf", if (vc) prf else 0)
                when {
                    qs && pw.isEmpty() -> call.put("unlock", "identity").blob("identity", Identity.secret(context))
                    else -> call.put("unlock", "password").blob("password", pw.copyOf()).blob("keyfiles", if (vc) packKeyfiles(context, keyfiles) else null)
                }
                if (hidden) {
                    call.put("protectHidden", true).blob("hiddenPassword", hpw.copyOf()).put("hiddenPim", hiddenPim.toIntOrNull() ?: 0)
                        .blob("hiddenKeyfiles", packKeyfiles(context, hiddenKeyfiles))
                }
                call.context()
                if (target != null) call.srcUsb(target).run()
                else Saf.open(context, uri!!, "rw")?.use { call.src(it.fd).run() } ?: Reply("""{"ok":false,"code":"io","message":"open"}""")
            }
            pw.fill(0)
            hpw.fill(0)
            busy = null
            if (opened.ok) {
                val info = VolumeInfo.from(opened.json)
                val session = Session(info.handle, container, info, System.currentTimeMillis(), target)
                AppState.opened(session)
                // Usable at once; the free space fills in the background (pausable, resumes later).
                if (fillMode == 1 && !hidden) Fill.schedule(context, session)
                AppState.replaceTop(Screen.Vault(info.handle))
            } else {
                message = "تم الإنشاء، لكن تعذّر فتحه الآن: ${opened.error}"
                AppState.replaceTop(Screen.Home)
            }
        }
    }

    val creator = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) create(uri)
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            TopBar(if (usb != null) "تشفير قرص · $format" else "حاوية $format جديدة", onBack = { AppState.pop() })
            Gap(10.dp)
            StepBar(2, 3)
            Gap(20.dp)
            if (usb != null) {
                QsCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Tile(R.drawable.ic_usb, Qs.coral, size = 46.dp, radius = 15.dp)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(usb.title, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(humanSize(usb.size), style = T.mono.copy(fontSize = 12.sp))
                        }
                    }
                }
                Gap(10.dp)
                Note("سيُمسح كل ما على هذا القرص نهائياً. انسخ ملفاتك المهمة منه قبل المتابعة.", icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
                if (bitlocker && usb.start == 0L) {
                    Gap(8.dp)
                    Text("سيُنشأ قسم واحد يشغل القرص كله، كما يفعل ويندوز.", style = T.small)
                }
                Gap(18.dp)
            } else {
                Text(if (bitlocker) "اسم الملف" else "اسم الحاوية", style = T.label)
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
                if (bytes < minBytes) {
                    Gap(6.dp)
                    Text("أقل حجم لهذه الصيغة ${humanSize(minBytes)}.", style = T.small.copy(color = Qs.coral))
                }
                Gap(18.dp)
            }
            Text("نظام الملفات", style = T.label)
            Gap(8.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Chip("FAT", fsChoice == "fat") { fs = "fat" }
                Chip("exFAT", fsChoice == "exfat") { fs = "exfat" }
            }
            Gap(6.dp)
            Text(
                if (fsChoice == "fat") "FAT يعمل في كل مكان، وأقصى حجم للملف الواحد 4GB." else "exFAT بلا حد عملي لحجم الملف، ويعمل على ويندوز وماك وأندرويد الحديث.",
                style = T.small,
            )
            Gap(20.dp)
            if (qs) {
                Text("كلمة المرور اختيارية إن ربطته بجهات اتصال.", style = T.small)
                Gap(8.dp)
            }
            PasswordPair(password, confirm, { password = it }, { confirm = it })
            if (bitlocker && password.isNotEmpty() && password.length < 8) {
                Gap(6.dp)
                Text("BitLocker يشترط 8 أحرف على الأقل.", style = T.small.copy(color = Qs.coral))
            }
            if (vc) {
                Gap(8.dp)
                KeyfilesRow(keyfiles)
            }
            Gap(20.dp)
            when {
                vc -> {
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
                        (if (tc) TC_PRFS else VC_PRFS).forEach { (id, label) -> Chip(label, prf == id) { prf = id } }
                    }
                    if (!tc) {
                        Gap(16.dp)
                        OptionRow(R.drawable.ic_key, "PIM (اختياري)", "رقم يزيد قوة الاشتقاق، ويجب إدخاله عند كل فتح") {
                            QsField(value = pim, onValueChange = { v -> pim = v.filter { it.isDigit() }.take(5) }, placeholder = "—", keyboardType = KeyboardType.NumberPassword, height = 40.dp, modifier = Modifier.width(92.dp), textStyle = T.monoLarge)
                        }
                    } else {
                        Gap(12.dp)
                        Note("TrueCrypt يستخدم 1000 دورة اشتقاق فقط، فكلمة المرور أسهل تخميناً بكثير من VeraCrypt. استخدمه للتوافق فقط.", icon = R.drawable.ic_alert, color = Qs.coral)
                    }
                    Gap(8.dp)
                    OptionRow(R.drawable.ic_eye, "مجلد مخفي", "مجلد ثانٍ بكلمة مرور أخرى لا يمكن إثبات وجوده") { QsSwitch(hidden) { hidden = it } }
                    if (hidden) {
                        Column(Modifier.padding(start = 12.dp)) {
                            Text("إن أُجبرت على كشف كلمة المرور، أعطِ كلمة الحاوية الخارجية: تظهر ملفات عادية تضعها أنت، ويبقى المخفي غير قابل للإثبات.", style = T.small)
                            if (maxHidden < 0) {
                                Gap(6.dp)
                                Text("الحجم صغير جداً لمجلد مخفي. اختر حجماً أكبر.", style = T.small.copy(color = Qs.coral))
                            }
                            Gap(10.dp)
                            QsField(
                                value = hiddenMb,
                                onValueChange = { v -> hiddenMb = v.filter { it.isDigit() }.take(7) },
                                placeholder = if (maxHidden > 0) "حجم المخفي (حتى ${maxHidden / MIB} MB)" else "حجم المخفي",
                                keyboardType = KeyboardType.Number,
                                height = 48.dp,
                                trailing = { Text("MB", style = T.mono, modifier = Modifier.padding(end = 12.dp)) },
                            )
                            if (hiddenBytes > 0 && maxHidden > 0 && hiddenBytes > maxHidden) {
                                Gap(4.dp)
                                Text("أكبر حجم ممكن ${maxHidden / MIB} MB.", style = T.small.copy(color = Qs.coral))
                            }
                            Gap(10.dp)
                            QsField(value = hiddenPassword, onValueChange = { hiddenPassword = it }, placeholder = "كلمة مرور المجلد المخفي", password = true, height = 50.dp)
                            Gap(8.dp)
                            QsField(value = hiddenConfirm, onValueChange = { hiddenConfirm = it }, placeholder = "تأكيدها", password = true, height = 50.dp)
                            if (hiddenPassword.isNotEmpty() && hiddenPassword == password) {
                                Gap(4.dp)
                                Text("يجب أن تختلف عن كلمة مرور الحاوية الخارجية.", style = T.small.copy(color = Qs.coral))
                            } else if (hiddenConfirm.isNotEmpty() && hiddenConfirm != hiddenPassword) {
                                Gap(4.dp)
                                Text("غير متطابقتين", style = T.small.copy(color = Qs.coral))
                            }
                            if (!tc) {
                                OptionRow(R.drawable.ic_key, "PIM المخفي", "اختياري") {
                                    QsField(value = hiddenPim, onValueChange = { v -> hiddenPim = v.filter { it.isDigit() }.take(5) }, placeholder = "—", keyboardType = KeyboardType.NumberPassword, height = 40.dp, modifier = Modifier.width(92.dp), textStyle = T.monoLarge)
                                }
                            }
                            KeyfilesRow(hiddenKeyfiles, "ملفات مفاتيح المخفي")
                        }
                    }
                }
                bitlocker -> {
                    Text("طريقة التشفير", style = T.label)
                    Gap(8.dp)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        BDE_METHODS.forEach { (id, label) -> Chip(label, method == id) { method = id } }
                    }
                    Gap(8.dp)
                    Text(
                        if (method.startsWith("xts")) "XTS-AES هو افتراضي ويندوز 10 و11." else "AES-CBC للتوافق مع ويندوز 7 و8.",
                        style = T.small,
                    )
                    Gap(12.dp)
                    Note(
                        if (usb != null) "بعد التشفير، ضع الفلاشة في أي حاسوب ويندوز فيطلب كلمة المرور، دون أي برنامج."
                        else "يُحفظ كملف ‎.vhd‎: على ويندوز انقر عليه مرتين ليظهر كقرص، ثم افتحه بكلمة المرور. ويُفتح على هذا التطبيق أيضاً.",
                        icon = R.drawable.ic_drive,
                    )
                    Gap(6.dp)
                    Text("سيُعرض بعد الإنشاء مفتاح استرداد من 48 رقماً، يفتحه إن نسيت كلمة المرور.", style = T.small)
                }
                else -> ProtectionEditor(protection, container = true, hasIdentity = hasIdentity, hasPassword = password.isNotEmpty())
            }
            if (qs) {
                Gap(14.dp)
                FillChoice(fillMode, false) { fillMode = it }
            }
            if (!qs) {
                Gap(8.dp)
                Text(
                    if (advanced) "إخفاء الخيارات المتقدمة" else "خيارات متقدمة",
                    style = T.label.copy(color = Qs.brass),
                    modifier = Modifier.clickable { advanced = !advanced }.padding(vertical = 12.dp),
                )
                if (advanced) {
                    FillChoice(fillMode, hidden) { fillMode = it }
                }
            }
            Gap(20.dp)
        }
        Column(Modifier.padding(horizontal = 20.dp)) {
            PrimaryButton(
                if (usb != null) "تشفير القرص (${humanSize(bytes)})" else "إنشاء (${humanSize(bytes)})",
                icon = R.drawable.ic_lock,
                enabled = valid,
            ) {
                if (usb != null) {
                    if (AppState.sessions.any { it.container.uri.startsWith("usb:${usb.handle}:") }) {
                        message = "أغلق الأقراص المفتوحة من هذه الفلاشة أولاً."
                    } else {
                        confirmErase = true
                    }
                } else {
                    AppState.pickerOpen = true
                    val ext = extensionFor(format)
                    creator.launch(name.trim().let { if (it.endsWith(ext, ignoreCase = true)) it else it + ext })
                }
            }
            Gap(24.dp)
        }
    }
    if (confirmErase && usb != null) {
        DangerConfirm(
            "مسح القرص وتشفيره؟",
            "سيُمسح كل ما على «${usb.title}» (${humanSize(usb.size)}) نهائياً ولا يمكن التراجع.",
            "امسح وشفّر",
            { confirmErase = false; create(null) },
            { confirmErase = false },
        )
    }
    recovery?.let { (key, ack) ->
        RecoveryKeyDialog(
            if (bitlocker) "مفتاح استرداد BitLocker" else "مفتاح الاسترداد",
            key,
            if (bitlocker) "يفتح القرص على أي ويندوز وعلى QsCrypt إن نسيت كلمة المرور. احفظه بعيداً عن القرص: اكتبه على ورق أو في مدير كلمات مرور."
            else "يفتح الحاوية إن نسيت كلمة المرور. احفظه بعيداً عن الحاوية، فمن يملكه يستطيع فتحها.",
        ) { ack.complete(Unit) }
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = if (b.fraction != null) ({ cancel.set(true) }) else null) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}
