package com.qscrypt.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.Contact
import com.qscrypt.app.Identity
import com.qscrypt.app.Prefs
import com.qscrypt.app.Progress
import com.qscrypt.app.Qr
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

// ------------------------------------------------------------------ files shared from other apps

/** Where files shared to QsCrypt go: into an open vault, or encrypted as QsCrypt files. */
@Composable
fun ShareInScreen() {
    val context = LocalContext.current
    val docs = remember(AppState.shared) { AppState.shared.map { Saf.meta(context, it) } }
    if (AppState.shared.isEmpty()) {
        androidx.compose.runtime.LaunchedEffect(Unit) { AppState.pop() }
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("ملفات مشتركة", onBack = {
            AppState.shared = emptyList()
            AppState.pop()
        })
        Gap(12.dp)
        QsCard {
            Column {
                docs.take(6).forEach { m ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        QsIcon(R.drawable.ic_file, Qs.ivory, 18.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(m.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                        Text(humanSize(m.size), style = T.mono)
                    }
                }
                if (docs.size > 6) Text("و${docs.size - 6} ملفات أخرى", style = T.small)
            }
        }
        Gap(18.dp)
        val writable = AppState.sessions.filter { !it.info.readOnly }
        SectionLabel("أضفها إلى خزنة")
        Gap(8.dp)
        if (writable.isEmpty()) {
            Note("لا توجد خزنة مفتوحة. افتح خزنة من الرئيسية ثم عد إلى هنا، أو شفّرها كملفات QsCrypt.", icon = R.drawable.ic_info)
        }
        writable.forEach { s ->
            QsCard(Modifier.padding(vertical = 4.dp), onClick = { AppState.replaceTop(Screen.Vault(s.handle)) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(if (s.plain) R.drawable.ic_usb else R.drawable.ic_vault, Qs.brass, size = 40.dp, radius = 12.dp, iconSize = 20.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(s.container.name.substringBeforeLast('.').ifBlank { s.container.name }, style = T.item)
                        Text("اختر المجلد ثم «أضفها هنا»", style = T.small)
                    }
                    QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
                }
            }
        }
        Gap(18.dp)
        SectionLabel("أو")
        Gap(8.dp)
        SecondaryButton("شفّرها كملفات QsCrypt", icon = R.drawable.ic_lock) {
            AppState.encryptShared = AppState.shared
            AppState.shared = emptyList()
            AppState.replaceTop(Screen.QscEncrypt)
        }
        Gap(10.dp)
        if (AppState.containers.isNotEmpty() && writable.isEmpty()) {
            SecondaryButton("افتح خزنة", icon = R.drawable.ic_unlock) { AppState.tab(Screen.Home) }
        }
        Gap(24.dp)
    }
}

// ------------------------------------------------------------------ speed test

/** How fast each cipher is on this phone, and how long opening a vault takes. */
@Composable
fun BenchScreen() {
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var fraction by remember { mutableStateOf(0f) }
    var result by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("اختبار السرعة", onBack = { AppState.pop() })
        Gap(10.dp)
        Text("يقيس سرعة كل خوارزمية على معالج هذا الهاتف، ومدة فتح الخزنة. لا يمسّ ملفاتك.", style = T.small)
        Gap(16.dp)
        if (running) {
            LinearProgressIndicator(progress = { fraction }, color = Qs.brass, trackColor = Qs.line, modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)))
            Gap(8.dp)
            Text("يُقاس… (نحو عشر ثوانٍ)", style = T.small)
        } else {
            PrimaryButton(if (result == null) "ابدأ الاختبار" else "أعد الاختبار", icon = R.drawable.ic_clock) {
                running = true
                error = null
                scope.launch {
                    val r = withContext(Dispatchers.Default) {
                        Call("bench.run").run(Progress { d, t ->
                            fraction = if (t > 0) d.toFloat() / t else 0f
                            true
                        })
                    }
                    running = false
                    if (r.ok) result = r.json else error = r.error
                }
            }
        }
        error?.let {
            Gap(10.dp)
            Note(it, icon = R.drawable.ic_alert, color = Qs.coral)
        }
        result?.let { j ->
            val ciphers = j.optJSONArray("ciphers") ?: JSONArray()
            val rows = (0 until ciphers.length()).map { ciphers.getJSONObject(it) }
            val max = rows.maxOfOrNull { it.optDouble("encrypt") }?.coerceAtLeast(1.0) ?: 1.0
            val fastest = rows.maxByOrNull { it.optDouble("encrypt") }
            Gap(20.dp)
            SectionLabel("الحاويات (VeraCrypt وBitLocker)", count = "MB/ث")
            Gap(8.dp)
            rows.forEach { c ->
                val enc = c.optDouble("encrypt")
                Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                    Row(Modifier.fillMaxWidth()) {
                        Text(c.optString("name"), style = T.item.copy(fontSize = 14.sp), modifier = Modifier.weight(1f))
                        Text("%.0f / %.0f".format(enc, c.optDouble("decrypt")), style = T.mono)
                    }
                    Gap(4.dp)
                    Box(Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)).background(Qs.surface2)) {
                        Box(Modifier.fillMaxWidth((enc / max).toFloat().coerceIn(0.02f, 1f)).height(6.dp).clip(RoundedCornerShape(3.dp)).background(if (c == fastest) Qs.mint else Qs.brass))
                    }
                }
            }
            Gap(4.dp)
            Text("الرقم الأول للتشفير والثاني لفك التشفير.", style = T.small)
            Gap(18.dp)
            SectionLabel("ملفات QsCrypt")
            Gap(6.dp)
            Text("%.0f MB/ث (ثلاث طبقات تشفير)".format(j.optDouble("qscrypt")), style = T.item)
            Gap(18.dp)
            SectionLabel("مدة فتح الخزنة (اشتقاق المفتاح من كلمة المرور)")
            Gap(6.dp)
            Text("QsCrypt (Argon2id 64 MB): ${j.optLong("argon2Ms")} ملّي ثانية", style = T.item)
            Text("VeraCrypt (PBKDF2-SHA512، 500 ألف تكرار): ${"%.1f".format(j.optLong("pbkdf2Ms") / 1000.0)} ثانية", style = T.item)
            Gap(8.dp)
            Text("البطء هنا مقصود: يجعل تخمين كلمة المرور مكلفاً جداً على المهاجم.", style = T.small)
            Gap(16.dp)
            fastest?.let { Note("الأسرع على هذا الهاتف: ${it.optString("name")}. كل الخوارزميات آمنة؛ الأبطأ (السلاسل) تزيد هامش الأمان.", icon = R.drawable.ic_info) }
            Gap(8.dp)
            Text("المحرك: ${j.optString("backend")} · الأنوية: ${j.optLong("threads")}", style = T.mono)
        }
        Gap(24.dp)
    }
}

// ------------------------------------------------------------------ secret messages by QR

@Composable
private fun MultiField(value: String, onValueChange: (String) -> Unit, placeholder: String) {
    val shape = RoundedCornerShape(16.dp)
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        textStyle = T.body.copy(fontSize = 16.sp, lineHeight = 26.sp, color = Qs.ivory),
        cursorBrush = SolidColor(Qs.brass),
        modifier = Modifier.fillMaxWidth(),
        decorationBox = { inner ->
            Box(Modifier.fillMaxWidth().heightIn(min = 150.dp).clip(shape).background(Qs.surface).border(1.dp, Qs.line, shape).padding(14.dp)) {
                if (value.isEmpty()) Text(placeholder, style = T.body.copy(color = Qs.muted, fontSize = 15.sp))
                inner()
            }
        },
    )
}

private fun copyText(context: Context, text: String, label: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    // Android 13+: mark as sensitive so it is not previewed.
    clip.description.extras = android.os.PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    cm.setPrimaryClip(clip)
}

/**
 * A short secret text in one QR code: for contacts (only they can read it),
 * and/or with a password, optionally signed. Works with no internet.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun MessageScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableIntStateOf(0) }
    // Writing
    var text by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    val chosen = remember { mutableStateListOf<Contact>() }
    var picking by remember { mutableStateOf(false) }
    var sign by remember { mutableStateOf(Identity.exists(context)) }
    var sealed by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // Reading
    var scanned by remember { mutableStateOf<String?>(null) }
    var askPassword by remember { mutableStateOf(false) }
    var readPassword by remember { mutableStateOf("") }
    var opened by remember { mutableStateOf<JSONObject?>(null) }
    val hasIdentity = remember { Identity.exists(context) }
    val contacts = remember { Prefs.contacts() }

    fun open(raw: String) {
        error = null
        opened = null
        if (!raw.contains("QSMSG1:")) {
            error = "هذا ليس رمز رسالة QsCrypt."
            return
        }
        scanned = raw
        busy = true
        scope.launch {
            // First as one of its recipients (our identity), then ask for a password.
            val r = withContext(Dispatchers.IO) {
                if (hasIdentity) Call("msg.open").put("text", raw).put("unlock", "identity").blob("identity", Identity.secret(context)).context().run() else null
            }
            busy = false
            if (r != null && r.ok) opened = r.json else askPassword = true
        }
    }

    val camera = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (!ok) return@rememberLauncherForActivityResult
        scope.launch {
            val t = withContext(Dispatchers.IO) { Qr.decode(context, cameraUri(context)) }
            if (t == null) error = "لم يُعثر على رمز في الصورة. قرّب الكاميرا وأعد المحاولة." else open(t)
        }
    }
    val image = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            val t = withContext(Dispatchers.IO) { Qr.decode(context, uri) }
            if (t == null) error = "لم يُعثر على رمز في الصورة." else open(t)
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("رسالة سرية برمز QR", onBack = { AppState.pop() })
        Gap(8.dp)
        Text("رسالة قصيرة تنتقل بين هاتفين بالتصوير فقط، بلا إنترنت ولا بلوتوث.", style = T.small)
        Gap(14.dp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Chip("كتابة", tab == 0) { tab = 0; error = null }
            Chip("قراءة", tab == 1) { tab = 1; error = null }
        }
        Gap(16.dp)
        if (tab == 0) {
            val sealedText = sealed
            if (sealedText != null) {
                val bmp = remember(sealedText) { runCatching { Qr.encode(sealedText, 1000).asImageBitmap() }.getOrNull() }
                Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(18.dp)).background(Color.White).padding(10.dp), contentAlignment = Alignment.Center) {
                    if (bmp != null) Image(bmp, contentDescription = "رمز الرسالة", modifier = Modifier.fillMaxWidth()) else Text("تعذّر رسم الرمز", style = T.body.copy(color = Color.Black))
                }
                Gap(10.dp)
                Text(
                    (if (chosen.isNotEmpty()) "يقرؤها: ${chosen.joinToString("، ") { it.name }}" else "تُقرأ بكلمة المرور") + if (password.isNotEmpty() && chosen.isNotEmpty()) " أو بكلمة المرور" else "",
                    style = T.small,
                )
                Gap(12.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton("شارك كنص", modifier = Modifier.weight(1f), icon = R.drawable.ic_share) {
                        val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, sealedText)
                        AppState.pickerOpen = true
                        runCatching { context.startActivity(Intent.createChooser(i, "مشاركة الرسالة المشفّرة")) }
                    }
                    SecondaryButton("رسالة جديدة", modifier = Modifier.weight(1f), icon = R.drawable.ic_edit) {
                        sealed = null
                        text = ""
                    }
                }
                Gap(10.dp)
                Note("الرمز نفسه مشفّر: من يصوّره دون أن يكون من المستلمين أو دون كلمة المرور لا يرى شيئاً.", icon = R.drawable.ic_shield)
            } else {
                MultiField(text, { text = it; error = null }, "اكتب رسالتك هنا…")
                Gap(4.dp)
                Text("${text.toByteArray().size} بايت", style = T.mono.copy(fontSize = 11.sp))
                Gap(14.dp)
                SectionLabel("من يقرؤها")
                Gap(8.dp)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    chosen.forEach { c -> Pill(c.name, Qs.brass, icon = R.drawable.ic_close) { chosen.remove(c) } }
                    if (contacts.isNotEmpty()) Pill(if (chosen.isEmpty()) "اختر من جهات الاتصال" else "تعديل", Qs.ivory, icon = R.drawable.ic_users) { picking = true }
                }
                if (contacts.isEmpty()) Text("أضف جهات اتصال من تبويب «جهات الاتصال» لترسل لهم دون كلمة مرور.", style = T.small)
                Gap(12.dp)
                QsField(value = password, onValueChange = { password = it }, placeholder = if (chosen.isEmpty()) "كلمة مرور الرسالة" else "كلمة مرور (اختيارية)", password = true)
                if (hasIdentity) {
                    Gap(8.dp)
                    OptionRow(R.drawable.ic_check, "وقّعها باسمي", "يتأكد المستلم أنها منك ولم تُعدَّل") { QsSwitch(sign) { sign = it } }
                }
                Gap(14.dp)
                PrimaryButton(if (busy) "جارٍ التشفير…" else "أنشئ الرمز", icon = R.drawable.ic_lock, enabled = !busy && text.isNotBlank() && (password.isNotEmpty() || chosen.isNotEmpty())) {
                    busy = true
                    error = null
                    scope.launch {
                        val cards = JSONArray()
                        chosen.forEach { cards.put(it.card) }
                        val r = withContext(Dispatchers.IO) {
                            val c = Call("msg.seal").blob("text", text.toByteArray(Charsets.UTF_8)).put("recipients", cards)
                            if (password.isNotEmpty()) c.blob("password", password.toByteArray(Charsets.UTF_8))
                            if (sign && hasIdentity) c.put("sign", true).blob("identity", Identity.secret(context))
                            c.run()
                        }
                        busy = false
                        when {
                            r.ok -> sealed = r.json.optString("text")
                            r.code == "too_long" -> error = "الرسالة أطول من أن تتسع في رمز واحد: اختصرها نحو ${(r.json.optLong("over") / 2).coerceAtLeast(1)} حرفاً" + if (chosen.size > 1) "، أو أرسلها لعدد أقل من جهات الاتصال (كل مستلم يأخذ مساحة)." else "."
                            else -> error = r.error
                        }
                    }
                }
            }
        } else {
            val o = opened
            if (o != null) {
                QsCard(glow = true) {
                    Column {
                        SelectionContainer { Text(o.optString("text"), style = T.body.copy(fontSize = 17.sp, lineHeight = 28.sp, color = Qs.ivory)) }
                    }
                }
                Gap(10.dp)
                val signer = o.optString("signer")
                when {
                    !o.optBoolean("signed") -> Text("غير موقّعة: لا يُعرف مرسلها.", style = T.small)
                    !o.optBoolean("signatureValid") -> Note("التوقيع غير صالح: عُدّلت الرسالة أو زُوّرت.", icon = R.drawable.ic_alert, color = Qs.coral)
                    else -> Note("موقّعة من: ${signerName(context, signer) ?: "مفتاح غير معروف (${signer.take(16)}…)"}", icon = R.drawable.ic_check, color = Qs.mint)
                }
                Gap(12.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton("نسخ النص", modifier = Modifier.weight(1f), icon = R.drawable.ic_doc) { copyText(context, o.optString("text"), "QsCrypt") }
                    SecondaryButton("امسح", modifier = Modifier.weight(1f), icon = R.drawable.ic_trash) {
                        opened = null
                        scanned = null
                    }
                }
            } else {
                PrimaryButton("صوّر الرمز", icon = R.drawable.ic_eye) {
                    AppState.pickerOpen = true
                    runCatching { camera.launch(cameraUri(context)) }.onFailure { error = "لا يوجد تطبيق كاميرا." }
                }
                Gap(10.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton("من صورة", modifier = Modifier.weight(1f), icon = R.drawable.ic_image) {
                        AppState.pickerOpen = true
                        image.launch(arrayOf("image/*"))
                    }
                    SecondaryButton("الصق النص", modifier = Modifier.weight(1f), icon = R.drawable.ic_doc) {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                        if (t.isNullOrBlank()) error = "الحافظة فارغة." else open(t)
                    }
                }
                if (busy) {
                    Gap(14.dp)
                    CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(24.dp))
                }
            }
        }
        error?.let {
            Gap(12.dp)
            Note(it, icon = R.drawable.ic_alert, color = Qs.coral)
        }
        Gap(24.dp)
    }
    if (picking) ContactsPickerDialog(contacts, chosen) { picking = false }
    if (askPassword) {
        val raw = scanned
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { askPassword = false },
            containerColor = Qs.surface,
            title = { Text("كلمة مرور الرسالة", style = T.title) },
            text = { QsField(value = readPassword, onValueChange = { readPassword = it }, placeholder = "••••••••", password = true, highlighted = true) },
            confirmButton = {
                androidx.compose.material3.TextButton(enabled = readPassword.isNotEmpty() && raw != null, onClick = {
                    val pw = readPassword
                    askPassword = false
                    busy = true
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { Call("msg.open").put("text", raw).blob("password", pw.toByteArray(Charsets.UTF_8)).context().run() }
                        busy = false
                        readPassword = ""
                        if (r.ok) {
                            opened = r.json
                        } else {
                            Prefs.logAttempt("file", "رسالة QR")
                            error = if (r.code == "wrong_password") "كلمة المرور خاطئة، أو الرسالة ليست لك." else r.error
                        }
                    }
                }) { Text("افتح", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
            },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { askPassword = false }) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
        )
    }
}
