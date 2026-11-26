package com.qscrypt.app.ui

import android.content.Context
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.Container
import com.qscrypt.app.FileKeys
import com.qscrypt.app.Identity
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.Session
import com.qscrypt.app.UsbTarget
import com.qscrypt.app.VolumeInfo
import com.qscrypt.app.humanSize
import com.qscrypt.app.policyText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.TimeZone

private val PRFS = listOf(0 to "تلقائي", 1 to "SHA-512", 2 to "SHA-256", 3 to "Whirlpool", 4 to "RIPEMD-160")
private val FORMATS = listOf("auto" to "تلقائي", "veracrypt" to "VeraCrypt", "truecrypt" to "TrueCrypt")

fun tzMinutes() = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000

/**
 * Runs `block` with the disk of a container (a file, opened read-write when
 * the provider allows it, so policies can still be enforced) or a USB drive.
 */
fun <T> withSource(context: Context, container: Container, usb: UsbTarget?, writable: Boolean, block: (Call.() -> Call) -> T): T? {
    if (usb != null) return block { srcUsb(usb) }
    val uri = Uri.parse(container.uri)
    val rw = if (writable) Saf.open(context, uri, "rw") else null
    val pfd = rw ?: Saf.open(context, uri, "r") ?: return null
    return pfd.use { p -> block { src(p.fd) } }
}

/** Makes a QsCrypt file or container undecryptable (policy enforcement). */
fun destroyQsCrypt(context: Context, container: Container, usb: UsbTarget?): Boolean {
    if (usb != null) return Call("qsc.destroy").srcUsb(usb).run().ok
    val pfd = Saf.open(context, Uri.parse(container.uri), "rw") ?: return false
    return pfd.use { Call("qsc.destroy").fd("fd", it.fd).run().ok }
}

private enum class Kind { Unknown, VeraCrypt, BitLocker, QsCrypt }

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun UnlockScreen(container: Container, usb: UsbTarget? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var readOnly by remember { mutableStateOf(false) }
    var advanced by remember { mutableStateOf(false) }
    var prf by remember { mutableIntStateOf(0) }
    var format by remember { mutableStateOf("auto") }
    var useBackup by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    val keyfiles = remember { mutableStateListOf<Keyfile>() }
    var protect by remember { mutableStateOf(false) }
    var hiddenPassword by remember { mutableStateOf("") }
    var hiddenPim by remember { mutableStateOf("") }
    val hiddenKeyfiles = remember { mutableStateListOf<Keyfile>() }
    var kind by remember { mutableStateOf(Kind.Unknown) }
    var qsMode by remember { mutableStateOf("password") }
    var fileId by remember { mutableStateOf("") }
    var hasRecipients by remember { mutableStateOf(false) }
    val uri = remember(container.uri) { if (usb == null) Uri.parse(container.uri) else null }
    val hasIdentity = remember { Identity.exists(context) }

    LaunchedEffect(container.uri) {
        val r = withContext(Dispatchers.IO) { withSource(context, container, usb, false) { s -> Call("volume.probe").s().run() } }
        kind = when (r?.json?.optString("kind")) {
            "bitlocker" -> Kind.BitLocker
            "qscrypt" -> Kind.QsCrypt
            else -> Kind.VeraCrypt
        }
        if (kind == Kind.QsCrypt && uri != null) {
            val info = withContext(Dispatchers.IO) { Saf.open(context, uri, "r")?.use { Call("qsc.inspect").fd("in", it.fd).run() } }
            val p = info?.json?.optJSONObject("policy")
            fileId = p?.optString("fileId").orEmpty()
            hasRecipients = (p?.optInt("recipients") ?: 0) > 0
            if (FileKeys.has(context, fileId)) qsMode = "filekey"
            else if (hasRecipients && hasIdentity) qsMode = "identity"
        }
    }

    fun opened(r: Reply) {
        val info = VolumeInfo.from(r.json)
        password = ""
        hiddenPassword = ""
        info.extra.optString("fileKey").takeIf { it.isNotEmpty() && fileId.isNotEmpty() }?.let { FileKeys.put(context, fileId, it) }
        if (fileId.isNotEmpty()) Prefs.setAttempts(fileId, 0)
        val c = if (usb == null) {
            AppState.updateContainer(container.copy(format = info.format, ea = info.ea, fs = info.fs))
            AppState.containers.firstOrNull { it.uri == container.uri } ?: container
        } else {
            container.copy(format = info.format, ea = info.ea, fs = info.fs)
        }
        AppState.sessions.add(Session(info.handle, c, info, System.currentTimeMillis(), usb))
        AppState.replaceTop(Screen.Vault(info.handle))
    }

    suspend fun destroyContainer(): Boolean = withContext(Dispatchers.IO) { destroyQsCrypt(context, container, usb) }

    fun unlock() {
        if (busy) return
        if (kind != Kind.QsCrypt || qsMode == "password" || qsMode == "recovery") {
            if (password.isEmpty() && keyfiles.isEmpty()) return
        }
        busy = true
        error = null
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                val pw = password.toByteArray(Charsets.UTF_8)
                val kf = packKeyfiles(context, keyfiles)
                val hpw = if (protect) hiddenPassword.toByteArray(Charsets.UTF_8) else null
                val hkf = if (protect) packKeyfiles(context, hiddenKeyfiles) else null
                val identity = if (kind == Kind.QsCrypt && qsMode == "identity") Identity.secret(context) else null
                val fk = if (kind == Kind.QsCrypt && qsMode == "filekey") FileKeys.get(context, fileId) else null
                withSource(context, container, usb, true) { s ->
                    Call("volume.open").s()
                        .put("readOnly", readOnly).put("tz", tzMinutes()).put("format", format)
                        .put("pim", pim.toIntOrNull() ?: 0).put("prf", prf).put("useBackup", useBackup)
                        .put("protectHidden", protect).put("hiddenPim", hiddenPim.toIntOrNull() ?: 0)
                        .put("unlock", if (kind == Kind.QsCrypt) qsMode else "password")
                        .blob("password", pw).blob("keyfiles", kf).blob("hiddenPassword", hpw).blob("hiddenKeyfiles", hkf)
                        .blob("identity", identity).blob("fileKey", fk)
                        .context().run()
                }
            }
            busy = false
            when {
                r == null -> error = "تعذّر الوصول إلى الملف. ربما نُقل أو حُذف، أو أن الفلاشة غير متصلة."
                r.ok -> opened(r)
                r.code == "policy" -> {
                    val destroyed = r.json.optString("action") == "destroy"
                    if (destroyed) destroyContainer()
                    message = policyText(r.json.optString("reason")) + if (destroyed) "\n\nوقد أُتلفت الحاوية تنفيذاً لسياستها." else ""
                }
                r.code == "wrong_password" && kind == Kind.QsCrypt -> {
                    val p = r.json.optJSONObject("policy")
                    val max = p?.optInt("maxAttempts") ?: 0
                    if (max > 0 && fileId.isNotEmpty()) {
                        val n = Prefs.attempts(fileId) + 1
                        Prefs.setAttempts(fileId, n)
                        if (n >= max) {
                            destroyContainer()
                            message = "تجاوزت عدد المحاولات المسموح ($max)، فأُتلفت الحاوية تنفيذاً لسياستها."
                        } else {
                            error = "كلمة المرور غير صحيحة. بقيت ${max - n} من $max محاولات قبل الإتلاف."
                        }
                    } else {
                        error = r.error
                    }
                }
                else -> error = r.error
            }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar(if (usb != null) "فتح قرص" else "فتح حاوية", onBack = { AppState.pop() })
        Gap(18.dp)
        QsCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tile(if (usb != null) R.drawable.ic_usb else containerIcon(container), Qs.brass, size = 50.dp, radius = 16.dp, iconSize = 24.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(container.name, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(if (uri != null) Saf.location(uri) else usb?.title.orEmpty(), style = T.small, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(humanSize(container.size), style = T.mono.copy(fontSize = 12.sp))
                    when (kind) {
                        Kind.BitLocker -> Tag("BitLocker", TagKind.Brass)
                        Kind.QsCrypt -> Tag("QsCrypt", TagKind.Brass)
                        else -> {}
                    }
                }
            }
        }
        Gap(12.dp)
        Note(
            when (kind) {
                Kind.BitLocker -> "قرص BitLocker من ويندوز. افتحه بكلمة المرور، أو بمفتاح الاسترداد المكوّن من 48 رقماً (بشرطات أو بدونها)."
                Kind.QsCrypt -> "حاوية QsCrypt: ثلاث طبقات تشفير، وقد تحمل سياسات حماية من صاحبها."
                else -> "الحاوية تبدو بيانات عشوائية، وهذا طبيعي. سيتعرّف التطبيق على صيغتها وخوارزمياتها تلقائياً بعد إدخال كلمة المرور."
            },
        )
        Gap(22.dp)
        if (kind == Kind.QsCrypt) {
            Text("طريقة الفتح", style = T.label)
            Gap(8.dp)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Chip("كلمة المرور", qsMode == "password") { qsMode = "password" }
                Chip("مفتاح الاسترداد", qsMode == "recovery") { qsMode = "recovery" }
                if (hasRecipients && hasIdentity) Chip("هويتي", qsMode == "identity") { qsMode = "identity" }
                if (FileKeys.has(context, fileId)) Chip("تلقائي", qsMode == "filekey") { qsMode = "filekey" }
            }
            Gap(14.dp)
        }
        val needsSecret = kind != Kind.QsCrypt || qsMode == "password" || qsMode == "recovery"
        if (needsSecret) {
            Text(
                when {
                    kind == Kind.BitLocker -> "كلمة المرور أو مفتاح الاسترداد"
                    kind == Kind.QsCrypt && qsMode == "recovery" -> "مفتاح الاسترداد (32 حرفاً)"
                    else -> "كلمة المرور"
                },
                style = T.label,
            )
            Gap(8.dp)
            QsField(value = password, onValueChange = { password = it; error = null }, placeholder = "••••••••••••", password = kind != Kind.QsCrypt || qsMode != "recovery", highlighted = true)
        } else {
            Note(if (qsMode == "identity") "ستُفتح بمفتاح هويتك المحفوظ على هذا الهاتف." else "ستُفتح بالمفتاح الذي حفظه هذا الهاتف عند أول فتح.", icon = R.drawable.ic_key)
        }
        if (error != null) {
            Gap(10.dp)
            Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
        }
        Gap(10.dp)
        if (kind == Kind.VeraCrypt || kind == Kind.Unknown) {
            OptionRow(R.drawable.ic_key, "PIM (اختياري)", "اتركه فارغاً لاستخدام القيمة الافتراضية") {
                QsField(value = pim, onValueChange = { v -> pim = v.filter { it.isDigit() }.take(7) }, placeholder = "—", keyboardType = KeyboardType.NumberPassword, height = 40.dp, modifier = Modifier.width(92.dp), textStyle = T.monoLarge)
            }
            KeyfilesRow(keyfiles)
        }
        OptionRow(R.drawable.ic_eye, "فتح للقراءة فقط", "لا يمكن تعديل أي ملف داخل الحاوية") { QsSwitch(readOnly) { readOnly = it } }
        if (kind == Kind.VeraCrypt || kind == Kind.Unknown) {
            OptionRow(R.drawable.ic_shield, "حماية المجلد المخفي", "تمنع الكتابة فوق المجلد المخفي داخل هذه الحاوية") {
                QsSwitch(protect, enabled = !readOnly) { protect = it }
            }
            if (protect && !readOnly) {
                Column(Modifier.padding(start = 12.dp)) {
                    Text("كلمة مرور المجلد المخفي", style = T.small)
                    Gap(6.dp)
                    QsField(value = hiddenPassword, onValueChange = { hiddenPassword = it; error = null }, placeholder = "تُستخدم لمعرفة مكانه فقط", password = true, height = 50.dp)
                    Gap(6.dp)
                    OptionRow(R.drawable.ic_key, "PIM المخفي", "إن وُجد") {
                        QsField(value = hiddenPim, onValueChange = { v -> hiddenPim = v.filter { it.isDigit() }.take(7) }, placeholder = "—", keyboardType = KeyboardType.NumberPassword, height = 40.dp, modifier = Modifier.width(92.dp), textStyle = T.monoLarge)
                    }
                    KeyfilesRow(hiddenKeyfiles, "ملفات مفاتيح المخفي")
                    Text("يُفتح المجلد الخارجي، وأي كتابة كانت ستقع فوق المجلد المخفي تُمنع، والمساحة المتاحة تُحسب بدونه.", style = T.small)
                }
            }
            Text(
                if (advanced) "إخفاء الخيارات المتقدمة" else "خيارات متقدمة",
                style = T.label.copy(color = Qs.brass),
                modifier = Modifier.clickable { advanced = !advanced }.padding(vertical = 12.dp),
            )
            if (advanced) {
                Text("الصيغة", style = T.small)
                Gap(8.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { FORMATS.forEach { (id, name) -> Chip(name, format == id) { format = id } } }
                Gap(14.dp)
                Text("خوارزمية اشتقاق المفتاح (PRF)", style = T.small)
                Gap(8.dp)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { PRFS.take(3).forEach { (id, name) -> Chip(name, prf == id) { prf = id } } }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { PRFS.drop(3).forEach { (id, name) -> Chip(name, prf == id) { prf = id } } }
                }
                Gap(8.dp)
                OptionRow(R.drawable.ic_archive, "استخدام الترويسة الاحتياطية", "إن كانت الترويسة الأولى تالفة") { QsSwitch(useBackup) { useBackup = it } }
                Text("تحديد الخوارزمية يسرّع الفتح، والتلقائي يجرّب الكل.", style = T.small)
            }
        }
        Gap(24.dp)
        if (busy) {
            Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Text(if (kind == Kind.BitLocker) "جاري اشتقاق مفتاح BitLocker…" else "جاري التحقق من كلمة المرور…", style = T.label.copy(color = Qs.ivory))
            }
        } else {
            PrimaryButton(
                if (usb != null) "فتح القرص" else "فتح الحاوية",
                icon = R.drawable.ic_unlock,
                enabled = !needsSecret || password.isNotEmpty() || keyfiles.isNotEmpty(),
            ) { unlock() }
        }
        Gap(12.dp)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            QsIcon(R.drawable.ic_lock, Qs.muted, 14.dp)
            Spacer(Modifier.width(6.dp))
            Text("كلمة المرور لا تُحفظ ولا تغادر جهازك", style = T.small, textAlign = TextAlign.Center)
        }
        Gap(24.dp)
    }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null; AppState.pop() }, { message = null }, dismiss = null) }
}
