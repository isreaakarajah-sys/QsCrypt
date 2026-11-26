package com.qscrypt.app.ui

import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Contact
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import com.qscrypt.app.Saf
import com.qscrypt.app.humanSize
import org.json.JSONObject

// ------------------------------------------------------------------ keyfiles

data class Keyfile(val uri: Uri, val name: String, val size: Long)

/** Reads the first MiB of each keyfile and packs them as [u32 LE length][bytes]... */
fun packKeyfiles(context: Context, list: List<Keyfile>): ByteArray? {
    if (list.isEmpty()) return null
    val out = java.io.ByteArrayOutputStream()
    for (k in list) {
        val bytes = runCatching {
            context.contentResolver.openInputStream(k.uri)?.use { input ->
                val buf = ByteArray(1 shl 20)
                var n = 0
                while (n < buf.size) {
                    val r = input.read(buf, n, buf.size - n)
                    if (r <= 0) break
                    n += r
                }
                buf.copyOf(n).also { buf.fill(0) }
            }
        }.getOrNull() ?: return null
        val len = bytes.size
        out.write(byteArrayOf(len.toByte(), (len shr 8).toByte(), (len shr 16).toByte(), (len shr 24).toByte()))
        out.write(bytes)
        bytes.fill(0)
    }
    return out.toByteArray()
}

/** The keyfiles row with its picker; the list lives in the caller. */
@Composable
fun KeyfilesRow(files: SnapshotStateList<Keyfile>, title: String = "ملفات المفاتيح (Keyfiles)") {
    val context = LocalContext.current
    var info by remember { mutableStateOf(false) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        for (u in uris) if (files.none { it.uri == u }) {
            val m = Saf.meta(context, u)
            files.add(Keyfile(u, m.name, m.size))
        }
    }
    OptionRow(R.drawable.ic_file, title, if (files.isEmpty()) "اختياري: ملفات تصبح جزءاً من المفتاح" else "${files.size} ${if (files.size == 1) "ملف" else "ملفات"}") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("؟", style = T.label.copy(color = Qs.muted), modifier = Modifier.clickable { info = true }.padding(8.dp))
            Text("أضف", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable {
                AppState.pickerOpen = true
                picker.launch(arrayOf("*/*"))
            }.padding(12.dp))
        }
    }
    files.forEach { f ->
        Row(Modifier.fillMaxWidth().padding(start = 32.dp).height(40.dp), verticalAlignment = Alignment.CenterVertically) {
            QsIcon(R.drawable.ic_key, Qs.brass, 16.dp)
            Spacer(Modifier.width(8.dp))
            Text(f.name, style = T.small.copy(color = Qs.ivory), maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            Text(humanSize(f.size), style = T.mono)
            IconBtn(R.drawable.ic_close, "إزالة", tint = Qs.muted) { files.remove(f) }
        }
    }
    if (info) {
        QsAlert(
            "ملفات المفاتيح",
            "أي ملف (صورة، أغنية…) يمكن أن يكون جزءاً من المفتاح مع كلمة المرور، كما في VeraCrypt. تُستخدم أول 1MB من كل ملف، وترتيبها لا يهم. إن فُقد الملف أو تغيّر ولو بايت واحد، لا تُفتح الحاوية أبداً، فاحتفظ بنسخ منه.",
            "فهمت",
            { info = false },
            { info = false },
            dismiss = null,
        )
    }
}

// ------------------------------------------------------------------ dangerous confirmations

@Composable
fun DangerConfirm(title: String, text: String, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    QsAlert(title, text, confirm, onConfirm, onDismiss, danger = true)
}

// ------------------------------------------------------------------ recovery key

@Composable
fun RecoveryKeyDialog(title: String, key: String, note: String, onDone: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = {},
        containerColor = Qs.surface,
        title = { Text(title, style = T.title) },
        text = {
            Column {
                Text(note, style = T.body.copy(fontSize = 13.5.sp, color = Qs.muted))
                Gap(14.dp)
                Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Qs.base).border(1.dp, Qs.brass, RoundedCornerShape(14.dp)).padding(14.dp)) {
                    Text(key, style = T.monoLarge.copy(fontSize = 15.sp, lineHeight = 24.sp, color = Qs.ivory), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                }
                Gap(10.dp)
                Text("انسخ", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable {
                    clipboard.setText(AnnotatedString(key))
                    Toast.makeText(context, "نُسخ. احذفه من الحافظة بعد حفظه في مكان آمن.", Toast.LENGTH_LONG).show()
                }.padding(vertical = 6.dp))
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text("حفظته في مكان آمن", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) } },
    )
}

// ------------------------------------------------------------------ QsCrypt protection options

/** Every option starts off; switching a destructive one on asks first. */
class Protection {
    var offlineOnly by mutableStateOf(false)
    var offlineDestroy by mutableStateOf(true)
    var expiry by mutableStateOf(false)
    var expiryDays by mutableStateOf("7")
    var expiryDestroy by mutableStateOf(true)
    var openOnce by mutableStateOf(false)
    var attempts by mutableStateOf(false)
    var attemptsN by mutableStateOf("5")
    var autoOpen by mutableStateOf(false)
    var duress by mutableStateOf(false)
    var duressPassword by mutableStateOf("")
    var recovery by mutableStateOf(false)
    var sign by mutableStateOf(false)
    val recipients = mutableStateListOf<Contact>()
    var includeMe by mutableStateOf(true)

    fun policy(): JSONObject {
        val p = JSONObject()
        if (offlineOnly) p.put("offlineOnly", if (offlineDestroy) "destroy" else "refuse")
        if (expiry) {
            val days = expiryDays.toLongOrNull()?.coerceIn(1, 3650) ?: 7
            p.put("expires", System.currentTimeMillis() / 1000 + days * 86_400).put("expiresAction", if (expiryDestroy) "destroy" else "refuse")
        }
        if (openOnce) p.put("openOnce", true)
        if (attempts) p.put("maxAttempts", attemptsN.toIntOrNull()?.coerceIn(1, 50) ?: 5).put("attemptsAction", "destroy")
        if (autoOpen) p.put("autoOpen", true)
        return p
    }

    fun summary(): List<String> = buildList {
        if (recipients.isNotEmpty()) add("مربوط بـ ${recipients.joinToString("، ") { it.name }}")
        if (offlineOnly) add(if (offlineDestroy) "يُتلف إن فُتح مع إنترنت" else "لا يُفتح مع إنترنت")
        if (expiry) add("صالح ${expiryDays} يوم")
        if (openOnce) add("يُفتح مرة واحدة")
        if (attempts) add("يُتلف بعد ${attemptsN} محاولات خاطئة")
        if (duress) add("كلمة مرور طوارئ")
        if (recovery) add("مفتاح استرداد")
        if (sign) add("موقّع باسمك")
        if (autoOpen) add("فتح تلقائي")
    }
}

private data class Risk(val title: String, val text: String)

@Composable
private fun ProtectionRow(icon: Int, title: String, desc: String, checked: Boolean, destroys: Boolean, risk: Risk?, enabled: Boolean = true, onChange: (Boolean) -> Unit, extra: @Composable () -> Unit = {}) {
    var ask by remember { mutableStateOf(false) }
    var explain by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Tile(icon, if (checked) Qs.brass else Qs.muted, size = 40.dp, radius = 13.dp, iconSize = 20.dp)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f).clickable { explain = true }, verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(title, style = T.item)
                    if (destroys) {
                        Spacer(Modifier.width(8.dp))
                        Tag("إتلاف", TagKind.Coral)
                    }
                }
                Text(desc, style = T.small)
            }
            Spacer(Modifier.width(8.dp))
            QsSwitch(checked, enabled = enabled) { on -> if (on && risk != null) ask = true else onChange(on) }
        }
        if (checked) extra()
    }
    if (ask && risk != null) {
        DangerConfirm(risk.title, risk.text, "فهمت، فعّلها", { ask = false; onChange(true) }, { ask = false })
    }
    if (explain && risk != null) {
        QsAlert(risk.title, risk.text, "حسناً", { explain = false }, { explain = false }, dismiss = null)
    }
}

@Composable
private fun SmallNumber(value: String, suffix: String, onChange: (String) -> Unit) {
    Row(Modifier.padding(start = 52.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        QsField(value = value, onValueChange = { v -> onChange(v.filter { it.isDigit() }.take(4)) }, placeholder = "", keyboardType = KeyboardType.Number, height = 40.dp, modifier = Modifier.width(84.dp), textStyle = T.monoLarge)
        Spacer(Modifier.width(10.dp))
        Text(suffix, style = T.small.copy(color = Qs.ivory))
    }
}

@Composable
private fun ActionChoice(destroy: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.padding(start = 52.dp, top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Chip("إتلاف الملف", destroy) { onChange(true) }
        Chip("رفض الفتح فقط", !destroy) { onChange(false) }
    }
}

/** QsCrypt options: who can open it, and policies. `container` hides file-only ones. */
@Composable
fun ProtectionEditor(p: Protection, container: Boolean, hasIdentity: Boolean, hasPassword: Boolean) {
    val contacts = remember { Prefs.contacts() }
    var pickContacts by remember { mutableStateOf(false) }
    Text("من يستطيع الفتح", style = T.label)
    Gap(8.dp)
    QsCard(onClick = { pickContacts = true }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Tile(R.drawable.ic_users, if (p.recipients.isEmpty()) Qs.muted else Qs.brass, size = 40.dp, radius = 13.dp, iconSize = 20.dp)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(if (p.recipients.isEmpty()) "ربط بجهات اتصال (اختياري)" else p.recipients.joinToString("، ") { it.name }, style = T.item, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(
                    when {
                        p.recipients.isEmpty() -> "يفتحه من يعرف كلمة المرور"
                        hasPassword -> "يفتحه هؤلاء بهواتفهم دون كلمة مرور، أو أي شخص بكلمة المرور"
                        else -> "لا يفتحه إلا هؤلاء بهواتفهم (X25519 + ML-KEM-768)"
                    },
                    style = T.small,
                )
            }
            QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
        }
    }
    if (p.recipients.isNotEmpty() && hasIdentity) {
        OptionRow(R.drawable.ic_shield, "أنا أيضاً", "أستطيع فتحه بهاتفي") { QsSwitch(p.includeMe) { p.includeMe = it } }
    }
    Gap(18.dp)
    Text("مزايا الحماية", style = T.label)
    Gap(4.dp)
    Text("كلها مطفأة افتراضياً. اضغط على أي ميزة لقراءة عواقبها.", style = T.small)
    Gap(10.dp)
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(Qs.surface)) {
        ProtectionRow(R.drawable.ic_wifioff, "بلا إنترنت فقط", "لا يُفتح والجهاز متصل بالشبكة", p.offlineOnly, p.offlineDestroy,
            Risk("بلا إنترنت فقط", "إن فُتح والجهاز متصل بالواي فاي أو البيانات، يُتلف الملف فوراً (أو يُرفض فتحه، حسب اختيارك). الإتلاف نهائي ولا رجعة فيه، حتى لو كان الاتصال غير مقصود. تنفّذ هذه السياسة تطبيقات QsCrypt فقط."),
            onChange = { p.offlineOnly = it }) { ActionChoice(p.offlineDestroy) { p.offlineDestroy = it } }
        Line()
        ProtectionRow(R.drawable.ic_clock, "مدة صلاحية", "لا يُفتح بعد مدة تحددها", p.expiry, p.expiryDestroy,
            Risk("مدة الصلاحية", "بعد انتهاء المدة لا يُفتح الملف، ويُتلف إن اخترت ذلك. إرجاع ساعة الجهاز إلى الوراء يُكتشف ويُعامل كانتهاء للصلاحية."),
            onChange = { p.expiry = it }) {
            SmallNumber(p.expiryDays, "يوماً من الآن") { p.expiryDays = it }
            ActionChoice(p.expiryDestroy) { p.expiryDestroy = it }
        }
        if (!container) {
            Line()
            ProtectionRow(R.drawable.ic_eye, "فتح لمرة واحدة", "يُتلف بعد أول فتح ناجح", p.openOnce, true,
                Risk("فتح لمرة واحدة", "بعد أول فك ناجح يُتلف الملف المشفّر على ذلك الجهاز ويُسجَّل فيه كمستهلك. النسخ الأخرى من الملف المشفّر على أجهزة أخرى تبقى قابلة للفتح، فلا ترسله إلا مرة واحدة."),
                onChange = { p.openOnce = it })
        }
        Line()
        ProtectionRow(R.drawable.ic_key, "عدد المحاولات", "إتلاف بعد محاولات خاطئة متتالية", p.attempts, true,
            Risk("عدد المحاولات", "بعد هذا العدد من كلمات المرور الخاطئة على هاتف واحد يُتلف الملف. يحمي من التخمين، لكن صاحب الحق قد يُتلفه بنفسه إن أخطأ مرات كثيرة."),
            onChange = { p.attempts = it }) { SmallNumber(p.attemptsN, "محاولات") { p.attemptsN = it } }
        Line()
        ProtectionRow(R.drawable.ic_shield, "كلمة مرور الطوارئ", "تُتلف البيانات بصمت إن أُعطيت تحت الإكراه", p.duress, true,
            Risk("كلمة مرور الطوارئ", "كلمة ثانية تبدو كأنها كلمة المرور: إن أُدخلت يُتلف الملف بصمت وتظهر رسالة «كلمة مرور خاطئة». لا شيء في الملف يكشف وجودها."),
            enabled = hasPassword, onChange = { p.duress = it }) {
            Gap(8.dp)
            Box(Modifier.padding(start = 52.dp)) {
                QsField(value = p.duressPassword, onValueChange = { p.duressPassword = it }, placeholder = "كلمة مرور الطوارئ", password = true, height = 48.dp)
            }
        }
        Line()
        ProtectionRow(R.drawable.ic_archive, "مفتاح استرداد", "مفتاح من 32 حرفاً يفتحه إن نُسيت كلمة المرور", p.recovery, false, null, onChange = { p.recovery = it })
        if (!container) {
            Line()
            ProtectionRow(R.drawable.ic_check, "توقيع باسمي", "يعرف المستلم أن الملف منك ولم يُعدَّل", p.sign, false, null, enabled = hasIdentity, onChange = { p.sign = it })
            Line()
            ProtectionRow(R.drawable.ic_unlock, "الفتح التلقائي", "بعد أول فتح ناجح على هاتف المستلم", p.autoOpen, false,
                Risk("الفتح التلقائي", "بعد أول فتح يحفظ هاتف المستلم مفتاح الملف في مخزن مفاتيح أندرويد، فيفتحه لاحقاً دون كلمة مرور. من يمسك الهاتف مفتوحاً يستطيع فتح الملف."),
                onChange = { p.autoOpen = it })
        }
    }
    if (pickContacts) {
        ContactsPickerDialog(contacts, p.recipients) { pickContacts = false }
    }
}

@Composable
private fun Line() = Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))

@Composable
fun ContactsPickerDialog(all: List<Contact>, chosen: SnapshotStateList<Contact>, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        containerColor = Qs.surface,
        title = { Text("اختر جهات الاتصال", style = T.title) },
        text = {
            Column {
                if (all.isEmpty()) {
                    Text("لا توجد جهات اتصال بعد. أضفها من تبويب «جهات الاتصال» بمسح رمز QR.", style = T.body.copy(color = Qs.muted))
                }
                all.forEach { c ->
                    val on = chosen.any { it.fingerprint == c.fingerprint }
                    Row(Modifier.fillMaxWidth().clickable { if (on) chosen.removeAll { it.fingerprint == c.fingerprint } else chosen.add(c) }.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(22.dp).clip(RoundedCornerShape(6.dp)).border(2.dp, if (on) Qs.brass else Qs.muted, RoundedCornerShape(6.dp)).background(if (on) Qs.brass else Qs.surface), contentAlignment = Alignment.Center) {
                            if (on) QsIcon(R.drawable.ic_check, Qs.base, 14.dp)
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(c.name, style = T.item)
                            Text(c.safety, style = T.mono)
                        }
                        if (c.verified) Tag("موثّق", TagKind.Brass)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text("تم", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) } },
    )
}

/** A small round status dot with text, for result summaries. */
@Composable
fun StatusLine(ok: Boolean, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 3.dp)) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(if (ok) Qs.mint else Qs.coral))
        Spacer(Modifier.width(8.dp))
        Text(text, style = T.small.copy(color = Qs.ivory))
    }
}
