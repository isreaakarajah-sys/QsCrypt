package com.qscrypt.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val MENU = 0
private const val CHANGE = 1
private const val BACKUP = 2
private const val RESTORE = 3

/** Runs a header call on the volume's disk (its file, read-write, or its USB drive). */
private fun onDisk(context: android.content.Context, s: Session, call: Call): Reply {
    s.usb?.let { return call.srcUsb(it).run() }
    val pfd = Saf.open(context, Uri.parse(s.container.uri), "rw") ?: return Reply("""{"ok":false,"code":"read_only","message":"read only"}""")
    return pfd.use { call.src(it.fd).run() }
}

/** Password, keyfiles and PIM maintenance for VeraCrypt and TrueCrypt volumes. */
@Composable
fun VaultTools(session: Session, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by remember { mutableIntStateOf(MENU) }
    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    val keyfiles = remember { mutableStateListOf<Keyfile>() }
    var newPassword by remember { mutableStateOf("") }
    var newConfirm by remember { mutableStateOf("") }
    var newPim by remember { mutableStateOf("") }
    val newKeyfiles = remember { mutableStateListOf<Keyfile>() }
    var hiddenPassword by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var done by remember { mutableStateOf<String?>(null) }
    val tc = session.info.format == "TrueCrypt"

    fun credentials(c: Call): Call = c.put("pim", pim.toIntOrNull() ?: 0)
        .blob("password", password.toByteArray(Charsets.UTF_8)).blob("keyfiles", packKeyfiles(context, keyfiles))

    fun perform(work: suspend () -> Reply, success: (Reply) -> String) {
        busy = true
        error = null
        scope.launch {
            val r = withContext(Dispatchers.IO) { work() }
            busy = false
            if (r.ok) {
                password = ""
                newPassword = ""
                newConfirm = ""
                hiddenPassword = ""
                done = success(r)
            } else if (r.code != "cancelled") {
                error = r.error
            }
        }
    }

    val backupSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { out ->
        out ?: return@rememberLauncherForActivityResult
        perform({
            val r = Saf.open(context, out, "w")?.use { o ->
                onDisk(context, session, credentials(Call("volume.backupHeader")).fd("out", o.fd)
                    .blob("hiddenPassword", hiddenPassword.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8)))
            } ?: Reply("""{"ok":false,"code":"io","message":"open"}""")
            if (!r.ok) Saf.delete(context, out)
            r
        }) {
            "حُفظت نسخة الترويسات (128 KB). احفظها بعيداً عن الحاوية: تُصلح الحاوية إن تلفت ترويستها، وتفتحها بكلمة المرور القديمة."
        }
    }
    val restorePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { src ->
        src ?: return@rememberLauncherForActivityResult
        perform({
            Saf.open(context, src, "r")?.use { i ->
                onDisk(context, session, credentials(Call("volume.restoreHeader")).put("embedded", false).fd("in", i.fd))
            } ?: Reply("""{"ok":false,"code":"io","message":"open"}""")
        }) { r -> if (r.json.optBoolean("hidden")) "استُعيدت ترويسة المجلد المخفي من الملف." else "استُعيدت الترويسة من الملف." }
    }

    val title = when (step) {
        CHANGE -> "تغيير كلمة المرور"
        BACKUP -> "نسخة احتياطية للترويسة"
        RESTORE -> "استعادة الترويسة"
        else -> "أدوات الحاوية"
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        containerColor = Qs.surface,
        title = { Text(title, style = T.title) },
        text = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                if (done != null) {
                    Note(done!!, icon = R.drawable.ic_check, color = Qs.mint)
                    return@Column
                }
                if (step == MENU) {
                    Text("تعمل على الحاوية مباشرة، ولا تمسّ ملفاتك.", style = T.small)
                    Gap(12.dp)
                    ToolOption(R.drawable.ic_key, "تغيير كلمة المرور", "أو ملفات المفاتيح أو PIM") { step = CHANGE }
                    ToolOption(R.drawable.ic_download, "نسخة احتياطية للترويسة", "ملف صغير يُصلح الحاوية إن تلفت") { step = BACKUP }
                    ToolOption(R.drawable.ic_archive, "استعادة الترويسة", "من النسخة المضمّنة في الحاوية أو من ملف") { step = RESTORE }
                    return@Column
                }
                Text("كلمة المرور الحالية", style = T.label)
                Gap(6.dp)
                QsField(value = password, onValueChange = { password = it; error = null }, placeholder = "••••••••", password = true, height = 50.dp)
                if (!tc) {
                    Gap(6.dp)
                    QsField(value = pim, onValueChange = { v -> pim = v.filter { it.isDigit() }.take(7) }, placeholder = "PIM الحالي (إن وُجد)", keyboardType = KeyboardType.NumberPassword, height = 46.dp)
                }
                KeyfilesRow(keyfiles, "ملفات المفاتيح الحالية")
                when (step) {
                    CHANGE -> {
                        Gap(10.dp)
                        Text("الجديدة", style = T.label)
                        Gap(6.dp)
                        QsField(value = newPassword, onValueChange = { newPassword = it }, placeholder = "كلمة المرور الجديدة", password = true, height = 50.dp)
                        Gap(6.dp)
                        QsField(value = newConfirm, onValueChange = { newConfirm = it }, placeholder = "تأكيدها", password = true, height = 50.dp)
                        if (newConfirm.isNotEmpty() && newConfirm != newPassword) Text("غير متطابقتين", style = T.small.copy(color = Qs.coral))
                        if (!tc) {
                            Gap(6.dp)
                            QsField(value = newPim, onValueChange = { v -> newPim = v.filter { it.isDigit() }.take(5) }, placeholder = "PIM الجديد (اختياري)", keyboardType = KeyboardType.NumberPassword, height = 46.dp)
                        }
                        KeyfilesRow(newKeyfiles, "ملفات المفاتيح الجديدة")
                        Gap(6.dp)
                        Text("بكلمة مرور المجلد المخفي تُغيَّر كلمته هو. النسخ الاحتياطية القديمة للترويسة تبقى تفتح بالكلمة القديمة.", style = T.small)
                    }
                    BACKUP -> {
                        Gap(10.dp)
                        QsField(value = hiddenPassword, onValueChange = { hiddenPassword = it }, placeholder = "كلمة المجلد المخفي (إن وُجد)", password = true, height = 50.dp)
                        Gap(6.dp)
                        Text("تُحفظ ترويستا الحاوية العادية والمخفية معاً، كما يفعل VeraCrypt.", style = T.small)
                    }
                    RESTORE -> {
                        Gap(10.dp)
                        Text("إن تلفت بداية الحاوية فالترويسة الاحتياطية المضمّنة في آخرها تُصلحها.", style = T.small)
                    }
                }
                error?.let {
                    Gap(10.dp)
                    Note(it, icon = R.drawable.ic_alert, color = Qs.coral)
                }
            }
        },
        confirmButton = {
            when {
                done != null || step == MENU -> TextButton(onClick = onDismiss) { Text("إغلاق", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                busy -> TextButton(onClick = {}, enabled = false) { Text("جاري العمل…", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) }
                step == CHANGE -> TextButton(
                    enabled = (password.isNotEmpty() || keyfiles.isNotEmpty()) && (newPassword.isNotEmpty() || newKeyfiles.isNotEmpty()) && newPassword == newConfirm,
                    onClick = {
                        perform({
                            onDisk(
                                context, session,
                                credentials(Call("volume.changePassword")).put("prf", 0)
                                    .put("newPim", if (tc) 0 else newPim.toIntOrNull() ?: 0)
                                    .put("newPrf", 1)
                                    .blob("newPassword", newPassword.toByteArray(Charsets.UTF_8))
                                    .blob("newKeyfiles", packKeyfiles(context, newKeyfiles)),
                            )
                        }) { r -> if (r.json.optBoolean("hidden")) "تغيّرت كلمة مرور المجلد المخفي." else "تغيّرت كلمة المرور. استخدم الجديدة من الآن." }
                    },
                ) { Text("غيّر", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                step == BACKUP -> TextButton(enabled = password.isNotEmpty() || keyfiles.isNotEmpty(), onClick = {
                    AppState.pickerOpen = true
                    backupSaver.launch(session.container.name + ".header-backup")
                }) { Text("احفظ النسخة", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                else -> Row {
                    TextButton(enabled = password.isNotEmpty() || keyfiles.isNotEmpty(), onClick = {
                        AppState.pickerOpen = true
                        restorePicker.launch(arrayOf("*/*"))
                    }) { Text("من ملف", style = T.button.copy(color = Qs.ivory, fontSize = 15.sp)) }
                    TextButton(enabled = password.isNotEmpty() || keyfiles.isNotEmpty(), onClick = {
                        perform({ onDisk(context, session, credentials(Call("volume.restoreHeader")).put("embedded", true)) }) { "أُصلحت الترويسة من النسخة المضمّنة." }
                    }) { Text("المضمّنة", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                }
            }
        },
        dismissButton = {
            if (done == null && step != MENU && !busy) TextButton(onClick = { step = MENU; error = null }) { Text("رجوع", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) }
        },
    )
}

@Composable
private fun ToolOption(icon: Int, title: String, sub: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(14.dp)).background(Qs.surface2).clickable(onClick = onClick).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QsIcon(icon, Qs.brass, 22.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = T.item)
            Text(sub, style = T.small)
        }
    }
}
