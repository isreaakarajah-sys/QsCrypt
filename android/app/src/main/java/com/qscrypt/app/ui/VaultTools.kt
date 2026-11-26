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
import com.qscrypt.app.Fill
import com.qscrypt.app.Jobs
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
private const val CHECK = 4

/** The engine's file-system check, as words. */
private fun checkSummary(j: org.json.JSONObject): List<String> {
    val out = mutableListOf<String>()
    fun n(k: String) = j.optLong(k)
    if (n("lostClusters") > 0) out += "${n("lostClusters")} وحدة تخزين محجوزة لا يملكها ملف (مساحة ضائعة)"
    if (n("crossLinked") > 0) out += "${n("crossLinked")} وحدة يتشاركها أكثر من ملف"
    if (n("badChains") > 0) out += "${n("badChains")} سلسلة ملفات مقطوعة"
    if (n("sizeMismatches") > 0) out += "${n("sizeMismatches")} ملف حجمه لا يطابق مساحته"
    if (n("bitmapErrors") > 0) out += "${n("bitmapErrors")} خطأ في خريطة المساحة"
    if (n("checksumErrors") > 0) out += "${n("checksumErrors")} خطأ في المجموع الاختباري للمجلدات"
    if (j.optBoolean("freeCountWrong")) out += "عدّاد المساحة الحرة غير دقيق"
    if (n("unreadable") > 0) out += "${n("unreadable")} ملف تعذّرت قراءته"
    return out
}

/** Runs a header call on the volume's disk (its file, read-write, or its USB drive). */
private fun onDisk(context: android.content.Context, s: Session, call: Call): Reply {
    s.usb?.let { return call.srcUsb(it).run() }
    val pfd = Saf.open(context, Uri.parse(s.container.uri), "rw") ?: return Reply("""{"ok":false,"code":"read_only","message":"read only"}""")
    return pfd.use { call.src(it.fd).run() }
}

/**
 * Maintenance for every vault (check and repair, read every file, fill the
 * free space), and password, keyfiles and PIM tools for VeraCrypt and
 * TrueCrypt volumes. Long operations become background jobs (`onJob`).
 */
@Composable
fun VaultTools(session: Session, onJob: (Jobs.Job) -> Unit, onDismiss: () -> Unit) {
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
    var report by remember { mutableStateOf<org.json.JSONObject?>(null) }
    val tc = session.info.format == "TrueCrypt"
    val headers = session.info.format == "VeraCrypt" || session.info.format == "TrueCrypt"
    val canRepair = !session.info.readOnly && !session.info.protected

    fun runCheck(repair: Boolean) {
        busy = true
        error = null
        scope.launch {
            val r = withContext(Dispatchers.IO) { Call("vault.check").put("handle", session.handle).put("repair", repair).run() }
            busy = false
            if (r.ok) {
                // After a repair, check again so the report shows what is left.
                if (repair) {
                    val again = withContext(Dispatchers.IO) { Call("vault.check").put("handle", session.handle).run() }
                    report = (if (again.ok) again.json else r.json).put("repairedNow", r.json.optLong("repaired"))
                } else {
                    report = r.json
                }
            } else {
                error = r.error
            }
        }
    }

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
        CHECK -> "فحص الخزنة"
        else -> "أدوات الخزنة"
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
                    Text("الصيانة", style = T.label)
                    Gap(6.dp)
                    ToolOption(R.drawable.ic_check, "فحص الخزنة وإصلاحها", "يكشف أخطاء نظام الملفات ويصلحها دون مساس بملفاتك") {
                        step = CHECK
                        runCheck(false)
                    }
                    ToolOption(R.drawable.ic_eye, "قراءة كل الملفات", "يتأكد أن كل ملف يُقرأ كاملاً دون أخطاء (يستغرق وقتاً)") {
                        val j = Jobs.start(context, "check", "قراءة كل ملفات «${session.container.name.substringBeforeLast('.')}»", listOf(session.handle)) work@{
                            detail("تُقرأ الملفات واحداً واحداً للتحقق منها")
                            val r = Call("vault.check").put("handle", session.handle).put("deep", true).run(progress())
                            if (!r.ok) return@work r
                            val issues = checkSummary(r.json)
                            Reply(org.json.JSONObject().put("ok", true).put("summary", if (issues.isEmpty()) "كل الملفات (${r.json.optLong("files")}) تُقرأ سليمة." else issues.joinToString("، ")).toString())
                        }
                        onDismiss()
                        onJob(j)
                    }
                    if (Fill.possible(session)) {
                        val running = Fill.running(session)
                        ToolOption(
                            R.drawable.ic_shield,
                            if (running != null) "ملء المساحة الفارغة (يعمل الآن)" else if (Fill.pending(session)) "متابعة ملء المساحة الفارغة" else "ملء المساحة الفارغة",
                            "بيانات مشفّرة في كل فراغ الخزنة، فلا يُعرف حجم ما فيها. يعمل في الخلفية ويُستأنف",
                        ) {
                            val j = running ?: Fill.schedule(context, session)
                            onDismiss()
                            j?.let(onJob)
                        }
                    }
                    if (headers) {
                        Gap(10.dp)
                        Text("الترويسة وكلمة المرور", style = T.label)
                        Gap(6.dp)
                        ToolOption(R.drawable.ic_key, "تغيير كلمة المرور", "أو ملفات المفاتيح أو PIM") { step = CHANGE }
                        ToolOption(R.drawable.ic_download, "نسخة احتياطية للترويسة", "ملف صغير يُصلح الحاوية إن تلفت") { step = BACKUP }
                        ToolOption(R.drawable.ic_archive, "استعادة الترويسة", "من النسخة المضمّنة في الحاوية أو من ملف") { step = RESTORE }
                    }
                    return@Column
                }
                if (step == CHECK) {
                    val rep = report
                    when {
                        busy -> Row(verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.padding(4.dp))
                            Spacer(Modifier.width(10.dp))
                            Text("يُفحص نظام الملفات…", style = T.body)
                        }
                        rep != null -> {
                            val issues = checkSummary(rep)
                            val repairedNow = rep.optLong("repairedNow")
                            if (repairedNow > 0) {
                                Note("أُصلح $repairedNow ${if (repairedNow == 1L) "خطأ" else "أخطاء"}.", icon = R.drawable.ic_check, color = Qs.mint)
                                Gap(8.dp)
                            }
                            if (issues.isEmpty()) {
                                Note("الخزنة سليمة: ${rep.optLong("files")} ملفاً في ${rep.optLong("dirs")} مجلداً.", icon = R.drawable.ic_shield, color = Qs.mint)
                            } else {
                                Note("وُجدت مشكلات:", icon = R.drawable.ic_alert, color = Qs.coral)
                                Gap(6.dp)
                                issues.forEach { Text("• $it", style = T.small.copy(color = Qs.ivory)) }
                                val details = rep.optJSONArray("issues")
                                if (details != null && details.length() > 0) {
                                    Gap(8.dp)
                                    for (i in 0 until minOf(details.length(), 8)) Text(details.optString(i), style = T.mono.copy(fontSize = 11.sp))
                                }
                                Gap(8.dp)
                                Text(
                                    if (canRepair) "الإصلاح آمن: يحرّر المساحة الضائعة ويصحّح العدّادات، ولا يحذف ملفاً سليماً. يُفضّل تصدير الملفات المهمة قبله." else "الخزنة مفتوحة للقراءة فقط أو المخفي محمي، فلا يمكن الإصلاح الآن.",
                                    style = T.small,
                                )
                            }
                        }
                    }
                    error?.let {
                        Gap(10.dp)
                        Note(it, icon = R.drawable.ic_alert, color = Qs.coral)
                    }
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
                step == CHECK -> {
                    val rep = report
                    if (!busy && rep != null && checkSummary(rep).isNotEmpty() && canRepair) {
                        TextButton(onClick = { runCheck(true) }) { Text("أصلح", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                    } else {
                        TextButton(onClick = onDismiss, enabled = !busy) { Text("إغلاق", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
                    }
                }
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
