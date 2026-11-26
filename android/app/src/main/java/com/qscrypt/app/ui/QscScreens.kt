package com.qscrypt.app.ui

import android.content.Context
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Jobs
import com.qscrypt.app.Call
import com.qscrypt.app.Container
import com.qscrypt.app.FileKeys
import com.qscrypt.app.Identity
import com.qscrypt.app.Prefs
import com.qscrypt.app.Progress
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.humanSize
import com.qscrypt.app.policyText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

private data class Picked(val uri: Uri, val name: String, val size: Long)

private fun ioError(what: String) = Reply("""{"ok":false,"code":"io","message":"$what"}""")

/** Who signed a file, from the signer's Ed25519 key (hex). */
fun signerName(context: Context, signKey: String): String? {
    if (signKey.isEmpty()) return null
    if (Identity.public(context)?.optString("signKey").equals(signKey, ignoreCase = true)) return "أنت"
    return Prefs.contacts().firstOrNull { it.signKey.equals(signKey, ignoreCase = true) }?.name
}

fun dateText(seconds: Long): String = SimpleDateFormat("d MMMM yyyy، HH:mm", Locale("ar")).format(Date(seconds * 1000))

/** Short descriptions of a QsCrypt file's policy, for tags. */
fun policyTags(p: JSONObject?): List<Pair<String, TagKind>> = buildList {
    p ?: return@buildList
    if (p.optBoolean("signed")) add("موقّع" to TagKind.Mint)
    p.optInt("recipients").takeIf { it > 0 }?.let { add("لـ $it من جهات الاتصال" to TagKind.Brass) }
    if (p.optBoolean("recovery")) add("مفتاح استرداد" to TagKind.Outline)
    if (p.optBoolean("openOnce")) add("مرة واحدة" to TagKind.Coral)
    if (p.has("offlineOnly")) add("بلا إنترنت" to TagKind.Coral)
    if (p.has("expires")) add("حتى ${dateText(p.optLong("expires"))}" to TagKind.Coral)
    p.optInt("maxAttempts").takeIf { it > 0 }?.let { add("$it محاولات" to TagKind.Coral) }
    if (p.optBoolean("autoOpen")) add("فتح تلقائي" to TagKind.Outline)
}

// ------------------------------------------------------------------ encrypt files

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun QscEncryptScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by remember { mutableIntStateOf(2) }
    val files = remember { mutableStateListOf<Picked>() }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val protection = remember { Protection() }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var recovery by remember { mutableStateOf<String?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    val hasIdentity = remember { Identity.exists(context) }
    val passwordOk = password == confirm && (password.isNotEmpty() || protection.recipients.isNotEmpty())
    val duressOk = !protection.duress || (protection.duressPassword.isNotEmpty() && protection.duressPassword != password)

    BackHandler(enabled = step == 3) { step = 2 }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        for (u in uris) {
            if (files.none { it.uri == u }) {
                val m = Saf.meta(context, u)
                files.add(Picked(u, m.name, m.size))
            }
        }
    }

    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    // Files shared from another app with "encrypt as QsCrypt files".
    LaunchedEffect(Unit) {
        val preset = AppState.encryptShared
        AppState.encryptShared = emptyList()
        for (u in preset) if (files.none { it.uri == u }) Saf.meta(context, u).let { m -> files.add(Picked(u, m.name, m.size)) }
    }

    val folder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        if (tree == null) return@rememberLauncherForActivityResult
        val pw = password.toByteArray(Charsets.UTF_8)
        val batch = files.toList()
        val duress = if (protection.duress && protection.duressPassword.isNotEmpty()) protection.duressPassword.toByteArray(Charsets.UTF_8) else null
        val sign = protection.sign && hasIdentity
        val wantRecovery = protection.recovery
        val cards = recipientCards(context, protection)
        val policy = protection.policy()
        val summary = protection.summary()
        var key = ""
        // A background job: it can be paused, resumed, and keeps going if you leave this screen.
        job = Jobs.start(
            context, "encrypt",
            if (batch.size == 1) "تشفير «${batch[0].name}»" else "تشفير ${batch.size} ملفات",
            onEnd = { j ->
                if (j.state == Jobs.State.Done) {
                    password = ""
                    confirm = ""
                    files.clear()
                    step = 2
                    if (key.isNotEmpty()) recovery = key
                }
            },
        ) work@{
            try {
                // One recovery key and one policy for the whole batch.
                if (wantRecovery) key = Call("qsc.recoveryKey").run().json.optString("key")
                val total = batch.sumOf { it.size.coerceAtLeast(0) }
                this@work.job.total = total
                var base = 0L
                var done = 0
                for ((i, f) in batch.withIndex()) {
                    if (!checkpoint()) return@work Reply("""{"ok":false,"code":"cancelled"}""")
                    detail("${i + 1}/${batch.size} · ${f.name}")
                    val out = Saf.createInTree(context, tree, f.name + ".qsc") ?: return@work ioError("create")
                    val input = Saf.open(context, f.uri, "r")
                    val output = Saf.open(context, out, "w")
                    if (input == null || output == null) {
                        input?.close()
                        output?.close()
                        Saf.delete(context, out)
                        return@work ioError("open")
                    }
                    val call = Call("qsc.encrypt").put("size", f.size).put("name", f.name)
                        .put("mtime", System.currentTimeMillis() / 1000).put("now", System.currentTimeMillis() / 1000)
                        .put("policy", policy).put("recipients", cards)
                        .blob("password", if (pw.isNotEmpty()) pw.copyOf() else null)
                        .blob("recoveryKey", if (key.isNotEmpty()) key.toByteArray() else null)
                    if (duress != null) call.blob("duress", duress.copyOf())
                    if (sign) call.put("sign", true).blob("identity", Identity.secret(context))
                    val reply = input.use { inp -> output.use { o -> call.fd("in", inp.fd).fd("out", o.fd).run(progress(base, total)) } }
                    if (!reply.ok) {
                        Saf.delete(context, out)
                        return@work Reply(reply.json.put("message", "«${f.name}»: " + reply.json.optString("message")).toString())
                    }
                    base += f.size.coerceAtLeast(0)
                    done++
                }
                val text = "تم تشفير $done ${if (done == 1) "ملف" else "ملفات"} بصيغة QsCrypt." +
                    (if (summary.isNotEmpty()) " " + summary.joinToString(" · ") else "") +
                    " الملفات الأصلية لم تُحذف؛ احذفها بنفسك إن لم تعد تحتاجها."
                Reply(JSONObject().put("ok", true).put("summary", text).toString())
            } finally {
                pw.fill(0)
                duress?.fill(0)
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Gap(20.dp)
            TopBar(if (step == 2) "تشفير ملفات" else "من يفتح، ومزايا الحماية", onBack = { if (step == 3) step = 2 else AppState.pop() }) {
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
                Gap(8.dp)
                Text("يمكن ترك كلمة المرور فارغة إن ربطت الملفات بجهات اتصال في الخطوة التالية.", style = T.small)
            } else {
                ProtectionEditor(protection, container = false, hasIdentity = hasIdentity, hasPassword = password.isNotEmpty())
                val summary = protection.summary()
                if (summary.isNotEmpty()) {
                    Gap(14.dp)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        summary.forEach { Tag(it, TagKind.Outline) }
                    }
                }
                if (!passwordOk) {
                    Gap(10.dp)
                    Note("أدخل كلمة مرور في الخطوة السابقة، أو اختر جهة اتصال واحدة على الأقل.", icon = R.drawable.ic_alert, color = Qs.coral)
                }
            }
            Gap(20.dp)
        }
        if (step == 2) {
            PrimaryButton("التالي", enabled = files.isNotEmpty() && password == confirm) { step = 3 }
        } else {
            PrimaryButton("اختر مكان الحفظ وشفّر", icon = R.drawable.ic_lock, enabled = files.isNotEmpty() && passwordOk && duressOk) {
                AppState.pickerOpen = true
                folder.launch(null)
            }
        }
        Gap(24.dp)
    }
    job?.let { j -> JobDialog(j, onClose = { job = null }) }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = { cancel.set(true) }) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
    recovery?.let { k ->
        RecoveryKeyDialog("مفتاح الاسترداد", k, "مفتاح واحد يفتح كل الملفات التي شفّرتها الآن إن نُسيت كلمة المرور. احفظه بعيداً عنها.") { recovery = null }
    }
}

// ------------------------------------------------------------------ decrypt a file

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun QscDecryptScreen(uriString: String, name: String, size: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val uri = remember(uriString) { Uri.parse(uriString) }
    val asContainer = remember(uriString) { Container(uriString, name, size, 0L) }
    var password by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf("password") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var checking by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var policy by remember { mutableStateOf<JSONObject?>(null) }
    var version by remember { mutableIntStateOf(0) }
    var unreadable by remember { mutableStateOf(false) }
    val cancel = remember { AtomicBoolean(false) }
    val hasIdentity = remember { Identity.exists(context) }
    val fileId = policy?.optString("fileId").orEmpty()
    val burned = fileId.isNotEmpty() && Prefs.burned(fileId)
    val recipients = policy?.optInt("recipients") ?: 0

    LaunchedEffect(uriString) {
        val r = withContext(Dispatchers.IO) { Saf.open(context, uri, "r")?.use { Call("qsc.inspect").fd("in", it.fd).run() } }
        if (r == null || !r.ok) {
            unreadable = true
            return@LaunchedEffect
        }
        version = r.json.optInt("version")
        policy = r.json.optJSONObject("policy")
        val id = policy?.optString("fileId").orEmpty()
        mode = when {
            FileKeys.has(context, id) -> "filekey"
            (policy?.optInt("recipients") ?: 0) > 0 && hasIdentity && (policy?.optInt("passwordSlots") ?: 0) == 0 -> "identity"
            else -> "password"
        }
    }

    fun unlockCall(method: String): Call {
        val c = Call(method).put("unlock", mode).context()
        when (mode) {
            "identity" -> c.blob("identity", Identity.secret(context))
            "filekey" -> c.blob("fileKey", FileKeys.get(context, fileId))
            else -> c.blob("password", password.toByteArray(Charsets.UTF_8))
        }
        return c
    }

    suspend fun destroy() = withContext(Dispatchers.IO) { destroyQsCrypt(context, asContainer, null) }

    /** Common handling of refusals; returns true if the reply was handled. */
    suspend fun refused(r: Reply): Boolean {
        when (r.code) {
            "policy" -> {
                val destroyed = r.json.optString("action") == "destroy"
                if (destroyed) destroy()
                message = policyText(r.json.optString("reason")) + if (destroyed) "\n\nوقد أُتلف الملف تنفيذاً لسياسته." else ""
            }
            "duress" -> {
                destroy()
                error = "كلمة المرور غير صحيحة."
            }
            "wrong_password" -> {
                val max = r.json.optJSONObject("policy")?.optInt("maxAttempts") ?: 0
                if (max > 0 && fileId.isNotEmpty()) {
                    val n = Prefs.attempts(fileId) + 1
                    Prefs.setAttempts(fileId, n)
                    if (n >= max) {
                        destroy()
                        message = "تجاوزت عدد المحاولات المسموح ($max)، فأُتلف الملف تنفيذاً لسياسته."
                    } else {
                        error = "كلمة المرور غير صحيحة. بقيت ${max - n} من $max محاولات قبل الإتلاف."
                    }
                } else {
                    error = if (mode == "identity") "هذا الملف لم يُشفَّر لهويتك." else r.error
                }
            }
            else -> return false
        }
        return true
    }

    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { out ->
        if (out == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        busy = Busy("فك التشفير", 0f, name)
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                val input = Saf.open(context, uri, "r")
                val output = Saf.open(context, out, "w")
                if (input == null || output == null) {
                    input?.close()
                    output?.close()
                    return@withContext ioError("open")
                }
                input.use { i ->
                    output.use { o ->
                        unlockCall("qsc.decrypt").fd("in", i.fd).fd("out", o.fd).run(Progress { d, t ->
                            busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null)
                            !cancel.get()
                        })
                    }
                }
            }
            busy = null
            if (!r.ok) {
                Saf.delete(context, out)
                if (!refused(r)) error = if (r.code == "cancelled") null else r.error
                return@launch
            }
            password = ""
            if (fileId.isNotEmpty()) Prefs.setAttempts(fileId, 0)
            r.json.optString("fileKey").takeIf { it.isNotEmpty() && fileId.isNotEmpty() }?.let { FileKeys.put(context, fileId, it) }
            val lines = mutableListOf("حُفظ «${r.json.optString("name", name)}» (${humanSize(r.json.optLong("size"))}).")
            val p = r.json.optJSONObject("policy")
            if (p?.optBoolean("signed") == true) {
                val who = signerName(context, r.json.optString("signer"))
                lines += when {
                    !r.json.optBoolean("signatureValid") -> "تحذير: التوقيع غير صالح. ربما عُدّل الملف بعد توقيعه."
                    who != null -> "موقّع من $who، ولم يُعدَّل منذ توقيعه."
                    else -> "موقّع بمفتاح ليس في جهات اتصالك. لا تثق بمصدره قبل التحقق."
                }
            }
            if (p?.optBoolean("openOnce") == true && fileId.isNotEmpty()) {
                Prefs.burn(fileId)
                FileKeys.forget(context, fileId)
                val destroyed = destroy()
                lines += if (destroyed) "كان هذا الملف للفتح مرة واحدة، فأُتلفت نسخته المشفّرة." else "كان هذا الملف للفتح مرة واحدة، ولن يفتحه هذا الهاتف مجدداً."
            }
            message = lines.joinToString("\n")
        }
    }

    fun start() {
        if (checking || burned) return
        error = null
        checking = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { Saf.open(context, uri, "r")?.use { unlockCall("qsc.check").fd("in", it.fd).run() } } ?: ioError("open")
            checking = false
            when {
                r.ok -> {
                    AppState.pickerOpen = true
                    saver.launch(name.removeSuffix(".qsc").removeSuffix(".QSC").ifEmpty { "file" })
                }
                !refused(r) -> error = r.error
            }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("فك تشفير ملف", onBack = { AppState.pop() })
        Gap(18.dp)
        QsCard {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_shield, Qs.brass, size = 50.dp, radius = 16.dp, iconSize = 24.dp)
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(name, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(Saf.location(uri), style = T.small, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text(humanSize(size), style = T.mono.copy(fontSize = 12.sp))
                }
                val tags = policyTags(policy)
                if (tags.isNotEmpty()) {
                    Gap(12.dp)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        tags.forEach { (t, k) -> Tag(t, k) }
                    }
                }
            }
        }
        Gap(12.dp)
        when {
            unreadable -> Note("تعذّرت قراءة الملف. ربما نُقل أو أنه ليس ملف QsCrypt سليماً.", icon = R.drawable.ic_alert, color = Qs.coral)
            burned -> Note("هذا الملف للفتح مرة واحدة، وقد فُتح من قبل على هذا الهاتف.", icon = R.drawable.ic_alert, color = Qs.coral)
            version == 1 -> Note("ملف QsCrypt من الإصدار الأول: يُفتح بكلمة المرور فقط.")
            else -> Note("الملف مشفّر بثلاث طبقات (AES ثم Twofish ثم XChaCha20-Poly1305). يُحفظ الأصل في المكان الذي تختاره.")
        }
        if (!burned && !unreadable && version > 0) {
            Gap(20.dp)
            if (version == 2) {
                Text("طريقة الفتح", style = T.label)
                Gap(8.dp)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if ((policy?.optInt("passwordSlots") ?: 0) > 0) Chip("كلمة المرور", mode == "password") { mode = "password"; error = null }
                    if (policy?.optBoolean("recovery") == true) Chip("مفتاح الاسترداد", mode == "recovery") { mode = "recovery"; error = null }
                    if (recipients > 0 && hasIdentity) Chip("هويتي", mode == "identity") { mode = "identity"; error = null }
                    if (FileKeys.has(context, fileId)) Chip("تلقائي", mode == "filekey") { mode = "filekey"; error = null }
                }
                Gap(14.dp)
            }
            when (mode) {
                "identity" -> Note("يُفتح بمفتاح هويتك المحفوظ في هذا الهاتف، إن كان المرسل قد اختارك.", icon = R.drawable.ic_users)
                "filekey" -> Note("يُفتح بالمفتاح الذي حفظه هذا الهاتف عند أول فتح.", icon = R.drawable.ic_key)
                else -> {
                    Text(if (mode == "recovery") "مفتاح الاسترداد" else "كلمة المرور", style = T.label)
                    Gap(8.dp)
                    QsField(value = password, onValueChange = { password = it; error = null }, placeholder = if (mode == "recovery") "XXXX-XXXX-…" else "••••••••••••", password = mode != "recovery", highlighted = true)
                }
            }
            if (recipients > 0 && !hasIdentity) {
                Gap(8.dp)
                Text("هذا الملف مربوط بجهات اتصال. إن كنت منهم فأنشئ هويتك أولاً من «جهات الاتصال».", style = T.small)
            }
            if (error != null) {
                Gap(10.dp)
                Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
            }
            Gap(24.dp)
            if (checking) {
                Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.width(12.dp))
                    Text("جاري التحقق…", style = T.label.copy(color = Qs.ivory))
                }
            } else {
                PrimaryButton("فك التشفير واحفظ", icon = R.drawable.ic_unlock, enabled = mode == "identity" || mode == "filekey" || password.isNotEmpty()) { start() }
            }
        }
        Gap(24.dp)
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = { cancel.set(true) }) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null; AppState.pop() }, { message = null }, dismiss = null) }
}
