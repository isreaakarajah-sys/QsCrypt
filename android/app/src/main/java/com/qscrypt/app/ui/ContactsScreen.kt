package com.qscrypt.app.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.Contact
import com.qscrypt.app.Identity
import com.qscrypt.app.Prefs
import com.qscrypt.app.Qr
import com.qscrypt.app.R
import com.qscrypt.app.Screen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

private val CARD = Regex("QSID1:[0-9A-Z $%*+./:-]+")

/** The identity card inside some text (a pasted message, a .qsid file). */
fun findCard(text: String?): String? = text?.let { CARD.find(it)?.value?.trimEnd() }

/** Safety numbers in groups of five digits, as people read them aloud. */
fun groupedSafety(s: String): String = s.filter { it.isDigit() }.chunked(5).joinToString(" ")

fun cameraUri(context: Context): Uri {
    val dir = File(context.cacheDir, "camera").apply { mkdirs() }
    val f = File(dir, "qr.jpg")
    return FileProvider.getUriForFile(context, "${context.packageName}.share", f)
}

private fun shareCard(context: Context, me: JSONObject) {
    val text = "هويتي على QsCrypt (${me.optString("name")}):\n${me.optString("card")}"
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    AppState.pickerOpen = true
    context.startActivity(Intent.createChooser(send, "مشاركة هويتي"))
}

@Composable
fun ContactsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    var me by remember { mutableStateOf(Identity.public(context)) }
    var contacts by remember { mutableStateOf(Prefs.contacts()) }
    var creating by remember { mutableStateOf(false) }
    var renamingMe by remember { mutableStateOf(false) }
    var deletingMe by remember { mutableStateOf(false) }
    var showQr by remember { mutableStateOf(false) }
    var pending by remember { mutableStateOf<JSONObject?>(null) }
    var detail by remember { mutableStateOf<Contact?>(null) }
    var renaming by remember { mutableStateOf<Contact?>(null) }
    var deleting by remember { mutableStateOf<Contact?>(null) }
    var pasting by remember { mutableStateOf(false) }
    var adding by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    fun save(list: List<Contact>) {
        Prefs.saveContacts(list)
        contacts = list
    }

    fun consider(text: String?) {
        val card = findCard(text)
        if (card == null) {
            message = "لم يُعثر على رمز هوية QsCrypt. تأكد أن الصورة واضحة ورمز QR كامل فيها، أو الصق نص الهوية كما وصلك."
            return
        }
        val r = Call("id.parseCard").put("card", card).run()
        if (!r.ok) {
            message = "رمز الهوية تالف أو ناقص."
            return
        }
        if (r.json.optString("fingerprint") == me?.optString("fingerprint")) {
            message = "هذه هويتك أنت."
            return
        }
        pending = r.json
    }

    fun decodeImage(uri: Uri) {
        scope.launch {
            val text = withContext(Dispatchers.IO) { Qr.decode(context, uri) }
            consider(text)
        }
    }

    val camera = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) decodeImage(cameraUri(context))
    }
    val gallery = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri -> uri?.let { decodeImage(it) } }
    val file = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        val buf = ByteArray(65536)
                        var n = 0
                        while (n < buf.size) {
                            val r = input.read(buf, n, buf.size - n)
                            if (r < 0) break
                            n += r
                        }
                        String(buf, 0, n, Charsets.UTF_8)
                    }
                }.getOrNull()
            }
            consider(text)
        }
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            Text("جهات الاتصال", style = T.display.copy(lineHeight = 36.sp))
            Gap(4.dp)
            Text("شفّر لأصدقائك ملفات لا يفتحها غيرهم، دون تبادل كلمات مرور", style = T.small)
            Gap(14.dp)
            QsCard(onClick = { AppState.push(Screen.Message) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_lock, Qs.brass, size = 40.dp, radius = 12.dp, iconSize = 20.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text("رسالة سرية برمز QR", style = T.item)
                        Text("اكتب لصديق، أو اقرأ رسالة وصلتك، بالتصوير فقط", style = T.small)
                    }
                    QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
                }
            }
            Gap(20.dp)
            SectionLabel("هويتي")
            Gap(8.dp)
            val my = me
            if (my == null) {
                QsCard(glow = true) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Tile(R.drawable.ic_key, Qs.brass, size = 46.dp, radius = 15.dp)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text("أنشئ هويتك", style = T.itemLarge)
                                Text("مفتاحان (X25519 وML-KEM-768) وتوقيع Ed25519، تُحفظ مشفّرة بعتاد الهاتف", style = T.small)
                            }
                        }
                        Gap(12.dp)
                        PrimaryButton("إنشاء هويتي", icon = R.drawable.ic_plus) { creating = true }
                    }
                }
            } else {
                QsCard {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Tile(R.drawable.ic_key, Qs.brass, size = 46.dp, radius = 15.dp)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(my.optString("name"), style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("رقم الأمان: " + groupedSafety(my.optString("safety")).take(17) + "…", style = T.mono.copy(fontSize = 12.sp))
                            }
                            IconBtn(R.drawable.ic_edit, "تغيير الاسم", tint = Qs.muted) { renamingMe = true }
                        }
                        Gap(12.dp)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SecondaryButton("رمز QR", modifier = Modifier.weight(1f), icon = R.drawable.ic_image) { showQr = true }
                            SecondaryButton("مشاركة", modifier = Modifier.weight(1f), icon = R.drawable.ic_share) { shareCard(context, my) }
                        }
                        Text(
                            "حذف هويتي من هذا الهاتف",
                            style = T.small.copy(color = Qs.coral),
                            modifier = Modifier.clickable { deletingMe = true }.padding(top = 12.dp, bottom = 2.dp),
                        )
                    }
                }
            }
            Gap(22.dp)
            SectionLabel("أصدقائي", count = contacts.size.takeIf { it > 0 }?.toString())
            Gap(8.dp)
            PrimaryButton("أضف جهة اتصال", icon = R.drawable.ic_plus) { adding = true }
            Gap(12.dp)
            if (contacts.isEmpty()) {
                Text("لا توجد جهات اتصال بعد. اطلب من صديقك فتح «جهات الاتصال» وعرض رمز QR الخاص به، ثم صوّره من هنا.", style = T.body.copy(color = Qs.muted))
            }
            contacts.sortedBy { it.name }.forEach { c ->
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable { detail = c }.padding(vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Tile(R.drawable.ic_users, if (c.verified) Qs.mint else Qs.muted, size = 42.dp, radius = 14.dp, iconSize = 21.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(c.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(groupedSafety(c.safety).take(17) + "…", style = T.mono)
                    }
                    if (c.verified) Tag("تم التحقق", TagKind.Mint) else Tag("لم يُتحقق", TagKind.Outline)
                }
            }
            Gap(18.dp)
            Note("أضف صديقك وجهاً لوجه بتصوير رمزه، أو قارن «رقم الأمان» معه بمكالمة إن وصلتك هويته برسالة. هكذا تتأكد أن أحداً لم يستبدلها.", icon = R.drawable.ic_shield)
            Gap(24.dp)
        }
        BottomNav(Screen.Contacts)
    }

    if (creating) {
        InputDialog("هويتك", "", "إنشاء", placeholder = "اسمك كما يراه أصدقاؤك", onConfirm = { name ->
            creating = false
            if (name.isNotBlank()) {
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { Identity.create(context, name.trim().take(40)) }
                    me = Identity.public(context)
                    if (!ok) message = "تعذّر إنشاء الهوية على هذا الهاتف."
                }
            }
        }, onDismiss = { creating = false })
    }
    if (renamingMe) {
        InputDialog("تغيير اسمي", me?.optString("name").orEmpty(), "حفظ", onConfirm = { name ->
            renamingMe = false
            if (name.isNotBlank() && Identity.rename(context, name.trim().take(40))) me = Identity.public(context)
        }, onDismiss = { renamingMe = false })
    }
    if (showQr) {
        val my = me
        if (my != null) {
            val bitmap = remember(my.optString("card")) { Qr.encode(my.optString("card")).asImageBitmap() }
            AlertDialog(
                onDismissRequest = { showQr = false },
                containerColor = Qs.surface,
                title = { Text(my.optString("name"), style = T.title) },
                text = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(16.dp)).background(androidx.compose.ui.graphics.Color.White).padding(10.dp)) {
                            Image(bitmap, "رمز QR لهويتي", Modifier.fillMaxSize(), filterQuality = FilterQuality.None)
                        }
                        Gap(12.dp)
                        Text("دع صديقك يصوّره من «أضف جهة اتصال» ← «تصوير رمز QR». ارفع سطوع الشاشة إن تعذّرت القراءة.", style = T.small, textAlign = TextAlign.Center)
                        Gap(10.dp)
                        Text("رقم الأمان", style = T.label)
                        Text(groupedSafety(my.optString("safety")), style = T.monoLarge.copy(lineHeight = 22.sp), textAlign = TextAlign.Center)
                    }
                },
                confirmButton = { TextButton(onClick = { showQr = false }) { Text("تم", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) } },
            )
        }
    }
    if (adding) {
        AlertDialog(
            onDismissRequest = { adding = false },
            containerColor = Qs.surface,
            title = { Text("أضف جهة اتصال", style = T.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    AddOption(R.drawable.ic_image, "تصوير رمز QR", "يفتح الكاميرا لتصوير رمز صديقك") {
                        adding = false
                        AppState.pickerOpen = true
                        runCatching { camera.launch(cameraUri(context)) }.onFailure { message = "لا يوجد تطبيق كاميرا." }
                    }
                    AddOption(R.drawable.ic_folder, "صورة من المعرض", "لقطة شاشة أو صورة فيها الرمز") {
                        adding = false
                        AppState.pickerOpen = true
                        gallery.launch("image/*")
                    }
                    AddOption(R.drawable.ic_doc, "لصق نص الهوية", "إن وصلتك برسالة تبدأ بـ QSID1:") {
                        adding = false
                        pasting = true
                    }
                    AddOption(R.drawable.ic_file, "من ملف", "ملف نصي فيه الهوية") {
                        adding = false
                        AppState.pickerOpen = true
                        file.launch(arrayOf("*/*"))
                    }
                }
            },
            confirmButton = { TextButton(onClick = { adding = false }) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
        )
    }
    if (pasting) {
        val clip = clipboard.getText()?.text
        InputDialog("لصق الهوية", findCard(clip) ?: "", "إضافة", placeholder = "QSID1:…", onConfirm = { text ->
            pasting = false
            consider(text)
        }, onDismiss = { pasting = false })
    }
    pending?.let { p ->
        val existing = contacts.firstOrNull { it.fingerprint == p.optString("fingerprint") }
        AlertDialog(
            onDismissRequest = { pending = null },
            containerColor = Qs.surface,
            title = { Text(if (existing != null) "تحديث ${existing.name}؟" else "إضافة ${p.optString("name")}؟", style = T.title) },
            text = {
                Column {
                    Text("قارن رقم الأمان مع ما يظهر على هاتف صديقك في «هويتي ← رمز QR». إن تطابق، فالهوية له فعلاً.", style = T.body.copy(color = Qs.muted, fontSize = 13.5.sp))
                    Gap(12.dp)
                    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Qs.base).padding(12.dp)) {
                        Text(groupedSafety(p.optString("safety")), style = T.monoLarge.copy(lineHeight = 22.sp), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val c = Contact(p.optString("name"), p.optString("card"), p.optString("safety"), p.optString("fingerprint"), p.optString("signKey"), false, System.currentTimeMillis())
                    save(contacts.filter { it.fingerprint != c.fingerprint } + c.copy(name = existing?.name ?: c.name))
                    pending = null
                    Toast.makeText(context, "أُضيف ${c.name}", Toast.LENGTH_SHORT).show()
                }) { Text("تطابق، أضف", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
            },
            dismissButton = { TextButton(onClick = { pending = null }) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
        )
    }
    detail?.let { c ->
        AlertDialog(
            onDismissRequest = { detail = null },
            containerColor = Qs.surface,
            title = { Text(c.name, style = T.title) },
            text = {
                Column {
                    Text("رقم الأمان", style = T.label)
                    Gap(6.dp)
                    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Qs.base).padding(12.dp)) {
                        Text(groupedSafety(c.safety), style = T.monoLarge.copy(lineHeight = 22.sp), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                    }
                    Gap(10.dp)
                    Text(if (c.verified) "قارنته معه ووجدته مطابقاً." else "قارنه مع صديقك وجهاً لوجه أو بمكالمة، ثم علّمه كمتحقَّق منه.", style = T.small)
                    Gap(14.dp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SecondaryButton(if (c.verified) "إلغاء التحقق" else "تم التحقق", modifier = Modifier.weight(1f), icon = R.drawable.ic_check, color = Qs.mint) {
                            save(contacts.map { if (it.fingerprint == c.fingerprint) it.copy(verified = !c.verified) else it })
                            detail = null
                        }
                        SecondaryButton("الاسم", modifier = Modifier.weight(1f), icon = R.drawable.ic_edit) {
                            renaming = c
                            detail = null
                        }
                    }
                    Gap(8.dp)
                    SecondaryButton("حذف", icon = R.drawable.ic_trash, color = Qs.coral) {
                        deleting = c
                        detail = null
                    }
                }
            },
            confirmButton = { TextButton(onClick = { detail = null }) { Text("إغلاق", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) } },
        )
    }
    renaming?.let { c ->
        InputDialog("اسم جهة الاتصال", c.name, "حفظ", onConfirm = { name ->
            renaming = null
            if (name.isNotBlank()) save(contacts.map { if (it.fingerprint == c.fingerprint) it.copy(name = name.trim().take(40)) else it })
        }, onDismiss = { renaming = null })
    }
    deleting?.let { c ->
        DangerConfirm("حذف ${c.name}؟", "لن تستطيع تشفير ملفات له حتى تضيفه من جديد. الملفات التي شفّرتها له سابقاً تبقى قابلة للفتح عنده.", "حذف", {
            save(contacts.filter { it.fingerprint != c.fingerprint })
            deleting = null
        }, { deleting = null })
    }
    if (deletingMe) {
        DangerConfirm("حذف هويتي؟", "سيُحذف مفتاحك الخاص من هذا الهاتف نهائياً: لن تفتح الملفات المرسلة لهويتك، ولن تستطيع التوقيع باسمك.", "احذف", {
            Identity.delete(context)
            me = null
            deletingMe = false
        }, { deletingMe = false })
    }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}

@Composable
private fun AddOption(icon: Int, title: String, sub: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Qs.surface2).clickable(onClick = onClick).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QsIcon(icon, Qs.brass, 22.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = T.item)
            Text(sub, style = T.small)
        }
    }
}
