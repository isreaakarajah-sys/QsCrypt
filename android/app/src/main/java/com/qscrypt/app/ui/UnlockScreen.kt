package com.qscrypt.app.ui

import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Container
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

private val PRFS = listOf(0 to "تلقائي", 1 to "SHA-512", 2 to "SHA-256", 3 to "Whirlpool", 4 to "RIPEMD-160")
private val FORMATS = listOf(0 to "تلقائي", 1 to "VeraCrypt", 2 to "TrueCrypt")

@Composable
fun UnlockScreen(container: Container) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var readOnly by remember { mutableStateOf(false) }
    var advanced by remember { mutableStateOf(false) }
    var prf by remember { mutableIntStateOf(0) }
    var format by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var keyfiles by remember { mutableStateOf(false) }
    var hiddenInfo by remember { mutableStateOf(false) }
    val uri = remember(container.uri) { Uri.parse(container.uri) }

    fun unlock() {
        if (password.isEmpty() || busy) return
        busy = true
        error = null
        val pw = password.toByteArray(Charsets.UTF_8)
        val pimValue = pim.toIntOrNull() ?: 0
        scope.launch {
            val tz = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000
            val raw = withContext(Dispatchers.IO) {
                val rw = if (readOnly) null else Saf.open(context, uri, "rw")
                val pfd = rw ?: Saf.open(context, uri, "r")
                val forcedReadOnly = readOnly || rw == null
                pfd?.use { QsCore.openVolume(it.fd, pw, pimValue, prf, format, forcedReadOnly, tz) }
            }
            pw.fill(0)
            busy = false
            if (raw == null) {
                error = "تعذّر الوصول إلى الملف. ربما نُقل أو حُذف، أو أن الفلاشة غير متصلة."
                return@launch
            }
            val r = Reply(raw)
            if (!r.ok) {
                error = r.error
                return@launch
            }
            val info = VolumeInfo.from(r.json)
            password = ""
            AppState.updateContainer(container.copy(format = info.format, ea = info.ea, fs = info.fs))
            val c = AppState.containers.firstOrNull { it.uri == container.uri } ?: container
            AppState.sessions.add(Session(info.handle, c, info, System.currentTimeMillis()))
            AppState.replaceTop(Screen.Vault(info.handle))
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("فتح حاوية", onBack = { AppState.pop() })
        Gap(18.dp)
        QsCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tile(containerIcon(container), Qs.brass, size = 50.dp, radius = 16.dp, iconSize = 24.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(container.name, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(Saf.location(uri), style = T.small, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text(humanSize(container.size), style = T.mono.copy(fontSize = 12.sp))
            }
        }
        Gap(12.dp)
        Note("الحاوية تبدو بيانات عشوائية، وهذا طبيعي. سيتعرّف التطبيق على صيغتها وخوارزمياتها تلقائياً بعد إدخال كلمة المرور.")
        Gap(22.dp)
        Text("كلمة المرور", style = T.label)
        Gap(8.dp)
        QsField(value = password, onValueChange = { password = it; error = null }, placeholder = "••••••••••••", password = true, highlighted = true)
        if (error != null) {
            Gap(10.dp)
            Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
        }
        Gap(10.dp)
        OptionRow(R.drawable.ic_key, "PIM (اختياري)", "اتركه فارغاً لاستخدام القيمة الافتراضية") {
            QsField(
                value = pim,
                onValueChange = { v -> pim = v.filter { it.isDigit() }.take(7) },
                placeholder = "—",
                keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword,
                height = 40.dp,
                modifier = Modifier.width(92.dp),
                textStyle = T.monoLarge,
            )
        }
        OptionRow(R.drawable.ic_file, "ملفات المفاتيح (Keyfiles)", "لم تُضف أي ملفات") {
            Text("أضف", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable { keyfiles = true }.padding(12.dp))
        }
        OptionRow(R.drawable.ic_eye, "فتح للقراءة فقط", "لا يمكن تعديل أي ملف داخل الحاوية") {
            QsSwitch(readOnly) { readOnly = it }
        }
        OptionRow(R.drawable.ic_shield, "حماية المجلد المخفي", "تمنع الكتابة فوق المجلد المخفي إن وُجد") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                ComingSoonTag()
                Spacer(Modifier.width(8.dp))
                QsSwitch(false, enabled = false) { hiddenInfo = true }
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
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FORMATS.forEach { (id, name) -> Chip(name, format == id) { format = id } }
            }
            Gap(14.dp)
            Text("خوارزمية اشتقاق المفتاح (PRF)", style = T.small)
            Gap(8.dp)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { PRFS.take(3).forEach { (id, name) -> Chip(name, prf == id) { prf = id } } }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { PRFS.drop(3).forEach { (id, name) -> Chip(name, prf == id) { prf = id } } }
            }
            Gap(8.dp)
            Text("تحديد الخوارزمية يسرّع الفتح، والتلقائي يجرّب الكل.", style = T.small)
        }
        Gap(24.dp)
        if (busy) {
            Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Text("جاري التحقق من كلمة المرور…", style = T.label.copy(color = Qs.ivory))
            }
        } else {
            PrimaryButton("فتح الحاوية", icon = R.drawable.ic_unlock, enabled = password.isNotEmpty()) { unlock() }
        }
        Gap(12.dp)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            QsIcon(R.drawable.ic_lock, Qs.muted, 14.dp)
            Spacer(Modifier.width(6.dp))
            Text("كلمة المرور لا تُحفظ ولا تغادر جهازك", style = T.small, textAlign = TextAlign.Center)
        }
        Gap(24.dp)
    }
    if (keyfiles) {
        QsAlert("ملفات المفاتيح", "دعم ملفات المفاتيح (Keyfiles) قادم في الإصدار التالي.", "حسناً", { keyfiles = false }, { keyfiles = false }, dismiss = null)
    }
    if (hiddenInfo) {
        QsAlert("حماية المجلد المخفي", "قادمة في الإصدار التالي. إلى ذلك الحين، افتح الحاوية الخارجية للقراءة فقط إن كانت تحتوي مجلداً مخفياً.", "حسناً", { hiddenInfo = false }, { hiddenInfo = false }, dismiss = null)
    }
}
