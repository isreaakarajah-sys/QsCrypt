package com.qscrypt.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.qscrypt.app.AppState
import com.qscrypt.app.Diag
import com.qscrypt.app.R
import com.qscrypt.app.humanSize
import java.io.File

/** Settings → diagnostic log: read it, send it to the developer, save it, clear it. */
@Composable
fun DiagScreen() {
    val context = LocalContext.current
    var text by remember { mutableStateOf(Diag.read()) }
    var askClear by remember { mutableStateOf(false) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) {
            val ok = runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(Diag.report().toByteArray()) } != null }.getOrDefault(false)
            Toast.makeText(context, if (ok) "تم حفظ السجل" else "تعذّر الحفظ", Toast.LENGTH_SHORT).show()
        }
    }
    Column(Modifier.fillMaxSize()) {
        TopBar("سجل التشخيص", onBack = { AppState.pop() })
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(8.dp)
            Note("يُحفظ على هذا الهاتف فقط ولا يُرسل وحده: التطبيق بلا إنترنت. فيه الأعطال وأخطاء المحرك والعمليات المتعثّرة، بلا كلمات مرور ولا مفاتيح ولا محتوى ملفات. أرسله للمطوّر إذا واجهتك مشكلة.", icon = R.drawable.ic_info)
            Gap(14.dp)
            androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("إرسال", Qs.brass, enabled = text.isNotBlank(), icon = R.drawable.ic_share) { shareLog(context) }
                Pill("نسخ", Qs.ivory, enabled = text.isNotBlank()) {
                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("QsCrypt", Diag.report()))
                    Toast.makeText(context, "تم نسخ السجل", Toast.LENGTH_SHORT).show()
                }
                Pill("حفظ كملف", Qs.ivory, enabled = text.isNotBlank(), icon = R.drawable.ic_download) {
                    AppState.pickerOpen = true
                    saver.launch("QsCrypt-log.txt")
                }
                Pill("مسح", Qs.coral, enabled = text.isNotBlank(), icon = R.drawable.ic_trash) { askClear = true }
            }
            Gap(14.dp)
            if (text.isBlank()) {
                Text("السجل فارغ: لم يحدث أي خطأ.", style = T.body.copy(color = Qs.muted))
            } else {
                Text("الحجم: ${humanSize(Diag.size())}", style = T.small)
                Gap(8.dp)
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    SelectionContainer {
                        Text(
                            text,
                            style = T.mono.copy(fontSize = 10.5.sp, lineHeight = 15.sp, color = Qs.ivory),
                            softWrap = false,
                            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        )
                    }
                }
            }
            Gap(24.dp)
        }
    }
    if (askClear) {
        QsAlert("مسح السجل", "يُحذف السجل من هذا الهاتف.", "مسح", onConfirm = {
            askClear = false
            Diag.clear()
            text = ""
        }, onDismiss = { askClear = false }, danger = true)
    }
}

/** Shares the log as a text file (large logs do not fit in a share's text). */
private fun shareLog(context: Context) {
    runCatching {
        val dir = File(context.cacheDir, "share").apply { mkdirs() }
        val f = File(dir, "QsCrypt-log.txt")
        f.writeText(Diag.report())
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.share", f)
        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, "QsCrypt – سجل التشخيص")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(send, "إرسال السجل"))
    }.onFailure { Toast.makeText(context, "تعذّر الإرسال", Toast.LENGTH_SHORT).show() }
}
