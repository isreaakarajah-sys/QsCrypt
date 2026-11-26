package com.qscrypt.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.qscrypt.app.AppState
import com.qscrypt.app.Backup
import com.qscrypt.app.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Settings → encrypted backup: make one, or restore one. */
@Composable
fun BackupScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var restoreUri by remember { mutableStateOf<Uri?>(null) }
    var restorePw by remember { mutableStateOf("") }
    val preview = remember { Backup.preview(context) }
    val strong = pw.length >= 8
    val matches = pw == pw2

    val creator = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val password = pw.toByteArray(Charsets.UTF_8)
        busy = true
        scope.launch {
            val sealed = withContext(Dispatchers.Default) { Backup.seal(context, password) }
            password.fill(0)
            val ok = sealed != null && withContext(Dispatchers.IO) {
                runCatching { context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(sealed) } != null }.getOrDefault(false)
            }
            busy = false
            if (ok) {
                pw = ""
                pw2 = ""
            }
            message = if (ok) true to "حُفظت النسخة الاحتياطية المشفّرة. احتفظ بها خارج الهاتف، ولا تنسَ كلمة مرورها: لا تُفتح بدونها." else false to "تعذّر إنشاء النسخة أو حفظها."
        }
    }
    val opener = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            restoreUri = uri
            restorePw = ""
        }
    }

    Column(Modifier.fillMaxSize()) {
        TopBar("النسخة الاحتياطية المشفّرة", onBack = { AppState.pop() })
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(8.dp)
            Note(
                "تحفظ ما يعيش داخل التطبيق فقط: هويتك وجهات اتصالك وقائمة خزناتك ومفاتيح ملفات «الفتح التلقائي»، مشفّرة بكلمة مرور تختارها. محتوى الخزنات ليس فيها: هو أصلاً في ملفاته المشفّرة.",
                icon = R.drawable.ic_shield,
            )
            Gap(16.dp)
            SectionLabel("إنشاء نسخة")
            Gap(8.dp)
            QsCard {
                Column {
                    Text(
                        buildList {
                            add(if (preview.identity) "الهوية: نعم" else "الهوية: لا توجد")
                            add("جهات الاتصال: ${preview.contacts}")
                            add("الخزنات في القائمة: ${preview.vaults}")
                            if (preview.keys > 0) add("مفاتيح ملفات: ${preview.keys}")
                        }.joinToString(" – "),
                        style = T.small,
                    )
                    Gap(12.dp)
                    QsField(value = pw, onValueChange = { pw = it }, placeholder = "كلمة مرور النسخة (8 أحرف على الأقل)", password = true)
                    Gap(10.dp)
                    QsField(value = pw2, onValueChange = { pw2 = it }, placeholder = "أعد كتابة كلمة المرور", password = true)
                    if (pw2.isNotEmpty() && !matches) {
                        Gap(6.dp)
                        Text("كلمتا المرور غير متطابقتين", style = T.small.copy(color = Qs.coral))
                    }
                    Gap(14.dp)
                    PrimaryButton("احفظ النسخة", icon = R.drawable.ic_download, enabled = strong && matches && !busy) {
                        AppState.pickerOpen = true
                        creator.launch("QsCrypt-backup-" + SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date()) + ".qsc")
                    }
                }
            }
            Gap(20.dp)
            SectionLabel("استعادة نسخة")
            Gap(8.dp)
            QsCard {
                Column {
                    Text("الهوية في النسخة تحلّ محل الهوية الحالية إن وُجدت. جهات الاتصال والخزنات والمفاتيح تُضاف إلى الموجود.", style = T.small)
                    Gap(12.dp)
                    SecondaryButton("اختر ملف النسخة", icon = R.drawable.ic_file, enabled = !busy) {
                        AppState.pickerOpen = true
                        opener.launch(arrayOf("*/*"))
                    }
                }
            }
            message?.let { (ok, text) ->
                Gap(16.dp)
                Note(text, icon = if (ok) R.drawable.ic_check else R.drawable.ic_alert, color = if (ok) Qs.mint else Qs.coral)
            }
            Gap(24.dp)
        }
    }

    restoreUri?.let { uri ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { if (!busy) restoreUri = null },
            containerColor = Qs.surface,
            title = { Text("كلمة مرور النسخة", style = T.title) },
            text = {
                Column {
                    QsField(value = restorePw, onValueChange = { restorePw = it }, placeholder = "كلمة المرور", password = true)
                    if (busy) {
                        Gap(10.dp)
                        Text("جاري الفك…", style = T.small)
                    }
                }
            },
            confirmButton = {
                Text(
                    "استعادة",
                    style = T.label.copy(color = if (restorePw.isNotEmpty() && !busy) Qs.brass else Qs.muted),
                    modifier = Modifier
                        .clickable(enabled = restorePw.isNotEmpty() && !busy) {
                            val password = restorePw.toByteArray(Charsets.UTF_8)
                            busy = true
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    val bytes = runCatching { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } }.getOrNull()
                                    if (bytes == null) null else Backup.restore(context, bytes, password)
                                }
                                password.fill(0)
                                busy = false
                                restoreUri = null
                                message = when (result) {
                                    null -> false to "تعذّرت قراءة الملف."
                                    Backup.Restored.WrongPassword -> false to "كلمة المرور غير صحيحة، أو أن الملف ليس نسخة احتياطية من QsCrypt."
                                    Backup.Restored.NotABackup -> false to "هذا الملف ليس نسخة احتياطية من QsCrypt."
                                    is Backup.Restored.Done -> true to buildList {
                                        if (result.summary.identity) add("استُعيدت الهوية")
                                        add("أُضيفت ${result.summary.contacts} جهة اتصال")
                                        add("${result.summary.vaults} خزنة")
                                        if (result.summary.keys > 0) add("${result.summary.keys} مفتاح ملف")
                                    }.joinToString(" – ") + ". إذا لم تُفتح خزنة من القائمة، أعد اختيار ملفها مرة واحدة."
                                }
                            }
                        }
                        .padding(8.dp),
                )
            },
            dismissButton = {
                Text("إلغاء", style = T.label.copy(color = Qs.muted), modifier = Modifier.clickable { if (!busy) restoreUri = null }.padding(8.dp))
            },
        )
    }
}
