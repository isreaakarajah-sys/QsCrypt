package com.qscrypt.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qscrypt.app.AppState
import com.qscrypt.app.Attempt
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import com.qscrypt.app.Screen
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private fun attemptText(a: Attempt): Pair<String, Int> = when (a.kind) {
    "app" -> "رمز أو نمط خاطئ لفتح التطبيق" to R.drawable.ic_lock
    "calc" -> "رمز خاطئ في الآلة الحاسبة (وضع التمويه)" to R.drawable.ic_sliders
    "vault" -> "كلمة مرور خاطئة للخزنة «${a.target}»" to R.drawable.ic_vault
    "file" -> "كلمة مرور خاطئة للملف «${a.target}»" to R.drawable.ic_file
    "finger" -> "فشل الفتح بالبصمة لـ «${a.target}»" to R.drawable.ic_finger
    else -> a.kind to R.drawable.ic_alert
}

fun timeText(ms: Long): String = "${friendlyDate(ms / 1000)} ${SimpleDateFormat("HH:mm", Locale.US).format(Date(ms))}".trim()

/** The log of failed attempts, newest first. */
@Composable
fun AttemptsScreen() {
    var log by remember { mutableStateOf(Prefs.attemptsLog()) }
    var enabled by remember { mutableStateOf(Prefs.logAttempts) }
    var confirmClear by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { Prefs.attemptsSeen = System.currentTimeMillis() }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("سجل المحاولات الفاشلة", onBack = { AppState.pop() }) {
            if (log.isNotEmpty()) IconBtn(R.drawable.ic_trash, "مسح السجل", tint = Qs.muted) { confirmClear = true }
        }
        Gap(12.dp)
        OptionRow(R.drawable.ic_eye, "سجّل المحاولات", "كل رمز أو نمط أو كلمة مرور خاطئة، مع الوقت") {
            QsSwitch(enabled) {
                enabled = it
                Prefs.logAttempts = it
            }
        }
        Gap(8.dp)
        Note("يُحفظ السجل على هذا الهاتف فقط. بعد كل دخول يخبرك التطبيق إن حاول أحد فتحه في غيابك.", icon = R.drawable.ic_info)
        Gap(14.dp)
        if (log.isEmpty()) {
            Column(Modifier.fillMaxWidth().padding(vertical = 40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                QsIcon(R.drawable.ic_shield, Qs.mint, 40.dp)
                Gap(12.dp)
                Text("لا توجد محاولات فاشلة", style = T.item.copy(color = Qs.muted))
            }
        } else {
            LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
                items(log) { a ->
                    val (text, icon) = attemptText(a)
                    Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Tile(icon, if (a.kind == "app" || a.kind == "calc") Qs.coral else Qs.brass, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(text, style = T.item, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(timeText(a.time), style = T.mono)
                        }
                    }
                    Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))
                }
                item { Gap(24.dp) }
            }
        }
    }
    if (confirmClear) {
        QsAlert("مسح السجل", "ستُحذف كل المحاولات المسجّلة.", "مسح", {
            Prefs.clearAttempts()
            log = emptyList()
            confirmClear = false
        }, { confirmClear = false }, danger = true)
    }
}

/** Once after unlocking: someone tried to open the app while you were away. */
@Composable
fun AttemptsReport() {
    val n = AppState.attemptsToReport
    if (n <= 0) return
    val last = remember(n) { Prefs.attemptsLog().firstOrNull { it.kind == "app" || it.kind == "calc" } }
    fun done() {
        AppState.attemptsToReport = 0
        Prefs.attemptsSeen = System.currentTimeMillis()
    }
    QsAlert(
        title = "محاولات فاشلة",
        text = (if (n == 1) "حاول أحدهم فتح التطبيق مرة واحدة بقفل خاطئ منذ آخر دخول." else "حدثت $n محاولات لفتح التطبيق بقفل خاطئ منذ آخر دخول.") +
            (last?.let { "\nآخرها: ${timeText(it.time)}." } ?: ""),
        confirm = "عرض السجل",
        onConfirm = {
            done()
            AppState.push(Screen.Attempts)
        },
        onDismiss = { done() },
        dismiss = "حسناً",
    )
}
