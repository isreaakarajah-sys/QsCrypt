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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Jobs
import com.qscrypt.app.R
import com.qscrypt.app.Transfers
import com.qscrypt.app.humanSize

private fun stateText(j: Jobs.Job): String = when (j.state) {
    Jobs.State.Queued -> "في الانتظار"
    Jobs.State.Running -> if (j.pauseFlag.get()) "يتوقف…" else "جارٍ"
    Jobs.State.Paused -> if (j.lowBattery && !j.pauseFlag.get()) "متوقفة: البطارية منخفضة (تُستأنف عند الشحن)" else "متوقفة مؤقتاً"
    Jobs.State.Done -> "اكتملت"
    Jobs.State.Failed -> "فشلت"
    Jobs.State.Cancelled -> "أُلغيت"
}

private fun etaText(j: Jobs.Job): String {
    if (j.state != Jobs.State.Running || j.speed <= 0 || j.total <= 0) return ""
    val left = (j.total - j.done).coerceAtLeast(0) / j.speed
    val t = when {
        left < 60 -> "أقل من دقيقة"
        left < 3600 -> "${left / 60} دقيقة"
        else -> "${left / 3600} ساعة و${(left % 3600) / 60} دقيقة"
    }
    return "${humanSize(j.speed)}/ث · باقٍ $t"
}

@Composable
private fun JobBody(j: Jobs.Job) {
    if (j.detail.isNotEmpty() && j.active) {
        Text(j.detail, style = T.small, maxLines = 2, overflow = TextOverflow.Ellipsis)
        Gap(8.dp)
    }
    if (j.active) {
        val f = j.fraction
        if (f != null) {
            LinearProgressIndicator(progress = { f }, color = if (j.state == Jobs.State.Paused) Qs.muted else Qs.brass, trackColor = Qs.line, modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)))
            Gap(6.dp)
            Row(Modifier.fillMaxWidth()) {
                Text("${(f * 100).toInt()}%", style = T.mono.copy(color = Qs.ivory))
                Spacer(Modifier.weight(1f))
                if (j.total > 1024) Text("${humanSize(j.done)} / ${humanSize(j.total)}", style = T.mono)
            }
        } else {
            LinearProgressIndicator(color = Qs.brass, trackColor = Qs.line, modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)))
        }
        val eta = etaText(j)
        if (eta.isNotEmpty()) {
            Gap(4.dp)
            Text(eta, style = T.small)
        }
    } else if (j.result.isNotEmpty()) {
        Text(j.result, style = T.small.copy(color = if (j.state == Jobs.State.Failed) Qs.coral else Qs.muted))
    }
}

/** Pause, resume and cancel for one job. */
@Composable
private fun JobControls(j: Jobs.Job) {
    if (!j.active) return
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        val paused = j.pauseFlag.get() || j.state == Jobs.State.Paused
        Pill(
            if (paused) "استئناف" else "إيقاف مؤقت",
            if (paused) Qs.mint else Qs.brass,
            onClick = { if (paused) j.resume() else j.pause() },
        )
        Pill("إلغاء", Qs.coral, onClick = { j.cancel() })
    }
}

/**
 * Progress of a job started from a screen. "In the background" closes the
 * dialog; the job goes on and appears under background operations.
 */
@Composable
fun JobDialog(job: Jobs.Job, onClose: () -> Unit, doneText: String? = null, onDone: (() -> Unit)? = null) {
    AlertDialog(
        onDismissRequest = { if (!job.active) onClose() },
        containerColor = Qs.surface,
        title = { Text(job.title, style = T.title.copy(fontSize = 18.sp), maxLines = 2, overflow = TextOverflow.Ellipsis) },
        text = {
            Column(Modifier.fillMaxWidth()) {
                Text(stateText(job), style = T.label.copy(color = if (job.state == Jobs.State.Failed) Qs.coral else Qs.brass))
                Gap(10.dp)
                JobBody(job)
                if (job.state == Jobs.State.Done && doneText != null) {
                    Gap(6.dp)
                    Text(doneText, style = T.small)
                }
            }
        },
        confirmButton = {
            if (job.active) {
                val paused = job.pauseFlag.get() || job.state == Jobs.State.Paused
                TextButton(onClick = { if (paused) job.resume() else job.pause() }) {
                    Text(if (paused) "استئناف" else "إيقاف مؤقت", style = T.button.copy(color = Qs.brass, fontSize = 15.sp))
                }
            } else {
                TextButton(onClick = {
                    onClose()
                    if (job.state == Jobs.State.Done) onDone?.invoke()
                }) { Text("تم", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
            }
        },
        dismissButton = {
            if (job.active) {
                Row {
                    TextButton(onClick = { job.cancel() }) { Text("إلغاء", style = T.button.copy(color = Qs.coral, fontSize = 15.sp)) }
                    TextButton(onClick = onClose) { Text("في الخلفية", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) }
                }
            }
        },
    )
}

/** Every background operation: running, paused, finished, and those left from before a restart. */
@Composable
fun JobsScreen() {
    val context = LocalContext.current
    var message by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("العمليات في الخلفية", onBack = { AppState.pop() }) {
            if (Jobs.list.any { !it.active }) IconBtn(R.drawable.ic_trash, "مسح المنتهية", tint = Qs.muted) { Jobs.clearFinished() }
        }
        Gap(12.dp)
        if (Jobs.list.isEmpty() && Jobs.pending.isEmpty()) {
            Column(Modifier.fillMaxWidth().padding(vertical = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                QsIcon(R.drawable.ic_check, Qs.mint, 40.dp)
                Gap(12.dp)
                Text("لا توجد عمليات", style = T.item.copy(color = Qs.muted))
                Gap(6.dp)
                Text("النسخ والإضافة والتصدير والتشفير الطويل يعمل هنا، ويمكن إيقافه مؤقتاً واستئنافه.", style = T.small)
            }
        }
        val active = Jobs.list.filter { it.active }
        val finished = Jobs.list.filter { !it.active }.reversed()
        if (active.size > 1) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("أوقف الكل مؤقتاً", Qs.brass, onClick = { active.forEach { it.pause() } })
                Pill("استأنف الكل", Qs.mint, onClick = { active.forEach { it.resume() } })
            }
            Gap(12.dp)
        }
        for (j in active + finished) {
            QsCard(Modifier.fillMaxWidth().padding(vertical = 5.dp)) { Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(
                        when (j.kind) {
                            "copy" -> R.drawable.ic_folder
                            "import" -> R.drawable.ic_plus
                            "export" -> R.drawable.ic_download
                            "fill" -> R.drawable.ic_shield
                            "check" -> R.drawable.ic_check
                            "delete" -> R.drawable.ic_trash
                            else -> R.drawable.ic_lock
                        },
                        when (j.state) {
                            Jobs.State.Failed -> Qs.coral
                            Jobs.State.Done -> Qs.mint
                            Jobs.State.Cancelled -> Qs.muted
                            else -> Qs.brass
                        },
                        size = 40.dp, radius = 12.dp, iconSize = 20.dp,
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(j.title, style = T.item, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Text(stateText(j), style = T.small.copy(color = if (j.state == Jobs.State.Failed) Qs.coral else Qs.muted))
                    }
                }
                Gap(10.dp)
                JobBody(j)
                if (j.active) {
                    Gap(10.dp)
                    JobControls(j)
                }
            } }
        }
        if (Jobs.pending.isNotEmpty()) {
            Gap(16.dp)
            SectionLabel("لم تكتمل قبل إغلاق التطبيق")
            for (p in Jobs.pending.toList()) {
                QsCard(Modifier.fillMaxWidth().padding(vertical = 5.dp)) { Column {
                    Text(p.title, style = T.item)
                    Gap(4.dp)
                    Text("يُكمل من حيث توقف، ويتخطى ما نُسخ كاملاً.", style = T.small)
                    Gap(10.dp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Pill("استئناف", Qs.mint, onClick = { message = Transfers.resume(context, p) })
                        Pill("تجاهل", Qs.muted, onClick = { Jobs.dropPending(p) })
                    }
                } }
            }
        }
        message?.let {
            Gap(10.dp)
            Note(it, color = Qs.coral, icon = R.drawable.ic_alert)
        }
        Gap(24.dp)
    }
}

/** A compact banner for Home and the vault screen: N operations running. */
@Composable
fun JobsBanner() {
    val active = Jobs.list.filter { it.active }
    if (active.isEmpty() && Jobs.pending.isEmpty()) return
    val f = active.mapNotNull { it.fraction }.let { if (it.isEmpty()) null else it.average().toFloat() }
    QsCard(Modifier.fillMaxWidth().padding(vertical = 6.dp), onClick = { AppState.push(com.qscrypt.app.Screen.JobsList) }) { Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(4.dp).height(34.dp).clip(RoundedCornerShape(2.dp)).background(if (active.isEmpty()) Qs.coral else Qs.brass))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    when {
                        active.isEmpty() -> "عمليات لم تكتمل: ${Jobs.pending.size}"
                        active.size == 1 -> active[0].title
                        else -> "${active.size} عمليات في الخلفية"
                    },
                    style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Text(
                    when {
                        active.isEmpty() -> "اضغط للمتابعة"
                        active.all { it.state == Jobs.State.Paused } -> "متوقفة مؤقتاً"
                        f != null -> "${(f * 100).toInt()}%"
                        else -> "جارٍ العمل…"
                    },
                    style = T.small,
                )
            }
            QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
        }
        if (f != null) {
            Gap(8.dp)
            LinearProgressIndicator(progress = { f }, color = Qs.brass, trackColor = Qs.line, modifier = Modifier.fillMaxWidth().height(3.dp).clip(RoundedCornerShape(2.dp)))
        }
    } }
}
