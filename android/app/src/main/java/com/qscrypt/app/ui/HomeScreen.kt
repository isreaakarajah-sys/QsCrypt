package com.qscrypt.app.ui

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Favorites
import com.qscrypt.app.Jobs
import com.qscrypt.app.Container
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.Session
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun BottomNav(current: Screen) {
    Column(Modifier.fillMaxWidth().background(Qs.surface)) {
        Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))
        Row(Modifier.fillMaxWidth().height(76.dp)) {
            NavTab(R.drawable.ic_vault, "خزناتي", current == Screen.Home) { AppState.tab(Screen.Home) }
            NavTab(R.drawable.ic_folder, "ملفاتي", current == Screen.Phone) { AppState.tab(Screen.Phone) }
            NavTab(R.drawable.ic_drive, "الأقراص", current == Screen.Drives) { AppState.tab(Screen.Drives) }
            NavTab(R.drawable.ic_users, "جهات الاتصال", current == Screen.Contacts) { AppState.tab(Screen.Contacts) }
            NavTab(R.drawable.ic_sliders, "الإعدادات", current == Screen.Settings) { AppState.tab(Screen.Settings) }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.NavTab(icon: Int, label: String, active: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.weight(1f).height(76.dp).clickable(onClick = onClick),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            Modifier
                .size(width = 58.dp, height = 30.dp)
                .clip(RoundedCornerShape(15.dp))
                .background(if (active) Qs.surface2 else androidx.compose.ui.graphics.Color.Transparent),
            contentAlignment = Alignment.Center,
        ) {
            QsIcon(icon, if (active) Qs.brass else Qs.muted, 21.dp)
        }
        Spacer(Modifier.height(4.dp))
        Text(label, style = T.label.copy(fontSize = 11.sp, lineHeight = 16.sp, color = if (active) Qs.ivory else Qs.muted), maxLines = 1, softWrap = false)
    }
}

fun containerIcon(c: Container): Int = when {
    c.uri.startsWith("usb:") -> R.drawable.ic_usb
    c.format == "QsCrypt" || c.name.endsWith(".qsc", ignoreCase = true) || c.name.endsWith(".qsv", ignoreCase = true) -> R.drawable.ic_shield
    c.format == "BitLocker" || c.name.endsWith(".vhd", ignoreCase = true) -> R.drawable.ic_drive
    else -> R.drawable.ic_file
}

fun containerMeta(c: Container): String {
    val parts = listOfNotNull(c.format.ifBlank { null }, c.ea.ifBlank { null }, humanSize(c.size))
    return parts.joinToString(" · ")
}

fun minutesAgo(since: Long, now: Long): String {
    val m = ((now - since) / 60_000).toInt()
    return when {
        m < 1 -> "مفتوحة الآن"
        m == 1 -> "مفتوحة منذ دقيقة"
        m == 2 -> "مفتوحة منذ دقيقتين"
        m in 3..10 -> "مفتوحة منذ $m دقائق"
        m < 60 -> "مفتوحة منذ $m دقيقة"
        else -> "مفتوحة منذ ${m / 60} ساعة"
    }
}

/** Opens a picked document: QsCrypt files go to decryption, anything else is treated as a volume. */
fun openPicked(context: android.content.Context, uri: Uri, scope: kotlinx.coroutines.CoroutineScope) {
    Saf.persist(context, uri)
    val meta = Saf.meta(context, uri)
    scope.launch {
        val kind = withContext(Dispatchers.IO) {
            Saf.open(context, uri, "r")?.use { pfd -> Reply(QsCore.sniff(pfd.fd)).json.optString("kind") } ?: "error"
        }
        when (kind) {
            "qscrypt" -> AppState.push(Screen.QscDecrypt(uri.toString(), meta.name, meta.size))
            "volume", "container", "bitlocker" -> {
                val c = AppState.addContainer(Container(uri.toString(), meta.name, meta.size, System.currentTimeMillis()))
                AppState.push(Screen.Unlock(c))
            }
            "error" -> Toast.makeText(context, "تعذّر فتح الملف", Toast.LENGTH_LONG).show()
            else -> Toast.makeText(context, "هذا الملف صغير جداً ولا يبدو حاوية مشفّرة", Toast.LENGTH_LONG).show()
        }
    }
}

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var searching by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(30_000)
            now = System.currentTimeMillis()
        }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) openPicked(context, uri, scope)
    }
    val openFile = {
        AppState.pickerOpen = true
        picker.launch(arrayOf("*/*"))
    }
    val containers = AppState.containers.filter { query.isBlank() || it.name.contains(query, ignoreCase = true) }

    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f)) {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
                item {
                    Gap(20.dp)
                    Row(Modifier.fillMaxWidth().height(48.dp), verticalAlignment = Alignment.CenterVertically) {
                        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(30.dp))
                        Spacer(Modifier.width(10.dp))
                        Text("خزناتي", style = T.display.copy(lineHeight = 36.sp), modifier = Modifier.weight(1f))
                        IconBtn(R.drawable.ic_search, "بحث", tint = if (searching) Qs.brass else Qs.ivory) {
                            searching = !searching
                            if (!searching) query = ""
                        }
                        IconBtn(R.drawable.ic_sliders, "الإعدادات") { AppState.tab(Screen.Settings) }
                    }
                    if (searching) {
                        Gap(12.dp)
                        QsField(value = query, onValueChange = { query = it }, placeholder = "ابحث في الخزنات", height = 48.dp, leading = { QsIcon(R.drawable.ic_search, Qs.muted) })
                    }
                }
                if (Jobs.list.any { it.active } || Jobs.pending.isNotEmpty()) {
                    item {
                        Gap(14.dp)
                        JobsBanner()
                    }
                }
                if (AppState.sessions.isNotEmpty()) {
                    item {
                        Gap(22.dp)
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            SectionLabel("مفتوحة الآن", AppState.sessions.size.toString(), modifier = Modifier.weight(1f))
                            Spacer(Modifier.width(10.dp))
                            Pill("أقفل الكل", Qs.brass, icon = R.drawable.ic_lock) { AppState.lockAll(context, "home") }
                        }
                        Gap(10.dp)
                    }
                    items(AppState.sessions.toList(), key = { "s${it.handle}" }) { s ->
                        OpenVaultCard(s, now)
                        Gap(10.dp)
                    }
                }
                item {
                    Gap(22.dp)
                    SectionLabel("كل الخزنات", AppState.containers.size.toString())
                    Gap(4.dp)
                }
                if (AppState.containers.isEmpty()) {
                    item { EmptyState(onOpen = openFile) }
                }
                items(containers, key = { it.uri }) { c -> ContainerRow(c) }
                item { Gap(110.dp) }
            }
            Row(
                Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SecondaryButton("افتح حاوية", modifier = Modifier.weight(1f).background(Qs.base, RoundedCornerShape(18.dp)), icon = R.drawable.ic_unlock, onClick = openFile)
                PrimaryButton("تشفير جديد", modifier = Modifier.weight(1f), icon = R.drawable.ic_plus) { AppState.push(Screen.NewEncryption) }
            }
        }
        BottomNav(Screen.Home)
    }
}

@Composable
private fun EmptyState(onOpen: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 36.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(84.dp))
        Gap(18.dp)
        Text("لا توجد خزنات بعد", style = T.itemLarge)
        Gap(6.dp)
        Text(
            "افتح حاوية VeraCrypt أو TrueCrypt أو BitLocker أو QsCrypt من جوالك أو فلاشة، أو أنشئ خزنة جديدة.",
            style = T.body.copy(color = Qs.muted),
            textAlign = TextAlign.Center,
        )
        Gap(16.dp)
        Text("اختر ملفاً", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable(onClick = onOpen).padding(8.dp))
    }
}

@Composable
private fun OpenVaultCard(s: Session, now: Long) {
    val context = LocalContext.current
    val used = (s.info.total - s.info.free).coerceAtLeast(0)
    var confirmClose by remember { mutableStateOf(false) }
    QsCard(onClick = { AppState.push(Screen.Vault(s.handle)) }) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tile(if (s.plain) R.drawable.ic_usb else R.drawable.ic_unlock, Qs.mint)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(s.container.name.substringBeforeLast('.').ifBlank { s.container.name }, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (s.plain) Tag("غير مشفّر", TagKind.Outline) else {
                            Tag(s.info.format)
                            Tag(s.info.ea)
                        }
                        Tag(s.info.fs)
                        if (s.info.hidden) Tag("مخفية", TagKind.Mint)
                        if (Jobs.busy(s.handle)) Tag("عملية جارية", TagKind.Brass)
                    }
                }
                IconBtn(
                    if (s.usb != null) R.drawable.ic_usb else R.drawable.ic_lock,
                    if (s.usb != null) "إغلاق وإخراج القرص" else "أقفل الخزنة",
                    tint = Qs.brass, border = Qs.brass,
                ) { if (Jobs.busy(s.handle)) confirmClose = true else AppState.safeClose(context, s) }
            }
            Gap(14.dp)
            Row {
                Text("${humanSize(used)} من ${humanSize(s.info.total)}", style = T.small, modifier = Modifier.weight(1f))
                Text(minutesAgo(s.openedAt, now), style = T.small)
            }
            Gap(8.dp)
            UsageBar(if (s.info.total > 0) used.toFloat() / s.info.total else 0f)
        }
    }
    if (confirmClose) {
        QsAlert(
            title = "عملية جارية",
            text = "تعمل عملية في الخلفية على «${s.container.name}». إغلاقها الآن يلغي العملية.",
            confirm = "ألغِ وأغلق",
            danger = true,
            onConfirm = {
                confirmClose = false
                AppState.safeClose(context, s)
            },
            onDismiss = { confirmClose = false },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ContainerRow(c: Container) {
    val context = LocalContext.current
    val open = AppState.sessionFor(c)
    var menu by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .fillMaxWidth()
                .height(64.dp)
                .combinedClickable(
                    onClick = { if (open != null) AppState.push(Screen.Vault(open.handle)) else AppState.push(Screen.Unlock(c)) },
                    onLongClick = { menu = true },
                ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Tile(containerIcon(c), if (open != null) Qs.mint else Qs.ivory, size = 42.dp, radius = 13.dp, iconSize = 21.dp)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(c.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(containerMeta(c), style = T.mono, maxLines = 1)
            }
            if (open == null && Favorites.has(context, c.uri)) {
                QsIcon(R.drawable.ic_finger, Qs.brass, 18.dp, description = "تُفتح بالبصمة")
                Spacer(Modifier.width(4.dp))
            }
            QsIcon(if (open != null) R.drawable.ic_unlock else R.drawable.ic_lock, if (open != null) Qs.mint else Qs.muted, 18.dp)
            Spacer(Modifier.width(6.dp))
            IconBtn(R.drawable.ic_more, "خيارات", tint = Qs.muted) { menu = true }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line).align(Alignment.BottomCenter))
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }, containerColor = Qs.surface) {
            if (Favorites.has(context, c.uri)) {
                DropdownMenuItem(text = { Text("إلغاء الفتح بالبصمة", style = T.item) }, onClick = {
                    menu = false
                    Favorites.forget(context, c.uri)
                })
            }
            DropdownMenuItem(text = { Text("إزالة من القائمة", style = T.item) }, onClick = {
                menu = false
                confirmRemove = true
            })
        }
    }
    if (confirmRemove) {
        QsAlert(
            title = "إزالة من القائمة",
            text = "سيُزال «${c.name}» من القائمة فقط، ولن يُحذف الملف نفسه.",
            confirm = "إزالة",
            onConfirm = {
                confirmRemove = false
                AppState.sessionFor(c)?.let { AppState.closeSession(it.handle) }
                Favorites.forget(context, c.uri)
                AppState.removeContainer(c)
                Saf.release(context, Uri.parse(c.uri))
            },
            onDismiss = { confirmRemove = false },
        )
    }
}
