package com.qscrypt.app.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.webkit.MimeTypeMap
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.qscrypt.app.AppState
import com.qscrypt.app.Item
import com.qscrypt.app.Jobs
import com.qscrypt.app.PhoneClip
import com.qscrypt.app.PhoneFiles
import com.qscrypt.app.PhoneItem
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Screen
import com.qscrypt.app.Session
import com.qscrypt.app.Transfers
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ---------------------------------------------------------------- access

/** Whether the app may read the phone's files, refreshed when the user comes back from settings. */
@Composable
private fun rememberAccess(): Pair<Boolean, () -> Unit> {
    val context = LocalContext.current
    var granted by remember { mutableStateOf(PhoneFiles.hasAccess(context)) }
    val owner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) granted = PhoneFiles.hasAccess(context) }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
    val perms = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted = PhoneFiles.hasAccess(context) }
    val ask = {
        AppState.pickerOpen = true
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                context.startActivity(PhoneFiles.accessIntent(context))
            } catch (e: ActivityNotFoundException) {
                runCatching { context.startActivity(PhoneFiles.accessIntentFallback()) }
            }
        } else {
            perms.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
        }
    }
    return granted to ask
}

@Composable
private fun AccessCard(onAsk: () -> Unit) {
    QsCard(glow = true) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tile(R.drawable.ic_folder, Qs.brass)
                Spacer(Modifier.width(12.dp))
                Text("الوصول إلى ملفات الهاتف", style = T.itemLarge)
            }
            Gap(10.dp)
            Text(
                "لتتصفّح ملفات هاتفك وتشفّرها مباشرة كما في «ملفاتي»، يحتاج QsCrypt إذن «الوصول إلى كل الملفات». التطبيق بلا إنترنت: لا يخرج أي ملف من هاتفك.",
                style = T.body.copy(color = Qs.muted),
            )
            Gap(14.dp)
            PrimaryButton("اسمح بالوصول", icon = R.drawable.ic_key, onClick = onAsk)
        }
    }
}

// ---------------------------------------------------------------- the tab

/** "ملفاتي": the phone's storage, categories, recent files, search, and encrypting it all. */
@Composable
fun PhoneScreen() {
    val context = LocalContext.current
    val (granted, ask) = rememberAccess()
    var query by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<PhoneItem>?>(null) }
    var recent by remember { mutableStateOf<List<PhoneItem>>(emptyList()) }
    var volumes by remember { mutableStateOf<List<PhoneFiles.Volume>>(emptyList()) }

    LaunchedEffect(granted) {
        if (!granted) return@LaunchedEffect
        volumes = withContext(Dispatchers.IO) { PhoneFiles.volumes(context) }
        recent = withContext(Dispatchers.IO) { PhoneFiles.category(context, PhoneFiles.Category.Recent).take(8) }
    }
    LaunchedEffect(query, granted) {
        results = null
        if (!granted || query.isBlank()) return@LaunchedEffect
        delay(300)
        results = withContext(Dispatchers.IO) { PhoneFiles.search(context, query) }
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            Row(Modifier.height(48.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("ملفاتي", style = T.display.copy(lineHeight = 36.sp))
            }
            Text("ملفات هاتفك: تصفّحها، وانقلها إلى خزنة، أو شفّرها دفعة واحدة.", style = T.small)
            Gap(16.dp)
            if (!granted) {
                AccessCard(ask)
            } else {
                QsField(value = query, onValueChange = { query = it }, placeholder = "ابحث في ملفات الهاتف", height = 48.dp, leading = { QsIcon(R.drawable.ic_search, Qs.muted) })
                Gap(16.dp)
                if (query.isNotBlank()) {
                    val r = results
                    when {
                        r == null -> Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp) }
                        r.isEmpty() -> Text("لا نتائج", style = T.item.copy(color = Qs.muted))
                        else -> {
                            Text("${r.size} نتيجة", style = T.small)
                            Gap(6.dp)
                            r.forEach { PhoneRow(it, selected = false, selecting = false, showPath = true, onOpen = { openItem(context, it) }, onLongClick = {}) }
                        }
                    }
                } else {
                    volumes.forEach { v ->
                        QsCard(onClick = { AppState.push(Screen.PhoneDir(v.root.absolutePath)) }) {
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Tile(if (v.removable) R.drawable.ic_drive else R.drawable.ic_folder, Qs.brass, size = 40.dp, iconSize = 20.dp)
                                    Spacer(Modifier.width(12.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(v.title, style = T.itemLarge)
                                        Text("${humanSize(v.total - v.free)} مستخدمة من ${humanSize(v.total)}", style = T.small)
                                    }
                                    QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
                                }
                                Gap(10.dp)
                                UsageBar(if (v.total > 0) (v.total - v.free).toFloat() / v.total else 0f)
                            }
                        }
                        Gap(10.dp)
                    }
                    Gap(8.dp)
                    SectionLabel("الأقسام")
                    Gap(8.dp)
                    CategoryGrid()
                    Gap(16.dp)
                    QsCard(glow = true, onClick = { AppState.push(Screen.EncryptPhone) }) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Tile(R.drawable.ic_shield, Qs.mint)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text("شفّر ملفاتك الشخصية", style = T.itemLarge)
                                Text("صور الكاميرا، لقطات الشاشة، المستندات، التنزيلات… إلى خزنة، دفعة واحدة", style = T.small)
                            }
                            QsIcon(R.drawable.ic_chev, Qs.muted, 18.dp)
                        }
                    }
                    if (recent.isNotEmpty()) {
                        Gap(18.dp)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            SectionLabel("الحديثة", modifier = Modifier.weight(1f))
                            Text("الكل", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable { AppState.push(Screen.PhoneCategory(PhoneFiles.Category.Recent.name)) }.padding(8.dp))
                        }
                        recent.forEach { PhoneRow(it, selected = false, selecting = false, showPath = false, onOpen = { openItem(context, it) }, onLongClick = {}) }
                    }
                }
            }
            Gap(24.dp)
        }
        BottomNav(Screen.Phone)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CategoryGrid() {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(10.dp), maxItemsInEachRow = 4) {
        PhoneFiles.Category.entries.filter { it != PhoneFiles.Category.Recent }.forEach { c ->
            Column(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(16.dp))
                    .background(Qs.surface)
                    .clickable { AppState.push(Screen.PhoneCategory(c.name)) }
                    .padding(vertical = 14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                QsIcon(c.icon, Qs.brass, 24.dp)
                Gap(6.dp)
                Text(c.title, style = T.label.copy(fontSize = 12.sp, color = Qs.ivory), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

// ---------------------------------------------------------------- folders and categories

/** A folder of the phone. */
@Composable
fun PhoneDirScreen(path: String) = PhoneListScreen(dir = File(path), category = null)

/** A category (all pictures, documents…). */
@Composable
fun PhoneCategoryScreen(name: String) = PhoneListScreen(dir = null, category = runCatching { PhoneFiles.Category.valueOf(name) }.getOrDefault(PhoneFiles.Category.Recent))

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PhoneListScreen(dir: File?, category: PhoneFiles.Category?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val (granted, ask) = rememberAccess()
    var items by remember(dir, category) { mutableStateOf<List<PhoneItem>?>(null) }
    var refresh by remember { mutableIntStateOf(0) }
    var hidden by remember { mutableStateOf(false) }
    var sortBy by remember { mutableIntStateOf(Prefs.sortBy) }
    var sortDesc by remember { mutableStateOf(Prefs.sortDesc) }
    var selected by remember(dir, category) { mutableStateOf(setOf<String>()) }
    var toVault by remember { mutableStateOf<Boolean?>(null) }   // copy (false) or move (true) into a vault
    var renameFor by remember { mutableStateOf<PhoneItem?>(null) }
    var askDelete by remember { mutableStateOf(false) }
    var newFolder by remember { mutableStateOf(false) }
    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    val selecting = selected.isNotEmpty()
    val ended: (Jobs.Job) -> Unit = { refresh++ }

    BackHandler(enabled = selecting) { selected = emptySet() }

    LaunchedEffect(dir, category, refresh, hidden, granted) {
        if (!granted) return@LaunchedEffect
        items = withContext(Dispatchers.IO) {
            if (dir != null) PhoneFiles.list(dir, hidden) else PhoneFiles.category(context, category!!)
        }
    }

    val order = remember(sortBy, sortDesc) { phoneOrder(sortBy, sortDesc) }
    val shown = (items ?: emptyList()).let { if (category == PhoneFiles.Category.Recent && sortBy == 0 && !sortDesc) it else it.sortedWith(order) }
    val picked = shown.filter { it.path in selected }
    val title = when {
        category != null -> category.title
        dir == null -> "ملفاتي"
        else -> PhoneFiles.volumes(context).firstOrNull { it.root == dir }?.title ?: dir.name
    }
    val vaultClip = AppState.clip
    val phoneClip = AppState.phoneClip

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Gap(12.dp)
        if (selecting) {
            Row(Modifier.fillMaxWidth().height(48.dp), verticalAlignment = Alignment.CenterVertically) {
                IconBtn(R.drawable.ic_close, "إلغاء التحديد") { selected = emptySet() }
                Spacer(Modifier.width(8.dp))
                Text("${selected.size} محدد", style = T.title, modifier = Modifier.weight(1f))
                Text(
                    if (selected.size == shown.size) "لا شيء" else "الكل",
                    style = T.label.copy(color = Qs.brass),
                    modifier = Modifier.clickable { selected = if (selected.size == shown.size) emptySet() else shown.map { it.path }.toSet() }.padding(10.dp),
                )
            }
            Gap(6.dp)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("إلى خزنة", Qs.mint, icon = R.drawable.ic_vault) { toVault = false }
                Pill("نقل إلى خزنة", Qs.mint, icon = R.drawable.ic_lock) { toVault = true }
                if (picked.none { it.dir }) Pill("ملف QsCrypt", Qs.brass, icon = R.drawable.ic_shield) {
                    AppState.encryptShared = picked.map { Uri.fromFile(it.file) }
                    selected = emptySet()
                    AppState.push(Screen.QscEncrypt)
                }
                Pill("نسخ", Qs.ivory, icon = R.drawable.ic_folder) {
                    AppState.phoneClip = PhoneClip(picked.map { it.path }, move = false)
                    selected = emptySet()
                    Toast.makeText(context, "نُسخ ${picked.size}. الصقها في مجلد آخر أو داخل خزنة.", Toast.LENGTH_SHORT).show()
                }
                Pill("قص", Qs.ivory, icon = R.drawable.ic_folderplus) {
                    AppState.phoneClip = PhoneClip(picked.map { it.path }, move = true)
                    selected = emptySet()
                    Toast.makeText(context, "قُصّ ${picked.size}. الصقها في مجلد آخر أو داخل خزنة.", Toast.LENGTH_SHORT).show()
                }
                if (picked.none { it.dir }) Pill("مشاركة", Qs.ivory, icon = R.drawable.ic_share) { share(context, picked.map { it.file }) }
                if (picked.size == 1) Pill("إعادة تسمية", Qs.ivory, icon = R.drawable.ic_edit) { renameFor = picked.first() }
                Pill("حذف", Qs.coral, icon = R.drawable.ic_trash) { askDelete = true }
            }
        } else {
            TopBar(title, onBack = { AppState.pop() }) {
                if (dir != null) {
                    IconBtn(R.drawable.ic_eye, if (hidden) "إخفاء الملفات المخفية" else "إظهار الملفات المخفية", tint = if (hidden) Qs.brass else Qs.muted) { hidden = !hidden }
                    IconBtn(R.drawable.ic_folderplus, "مجلد جديد", tint = Qs.muted) { newFolder = true }
                }
            }
            if (dir != null) Text(dir.absolutePath, style = T.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
            // Paste: phone files copied or cut elsewhere, or files from a vault (decrypted here).
            if (dir != null && (phoneClip != null || vaultClip != null)) {
                Gap(8.dp)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (phoneClip != null) Pill("الصق هنا (${phoneClip.paths.size})", Qs.brass, icon = R.drawable.ic_folder) {
                        AppState.phoneClip = null
                        job = phoneCopy(context, phoneClip, dir, ended)
                    }
                    if (vaultClip != null) {
                        val from = AppState.session(vaultClip.handle)
                        if (from != null) Pill("الصق من «${vaultClip.vaultName.substringBeforeLast('.')}» (${vaultClip.names.size})", Qs.mint, icon = R.drawable.ic_vault) {
                            AppState.clip = null
                            scope.launch {
                                val entries = withContext(Dispatchers.IO) { com.qscrypt.app.parseEntries(Reply(com.qscrypt.app.QsCore.list(from.handle, vaultClip.dir)).json) }
                                val chosen = entries.filter { it.name in vaultClip.names }.map { Item(it.name, it.dir, it.size) }
                                job = Transfers.exportPhone(context, from, vaultClip.dir, chosen, dir.absolutePath, vaultClip.move, onEnd = ended)
                            }
                        }
                    }
                }
            }
        }
        Gap(10.dp)
        if (!granted) {
            AccessCard(ask)
        } else {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("ترتيب:", style = T.small)
                listOf("الاسم", "التاريخ", "الحجم").forEachIndexed { i, label ->
                    val arrow = if (sortBy == i) (if (sortDesc) " ↓" else " ↑") else ""
                    Chip(label + arrow, sortBy == i) {
                        if (sortBy == i) sortDesc = !sortDesc else {
                            sortBy = i
                            sortDesc = i != 0
                        }
                        Prefs.sortBy = sortBy
                        Prefs.sortDesc = sortDesc
                    }
                }
            }
            Gap(8.dp)
            val list = items
            when {
                list == null -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp) }
                shown.isEmpty() -> Column(Modifier.fillMaxWidth().padding(vertical = 40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    QsIcon(R.drawable.ic_folder, Qs.muted, 40.dp)
                    Gap(12.dp)
                    Text(if (dir != null) "المجلد فارغ" else "لا شيء هنا", style = T.item.copy(color = Qs.muted))
                }
                else -> LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
                    items(shown, key = { it.path }) { it ->
                        PhoneRow(
                            it,
                            selected = it.path in selected,
                            selecting = selecting,
                            showPath = category != null,
                            onOpen = {
                                when {
                                    selecting -> selected = if (it.path in selected) selected - it.path else selected + it.path
                                    it.dir -> AppState.push(Screen.PhoneDir(it.path))
                                    else -> openItem(context, it)
                                }
                            },
                            onLongClick = { selected = if (it.path in selected) selected - it.path else selected + it.path },
                        )
                    }
                    item { Gap(16.dp) }
                }
            }
        }
    }

    toVault?.let { move ->
        VaultPicker(
            move = move,
            count = picked.size,
            onPick = { s ->
                toVault = null
                job = Transfers.importPhone(context, s, "/", picked.map { it.path }, move, onEnd = ended)
                selected = emptySet()
            },
            onDismiss = { toVault = null },
        )
    }
    renameFor?.let { it ->
        InputDialog("إعادة تسمية", it.name, "حفظ", onConfirm = { name ->
            renameFor = null
            if (PhoneFiles.rename(it.file, name) == null) Toast.makeText(context, "تعذّرت إعادة التسمية: الاسم مستخدم أو غير صالح.", Toast.LENGTH_SHORT).show()
            selected = emptySet()
            refresh++
        }, onDismiss = { renameFor = null })
    }
    if (newFolder && dir != null) {
        InputDialog("مجلد جديد", "", "إنشاء", placeholder = "اسم المجلد", onConfirm = { name ->
            newFolder = false
            if (!PhoneFiles.mkdir(dir, name)) Toast.makeText(context, "تعذّر إنشاء المجلد.", Toast.LENGTH_SHORT).show()
            refresh++
        }, onDismiss = { newFolder = false })
    }
    if (askDelete) {
        QsAlert(
            "حذف ${picked.size} ${if (picked.size == 1) "عنصر" else "عناصر"}",
            "يُحذف من الهاتف نهائياً، ولا يمر بسلة المحذوفات.",
            "حذف",
            onConfirm = {
                askDelete = false
                val files = picked.map { it.file }
                selected = emptySet()
                job = Jobs.start(context, "phoneDelete", "حذف ${files.size} من الهاتف", onEnd = ended) work@{
                    val n = PhoneFiles.delete(files)
                    Reply(JSONObject().put("ok", true).put("summary", "حُذف $n من ${files.size}.").toString())
                }
            },
            onDismiss = { askDelete = false },
            danger = true,
        )
    }
    job?.let { j -> JobDialog(j, onClose = { job = null }) }
}

/** Phone files pasted into another phone folder (a move within one storage is a rename). */
private fun phoneCopy(context: Context, clip: PhoneClip, dest: File, onEnd: (Jobs.Job) -> Unit): Jobs.Job {
    val files = clip.paths.map(::File).filter { it.exists() }
    val verb = if (clip.move) "نقل" else "نسخ"
    return Jobs.start(context, "phoneCopy", "$verb ${files.size} إلى «${dest.name}»", onEnd = onEnd) work@{
        val total = PhoneFiles.totalSize(files)
        job.total = total
        var done = 0L
        val made = mutableListOf<File>()
        fun copyOne(src: File, into: File): Boolean {
            val target = File(into, PhoneFiles.freeName(into, src.name))
            if (src.isDirectory) {
                if (!target.mkdirs()) return false
                made += target
                for (c in src.listFiles() ?: emptyArray()) if (!copyOne(c, target)) return false
                return true
            }
            src.inputStream().use { input ->
                target.outputStream().use { out ->
                    val buf = ByteArray(1 shl 20)
                    while (true) {
                        if (job.cancelFlag.get()) return false
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        done += n
                        job.done = done
                    }
                }
            }
            target.setLastModified(src.lastModified())
            made += target
            return true
        }
        for (f in files) {
            if (!checkpoint()) return@work Reply("""{"ok":false,"code":"cancelled"}""")
            detail(f.name)
            if (f.absolutePath == dest.absolutePath || dest.absolutePath.startsWith(f.absolutePath + "/")) continue
            if (clip.move) {
                val target = File(dest, PhoneFiles.freeName(dest, f.name))
                if (f.renameTo(target)) {
                    PhoneFiles.rescan(listOf(f, target))
                    continue
                }
            }
            if (!copyOne(f, dest)) return@work Reply(JSONObject().put("ok", false).put("code", "io").put("message", "cannot copy ${f.name}").toString())
            if (clip.move) PhoneFiles.delete(listOf(f))
        }
        PhoneFiles.rescan(made)
        Reply(JSONObject().put("ok", true).put("summary", (if (clip.move) "نُقل " else "نُسخ ") + "${files.size}.").toString())
    }
}

/** Choose the open vault the selected phone files go into. */
@Composable
private fun VaultPicker(move: Boolean, count: Int, onPick: (Session) -> Unit, onDismiss: () -> Unit) {
    val vaults = AppState.sessions.filter { !it.info.readOnly }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Qs.surface,
        title = { Text(if (move) "نقل $count إلى خزنة" else "تشفير $count في خزنة", style = T.title) },
        text = {
            Column {
                if (vaults.isEmpty()) {
                    Text("لا توجد خزنة مفتوحة. افتح خزنة من «خزناتي» ثم عد إلى هنا.", style = T.body.copy(color = Qs.muted))
                } else {
                    if (move) {
                        Text("يُحذف كل أصل من الهاتف بعد كتابة نسخته المشفّرة.", style = T.small.copy(color = Qs.coral))
                        Gap(10.dp)
                    }
                    vaults.forEach { s ->
                        Row(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { onPick(s) }.padding(vertical = 10.dp, horizontal = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            QsIcon(if (s.plain) R.drawable.ic_usb else R.drawable.ic_vault, Qs.brass, 20.dp)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(s.container.name.substringBeforeLast('.').ifBlank { s.container.name }, style = T.item)
                                Text("فارغ ${humanSize(s.info.free)}" + if (s.plain) " – غير مشفّر" else "", style = T.small)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (vaults.isEmpty()) TextButton(onClick = { onDismiss(); AppState.tab(Screen.Home) }) { Text("خزناتي", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
    )
}

// ---------------------------------------------------------------- rows

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun PhoneRow(it: PhoneItem, selected: Boolean, selecting: Boolean, showPath: Boolean, onOpen: () -> Unit, onLongClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) Qs.surface2 else androidx.compose.ui.graphics.Color.Transparent)
            .combinedClickable(onClick = onOpen, onLongClick = onLongClick)
            .padding(vertical = 9.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box {
            Tile(
                when {
                    it.dir -> R.drawable.ic_folder
                    isImage(it.name) -> R.drawable.ic_image
                    isVideo(it.name) -> R.drawable.ic_video
                    isAudio(it.name) -> R.drawable.ic_music
                    ext(it.name) in DOCS || isPdf(it.name) -> R.drawable.ic_doc
                    else -> R.drawable.ic_file
                },
                if (it.dir) Qs.brass else Qs.ivory,
                size = 40.dp,
                radius = 12.dp,
                iconSize = 20.dp,
            )
            if (selecting) {
                Box(
                    Modifier.align(Alignment.BottomEnd).size(16.dp).clip(RoundedCornerShape(8.dp)).background(if (selected) Qs.brass else Qs.line),
                    contentAlignment = Alignment.Center,
                ) { if (selected) QsIcon(R.drawable.ic_check, Qs.base, 12.dp) }
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(it.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val meta = buildList {
                if (!it.dir) add(humanSize(it.size))
                if (it.mtime > 0) add(SimpleDateFormat("yyyy/MM/dd", Locale.US).format(Date(it.mtime)))
            }.joinToString(" – ")
            Text(if (showPath) (it.file.parent ?: "") else meta, style = if (showPath) T.mono else T.small, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

fun phoneOrder(by: Int, desc: Boolean): Comparator<PhoneItem> {
    val collator = java.text.Collator.getInstance(Locale("ar")).apply { strength = java.text.Collator.SECONDARY }
    val byName = Comparator<PhoneItem> { a, b -> collator.compare(a.name, b.name) }
    val key: Comparator<PhoneItem> = when (by) {
        1 -> compareBy<PhoneItem> { it.mtime }.then(byName)
        2 -> compareBy<PhoneItem> { if (it.dir) 0L else it.size }.then(byName)
        else -> byName
    }
    return compareBy<PhoneItem> { !it.dir }.then(if (desc) key.reversed() else key)
}

// ---------------------------------------------------------------- opening and sharing

private fun uriOf(context: Context, f: File): Uri = FileProvider.getUriForFile(context, "${context.packageName}.share", f)

private fun mimeOf(name: String): String =
    MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase()) ?: "*/*"

/** Opens a phone file with an app of the user's choice. */
private fun openItem(context: Context, it: PhoneItem) {
    if (it.dir) {
        AppState.push(Screen.PhoneDir(it.path))
        return
    }
    runCatching {
        val i = Intent(Intent.ACTION_VIEW).setDataAndType(uriOf(context, it.file), mimeOf(it.name)).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(i, it.name))
    }.onFailure { Toast.makeText(context, "لا يوجد تطبيق يفتح هذا الملف.", Toast.LENGTH_SHORT).show() }
}

private fun share(context: Context, files: List<File>) {
    runCatching {
        val uris = ArrayList(files.map { uriOf(context, it) })
        val i = if (uris.size == 1) Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, uris[0]).setType(mimeOf(files[0].name))
        else Intent(Intent.ACTION_SEND_MULTIPLE).putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris).setType("*/*")
        context.startActivity(Intent.createChooser(i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION), "مشاركة"))
    }.onFailure { Toast.makeText(context, "تعذّرت المشاركة.", Toast.LENGTH_SHORT).show() }
}

// ---------------------------------------------------------------- encrypt my files

/** The wizard: chosen personal folders of the phone into an open vault, optionally removing the originals. */
@Composable
fun EncryptPhoneScreen() {
    val context = LocalContext.current
    val (granted, ask) = rememberAccess()
    val folders = remember(granted) { if (granted) PhoneFiles.personal() else emptyList() }
    var chosen by remember(folders) { mutableStateOf(folders.map { it.folder.absolutePath }.toSet()) }
    var sizes by remember { mutableStateOf<Map<String, Pair<Int, Long>>>(emptyMap()) }
    val vaults = AppState.sessions.filter { !it.info.readOnly && !it.plain }
    var vault by remember { mutableStateOf(vaults.firstOrNull()?.handle) }
    var move by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf(false) }
    var started by remember { mutableStateOf(0) }

    LaunchedEffect(folders) {
        for (p in folders) {
            val (n, size) = withContext(Dispatchers.IO) { PhoneFiles.walk(listOf(p.folder)).let { fs -> fs.size to fs.sumOf { it.length() } } }
            sizes = sizes + (p.folder.absolutePath to (n to size))
        }
    }
    val target = vaults.firstOrNull { it.handle == vault }
    val totalSize = chosen.sumOf { sizes[it]?.second ?: 0L }
    val totalCount = chosen.sumOf { sizes[it]?.first ?: 0 }
    val fits = target == null || totalSize <= target.info.free

    Column(Modifier.fillMaxSize()) {
        TopBar("شفّر ملفاتك الشخصية", onBack = { AppState.pop() })
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(8.dp)
            if (!granted) {
                AccessCard(ask)
                return@Column
            }
            Note("تُنسخ الملفات مشفّرة إلى الخزنة في مجلد «من الهاتف»، بالمجلدات نفسها. إن اخترت حذف الأصول، يُحذف كل ملف من الهاتف فور كتابة نسخته المشفّرة.", icon = R.drawable.ic_shield)
            Gap(16.dp)
            SectionLabel("ما يُشفَّر")
            Gap(6.dp)
            folders.forEach { p ->
                val key = p.folder.absolutePath
                val info = sizes[key]
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).clickable { chosen = if (key in chosen) chosen - key else chosen + key }.padding(vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    QsSwitch(key in chosen) { on -> chosen = if (on) chosen + key else chosen - key }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(p.title, style = T.item)
                        Text(if (info == null) "يُحسب…" else "${info.first} ملف – ${humanSize(info.second)}", style = T.small)
                    }
                }
            }
            if (folders.isEmpty()) Text("لم يُعثر على مجلدات شخصية معروفة. استعمل تبويب «ملفاتي» لاختيار ما تريد.", style = T.small)
            Gap(16.dp)
            SectionLabel("إلى أي خزنة")
            Gap(6.dp)
            if (vaults.isEmpty()) {
                Note("لا توجد خزنة مفتوحة. افتح خزنة من «خزناتي» أولاً.", icon = R.drawable.ic_alert, color = Qs.coral)
            } else {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    vaults.forEach { s -> Chip(s.container.name.substringBeforeLast('.').ifBlank { s.container.name }, vault == s.handle) { vault = s.handle } }
                }
                target?.let {
                    Gap(6.dp)
                    Text("فارغ فيها: ${humanSize(it.info.free)}", style = T.small.copy(color = if (fits) Qs.muted else Qs.coral))
                }
            }
            Gap(16.dp)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("احذف الأصول من الهاتف", style = T.item)
                    Text("بعد تشفير كل ملف. لا تبقى نسخة غير مشفّرة.", style = T.small)
                }
                QsSwitch(move) { move = it }
            }
            Gap(20.dp)
            PrimaryButton(
                "ابدأ (${totalCount} ملف – ${humanSize(totalSize)})",
                icon = R.drawable.ic_lock,
                enabled = target != null && chosen.isNotEmpty() && totalCount > 0 && fits && started == 0,
            ) { if (move) confirm = true else started = start(context, target!!, folders.filter { it.folder.absolutePath in chosen }, false) }
            if (started > 0) {
                Gap(12.dp)
                Note("بدأ التشفير في الخلفية ($started ${if (started == 1) "عملية" else "عمليات"}). تتابعه من شريط العمليات.", icon = R.drawable.ic_check, color = Qs.mint)
            }
            Gap(24.dp)
        }
    }
    if (confirm && target != null) {
        QsAlert(
            "حذف الأصول",
            "سيُحذف $totalCount ملف من الهاتف بعد تشفيرها داخل «${target.container.name.substringBeforeLast('.')}». تأكد أنك تتذكر كلمة مرور الخزنة.",
            "ابدأ",
            onConfirm = {
                confirm = false
                started = start(context, target, folders.filter { it.folder.absolutePath in chosen }, true)
            },
            onDismiss = { confirm = false },
            danger = true,
        )
    }
}

/** One background job per folder (they run one after another). Returns how many started. */
private fun start(context: Context, s: Session, chosen: List<PhoneFiles.Personal>, move: Boolean): Int {
    val paths = chosen.map { it.folder.absolutePath }
    var n = 0
    for (p in chosen) {
        // A folder chosen on its own (Screenshots inside Pictures) is not taken twice.
        val inner = paths.filter { it != p.folder.absolutePath && it.startsWith(p.folder.absolutePath + "/") }
        val children = (p.folder.listFiles() ?: emptyArray()).filter { c -> inner.none { c.absolutePath == it || it.startsWith(c.absolutePath + "/") } }
        if (children.isEmpty()) continue
        Transfers.importPhone(context, s, "/من الهاتف/${p.vaultFolder}", children.map { it.absolutePath }, move, title = (if (move) "نقل " else "تشفير ") + p.title)
        n++
    }
    return n
}
