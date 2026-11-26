package com.qscrypt.app.ui

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.Clip
import com.qscrypt.app.Entry
import com.qscrypt.app.Fill
import com.qscrypt.app.Item
import com.qscrypt.app.Jobs
import com.qscrypt.app.Prefs
import com.qscrypt.app.Progress
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.Thumbs
import com.qscrypt.app.Transfers
import com.qscrypt.app.VolumeInfo
import com.qscrypt.app.humanSize
import com.qscrypt.app.parseEntries
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Calendar
import java.util.concurrent.atomic.AtomicBoolean

private val IMAGES = setOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif")
private val VIDEOS = setOf("mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v", "ts")
private val AUDIO = setOf("mp3", "m4a", "aac", "wav", "ogg", "flac", "opus", "amr", "mid")
private val TEXT = setOf("txt", "md", "csv", "json", "xml", "log", "html", "htm", "ini", "cfg", "conf", "yaml", "yml", "srt", "kt", "java", "py", "js")
val DOCS = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "epub") + TEXT
private val ARCHIVES = setOf("zip", "rar", "7z", "tar", "gz", "xz", "apk")
private val KEYS = setOf("kdbx", "key", "pem", "p12", "pfx", "asc", "gpg")

fun ext(name: String) = name.substringAfterLast('.', "").lowercase()
fun isImage(name: String) = ext(name) in IMAGES
fun isText(name: String) = ext(name) in TEXT
fun isVideo(name: String) = ext(name) in VIDEOS
fun isAudio(name: String) = ext(name) in AUDIO
fun isPdf(name: String) = ext(name) == "pdf"

private fun iconFor(e: Entry): Pair<Int, androidx.compose.ui.graphics.Color> {
    if (e.dir) return R.drawable.ic_folder to Qs.brass
    return when (ext(e.name)) {
        in IMAGES -> R.drawable.ic_image to Qs.mint
        in VIDEOS -> R.drawable.ic_video to Qs.coral
        in AUDIO -> R.drawable.ic_music to Qs.coral
        in KEYS -> R.drawable.ic_key to Qs.brass
        in ARCHIVES -> R.drawable.ic_archive to Qs.ivory
        in DOCS -> R.drawable.ic_doc to Qs.ivory
        else -> R.drawable.ic_file to Qs.ivory
    }
}

private val MONTHS = listOf("يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر")
private val DAYS = listOf("الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت")

fun friendlyDate(unix: Long): String {
    if (unix <= 0) return ""
    val then = Calendar.getInstance().apply { timeInMillis = unix * 1000 }
    val now = Calendar.getInstance()
    fun dayIndex(c: Calendar) = c.get(Calendar.YEAR) * 400 + c.get(Calendar.DAY_OF_YEAR)
    val diff = dayIndex(now) - dayIndex(then)
    return when {
        diff == 0 -> "اليوم"
        diff == 1 -> "أمس"
        diff in 2..6 -> DAYS[then.get(Calendar.DAY_OF_WEEK) - 1]
        then.get(Calendar.YEAR) == now.get(Calendar.YEAR) -> "${then.get(Calendar.DAY_OF_MONTH)} ${MONTHS[then.get(Calendar.MONTH)]}"
        else -> "${then.get(Calendar.DAY_OF_MONTH)} ${MONTHS[then.get(Calendar.MONTH)]} ${then.get(Calendar.YEAR)}"
    }
}

fun childPath(dir: String, name: String) = if (dir == "/" || dir.isEmpty()) "/$name" else "$dir/$name"

/** Shown while a long operation runs. */
data class Busy(val title: String, val fraction: Float?, val detail: String = "")

/** Exports a file from the vault to a document picked with CreateDocument. */
suspend fun exportTo(context: Context, handle: Long, path: String, target: Uri, progress: Progress): Reply = withContext(Dispatchers.IO) {
    val pfd = Saf.open(context, target, "wt") ?: Saf.open(context, target, "w")
    val r = pfd?.use { Reply(QsCore.exportFile(handle, path, it.fd, progress)) } ?: Reply("{\"ok\":false,\"code\":\"io\"}")
    if (!r.ok) Saf.delete(context, target)
    r
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VaultScreen(handle: Long, path: String) {
    val session = AppState.session(handle)
    if (session == null) {
        LaunchedEffect(Unit) { AppState.pop() }
        return
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var entries by remember(path) { mutableStateOf<List<Entry>?>(null) }
    var info by remember { mutableStateOf(session.info) }
    var error by remember { mutableStateOf<String?>(null) }
    var refresh by remember { mutableIntStateOf(0) }
    var tools by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var sortBy by remember { mutableIntStateOf(Prefs.sortBy) }
    var sortDesc by remember { mutableStateOf(Prefs.sortDesc) }
    var deep by remember { mutableStateOf(true) }
    var found by remember { mutableStateOf<List<Found>?>(null) }
    var foundMore by remember { mutableStateOf(false) }
    var filter by remember { mutableIntStateOf(0) }
    var newFolder by remember { mutableStateOf(false) }
    var renameFor by remember { mutableStateOf<Entry?>(null) }
    var deleteNames by remember { mutableStateOf<List<String>?>(null) }
    var cannotView by remember { mutableStateOf<Entry?>(null) }
    var pendingExport by remember { mutableStateOf<Entry?>(null) }
    var pendingTreeExport by remember { mutableStateOf<List<Entry>?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var selected by remember(path) { mutableStateOf(setOf<String>()) }
    var grid by remember { mutableStateOf(Prefs.gridView) }
    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    var addMenu by remember { mutableStateOf(false) }
    var confirmClose by remember { mutableStateOf(false) }
    val selecting = selected.isNotEmpty()
    val readOnly = info.readOnly
    val ended: (Jobs.Job) -> Unit = { refresh++ }

    BackHandler(enabled = selecting) { selected = emptySet() }

    LaunchedEffect(path, refresh) {
        val r = Reply(withContext(Dispatchers.IO) { QsCore.list(handle, path) })
        if (r.ok) {
            entries = parseEntries(r.json)
            error = null
        } else {
            error = r.error
        }
        val ir = Reply(withContext(Dispatchers.IO) { QsCore.volumeInfo(handle) })
        if (ir.ok) info = VolumeInfo.from(ir.json)
    }

    val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        val docs = uris.map { u -> Saf.meta(context, u).let { m -> Transfers.Doc(u, m.name, m.size) } }
        job = Transfers.importDocs(context, session, path, docs, ended)
    }
    val folderImporter = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        tree ?: return@rememberLauncherForActivityResult
        job = Transfers.importFolder(context, session, path, tree, ended)
    }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val e = pendingExport
        pendingExport = null
        if (uri == null || e == null) return@rememberLauncherForActivityResult
        job = Jobs.start(context, "export", "تصدير «${e.name}»", listOf(handle), onEnd = ended) work@{
            val r = exportTo(context, handle, childPath(path, e.name), uri, progress())
            if (!r.ok) return@work r
            Reply(org.json.JSONObject().put("ok", true).put("summary", "صُدّر «${e.name}». تذكّر أن النسخة المصدّرة غير مشفّرة.").toString())
        }
    }
    val treeExporter = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        val items = pendingTreeExport
        pendingTreeExport = null
        if (tree == null || items == null) return@rememberLauncherForActivityResult
        job = Transfers.exportTo(context, session, path, items.map { Item(it.name, it.dir, it.size) }, tree, ended)
        selected = emptySet()
    }

    fun export(e: Entry) {
        if (e.dir) {
            pendingTreeExport = listOf(e)
            AppState.pickerOpen = true
            treeExporter.launch(null)
        } else {
            pendingExport = e
            AppState.pickerOpen = true
            exporter.launch(e.name)
        }
    }

    // Searching every folder below this one (engine walk, after a short pause in typing).
    LaunchedEffect(query, deep, path, refresh) {
        found = null
        foundMore = false
        if (!deep || query.isBlank()) return@LaunchedEffect
        delay(300)
        val r = withContext(Dispatchers.IO) { Call("fs.find").put("handle", handle).put("path", path).put("query", query.trim()).put("max", 500).run() }
        if (r.ok) {
            val arr = r.json.optJSONArray("entries") ?: org.json.JSONArray()
            found = (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Found(o.optString("path"), Entry(o.optString("name"), o.optBoolean("dir"), o.optLong("size"), o.optLong("mtime")))
            }
            foundMore = r.json.optBoolean("truncated")
        } else {
            found = emptyList()
        }
    }

    fun openAt(dir: String, e: Entry) {
        val p = childPath(dir, e.name)
        when {
            e.dir -> AppState.push(Screen.Vault(handle, p))
            isImage(e.name) -> AppState.push(Screen.Gallery(handle, dir, e.name))
            isVideo(e.name) || isAudio(e.name) -> AppState.push(Screen.Media(handle, p, e.name, e.size))
            isPdf(e.name) -> AppState.push(Screen.Pdf(handle, p, e.name, e.size))
            isText(e.name) -> AppState.push(Screen.Viewer(handle, p, e.name, e.size))
            else -> cannotView = e
        }
    }

    fun open(e: Entry) = openAt(path, e)

    fun toggle(e: Entry) {
        selected = if (e.name in selected) selected - e.name else selected + e.name
    }

    fun runOp(op: () -> String) {
        scope.launch {
            val r = Reply(withContext(Dispatchers.IO) { op() })
            if (!r.ok) message = r.error
            refresh++
        }
    }

    fun toClipboard(move: Boolean) {
        val names = selected.toList()
        AppState.clip = Clip(handle, path, names, move, session.container.name)
        selected = emptySet()
        Toast.makeText(
            context,
            (if (move) "قُصّ" else "نُسخ") + " ${names.size} ${if (names.size == 1) "عنصر" else "عناصر"}. افتح المجلد أو الخزنة الهدف واضغط «الصق هنا».",
            Toast.LENGTH_LONG,
        ).show()
    }

    fun paste() {
        val c = AppState.clip ?: return
        val from = AppState.session(c.handle)
        if (from == null) {
            AppState.clip = null
            message = "أُغلقت الخزنة التي نسخت منها. افتحها وانسخ من جديد."
            return
        }
        AppState.clip = null
        job = Transfers.copy(context, from, c.dir, c.names, session, path, c.move, onEnd = ended)
    }

    val all = entries ?: emptyList()
    fun kindOk(e: Entry) = when (filter) {
        1 -> e.dir || isImage(e.name)
        2 -> e.dir || ext(e.name) in DOCS
        3 -> e.dir || isVideo(e.name) || isAudio(e.name)
        else -> true
    }
    val order = remember(sortBy, sortDesc) { entryOrder(sortBy, sortDesc) }
    val shown = all.filter { e -> (query.isBlank() || e.name.contains(query, ignoreCase = true)) && kindOk(e) }.sortedWith(order)
    val searchingAll = deep && query.isNotBlank()
    val foundShown = found?.filter { kindOk(it.entry) }?.sortedWith(compareBy<Found> { !it.entry.dir }.thenComparator { a, b -> order.compare(a.entry, b.entry) })
    val used = (info.total - info.free).coerceAtLeast(0)
    val fileCount = all.count { !it.dir }
    val title = if (path == "/") session.container.name.substringBeforeLast('.').ifBlank { session.container.name } else path.substringAfterLast('/')
    val clipboard = AppState.clip
    val canPaste = clipboard != null && !readOnly && !(clipboard.handle == handle && clipboard.dir == path)
    val fill = Fill.running(session)

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            if (selecting) {
                // Selection bar: what can be done with the chosen items.
                Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconBtn(R.drawable.ic_close, "إلغاء التحديد") { selected = emptySet() }
                    Spacer(Modifier.width(8.dp))
                    Text("${selected.size} محدد", style = T.h1.copy(fontSize = 22.sp, lineHeight = 28.sp), modifier = Modifier.weight(1f))
                    Text(
                        if (selected.size == shown.size) "لا شيء" else "الكل",
                        style = T.label.copy(color = Qs.brass),
                        modifier = Modifier.clickable { selected = if (selected.size == shown.size) emptySet() else shown.map { it.name }.toSet() }.padding(10.dp),
                    )
                }
                Gap(6.dp)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Pill("نسخ", Qs.brass, icon = R.drawable.ic_folder) { toClipboard(false) }
                    if (!readOnly) Pill("قص", Qs.brass, icon = R.drawable.ic_folderplus) { toClipboard(true) }
                    Pill("تصدير", Qs.ivory, icon = R.drawable.ic_export) {
                        pendingTreeExport = all.filter { it.name in selected }
                        AppState.pickerOpen = true
                        treeExporter.launch(null)
                    }
                    if (selected.size == 1 && !readOnly) Pill("إعادة تسمية", Qs.ivory, icon = R.drawable.ic_edit) { renameFor = all.firstOrNull { it.name in selected } }
                    if (!readOnly) Pill("حذف", Qs.coral, icon = R.drawable.ic_trash) { deleteNames = selected.toList() }
                }
            } else {
                Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconBtn(R.drawable.ic_back, "رجوع") { AppState.pop() }
                    Spacer(Modifier.width(6.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(title, style = T.h1.copy(lineHeight = 30.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            if (session.plain) Tag("غير مشفّر", TagKind.Outline) else {
                                Tag(info.format)
                                Tag(info.ea)
                            }
                            Tag(info.fs)
                            if (readOnly) Tag("للقراءة فقط", TagKind.Outline)
                            if (info.hidden) Tag("مخفية", TagKind.Mint)
                            if (info.protected) Tag("المخفي محمي", TagKind.Mint)
                            if (info.extra.optBoolean("togo")) Tag("To Go", TagKind.Outline)
                            if (session.usb != null) Tag("USB", TagKind.Outline)
                        }
                    }
                    IconBtn(if (grid) R.drawable.ic_doc else R.drawable.ic_image, if (grid) "عرض كقائمة" else "عرض كشبكة صور", tint = Qs.muted) {
                        grid = !grid
                        Prefs.gridView = grid
                    }
                    if (!session.plain) IconBtn(R.drawable.ic_sliders, "أدوات الخزنة", tint = Qs.muted) { tools = true }
                    Row(
                        Modifier
                            .height(40.dp)
                            .clickable { if (Jobs.busy(handle)) confirmClose = true else AppState.safeClose(context, session) }
                            .padding(horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        QsIcon(if (session.usb != null) R.drawable.ic_usb else R.drawable.ic_lock, Qs.brass, 18.dp)
                        Spacer(Modifier.width(6.dp))
                        Text(if (session.usb != null) "إخراج" else if (session.plain) "إغلاق" else "أقفل", style = T.label.copy(color = Qs.brass))
                    }
                }
            }
            // Other open vaults, one tap away (to paste into, or just to switch).
            val others = AppState.sessions.filter { it.handle != handle }
            if (others.isNotEmpty() && !selecting) {
                Gap(8.dp)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("مفتوحة أيضاً:", style = T.small)
                    others.forEach { o ->
                        Pill(o.container.name.substringBeforeLast('.').ifBlank { o.container.name }, Qs.muted, icon = if (o.plain) R.drawable.ic_usb else R.drawable.ic_vault) {
                            AppState.push(Screen.Vault(o.handle))
                        }
                    }
                }
            }
            if (path != "/") {
                Gap(6.dp)
                Text(path, style = T.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Gap(14.dp)
            Row {
                Text("${humanSize(used)} من ${humanSize(info.total)} مستخدمة", style = T.small, modifier = Modifier.weight(1f))
                Text("$fileCount ملفاً", style = T.small)
            }
            Gap(8.dp)
            UsageBar(if (info.total > 0) used.toFloat() / info.total else 0f)
            if (fill != null) {
                Gap(8.dp)
                Row(Modifier.fillMaxWidth().clickable { AppState.push(Screen.JobsList) }, verticalAlignment = Alignment.CenterVertically) {
                    QsIcon(R.drawable.ic_shield, Qs.mint, 15.dp)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "يُملأ الفراغ ببيانات مشفّرة في الخلفية" + (fill.fraction?.let { " · ${(it * 100).toInt()}%" } ?: "") + if (fill.state == Jobs.State.Paused) " (متوقف)" else "",
                        style = T.small.copy(color = Qs.mint),
                    )
                }
            } else if (Fill.pending(session) && Fill.possible(session)) {
                Gap(8.dp)
                Row(Modifier.fillMaxWidth().clickable { job = Fill.start(context, session) }, verticalAlignment = Alignment.CenterVertically) {
                    QsIcon(R.drawable.ic_shield, Qs.brass, 15.dp)
                    Spacer(Modifier.width(6.dp))
                    Text("ملء الفراغ لم يكتمل · اضغط للمتابعة", style = T.small.copy(color = Qs.brass))
                }
            }
            Gap(14.dp)
            QsField(value = query, onValueChange = { query = it }, placeholder = "ابحث داخل الخزنة", height = 48.dp, leading = { QsIcon(R.drawable.ic_search, Qs.muted) })
            Gap(12.dp)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("الكل", "صور", "مستندات", "فيديو وصوت").forEachIndexed { i, label -> Chip(label, filter == i) { filter = i } }
            }
            Gap(8.dp)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                if (query.isNotBlank()) {
                    Chip("كل المجلدات الفرعية", deep) { deep = true }
                    Chip("هذا المجلد فقط", !deep) { deep = false }
                    Spacer(Modifier.width(6.dp))
                }
                Text("ترتيب:", style = T.small)
                listOf("الاسم", "التاريخ", "الحجم").forEachIndexed { i, label ->
                    val arrow = if (sortBy == i) (if (sortDesc) " ↓" else " ↑") else ""
                    Chip(label + arrow, sortBy == i) {
                        if (sortBy == i) sortDesc = !sortDesc else {
                            sortBy = i
                            // Dates and sizes are most useful newest / largest first.
                            sortDesc = i != 0
                        }
                        Prefs.sortBy = sortBy
                        Prefs.sortDesc = sortDesc
                    }
                }
            }
            Gap(10.dp)
            when {
                searchingAll -> when {
                    foundShown == null -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp)
                    }
                    foundShown.isEmpty() -> Column(Modifier.fillMaxWidth().padding(vertical = 40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        QsIcon(R.drawable.ic_search, Qs.muted, 40.dp)
                        Gap(12.dp)
                        Text("لا نتائج في هذا المجلد وما تحته", style = T.item.copy(color = Qs.muted))
                    }
                    else -> LazyColumn(Modifier.fillMaxWidth()) {
                        item {
                            Text("${foundShown.size}${if (foundMore) "+" else ""} نتيجة", style = T.small)
                            Gap(6.dp)
                        }
                        items(foundShown, key = { it.path }) { f ->
                            FoundRow(f, path) { openAt(f.path.substringBeforeLast('/').ifEmpty { "/" }, f.entry) }
                        }
                        item { Gap(16.dp) }
                    }
                }
                error != null -> Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
                entries == null -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp)
                }
                shown.isEmpty() -> Column(Modifier.fillMaxWidth().padding(vertical = 40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    QsIcon(R.drawable.ic_folder, Qs.muted, 40.dp)
                    Gap(12.dp)
                    Text(if (all.isEmpty()) (if (session.plain) "القرص فارغ" else "الخزنة فارغة") else "لا نتائج", style = T.item.copy(color = Qs.muted))
                    if (all.isEmpty() && !readOnly) {
                        Gap(6.dp)
                        Text(if (session.plain) "انسخ إليه ملفات من خزنة أو من الجهاز." else "أضف ملفات لتُشفَّر داخلها تلقائياً.", style = T.small)
                    }
                }
                grid -> LazyVerticalGrid(GridCells.Adaptive(minSize = 104.dp), Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(shown, key = { it.name }) { e ->
                        GridCell(
                            handle, path, e,
                            selected = e.name in selected,
                            onClick = { if (selecting) toggle(e) else open(e) },
                            onLongClick = { toggle(e) },
                        )
                    }
                }
                else -> LazyColumn(Modifier.fillMaxWidth()) {
                    items(shown, key = { it.name }) { e ->
                        FileRow(
                            handle, path, e,
                            readOnly = readOnly,
                            selecting = selecting,
                            selected = e.name in selected,
                            onOpen = { if (selecting) toggle(e) else open(e) },
                            onLongClick = { toggle(e) },
                            onExport = { export(e) },
                            onCopy = { selected = setOf(e.name); toClipboard(false) },
                            onCut = { selected = setOf(e.name); toClipboard(true) },
                            onRename = { renameFor = e },
                            onDelete = { deleteNames = listOf(e.name) },
                        )
                    }
                    item { Gap(16.dp) }
                }
            }
        }
        Column(Modifier.fillMaxWidth().background(Qs.base)) {
            Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))
            if (AppState.shared.isNotEmpty() && !readOnly) {
                // Files shared from another app: add them here.
                Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("${AppState.shared.size} ${if (AppState.shared.size == 1) "ملف مشترك" else "ملفات مشتركة"}", style = T.item)
                        Text("من تطبيق آخر، تُضاف مشفّرة", style = T.small)
                    }
                    Pill("أضفها هنا", Qs.brass) {
                        val docs = AppState.shared.map { u -> Saf.meta(context, u).let { m -> Transfers.Doc(u, m.name, m.size) } }
                        AppState.shared = emptyList()
                        job = Transfers.importDocs(context, session, path, docs, ended)
                    }
                    Spacer(Modifier.width(6.dp))
                    IconBtn(R.drawable.ic_close, "تجاهل", tint = Qs.muted) { AppState.shared = emptyList() }
                }
            }
            if (clipboard != null) {
                // Something was copied or cut: paste it here.
                Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text((if (clipboard.move) "قص " else "نسخ ") + if (clipboard.names.size == 1) "«${clipboard.names[0]}»" else "${clipboard.names.size} عناصر", style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            when {
                                readOnly -> "هذه الخزنة للقراءة فقط"
                                !canPaste -> "افتح مجلداً آخر أو خزنة أخرى للصق"
                                else -> "من «${clipboard.vaultName.substringBeforeLast('.')}»"
                            },
                            style = T.small, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Pill("الصق هنا", Qs.brass, enabled = canPaste) { paste() }
                    Spacer(Modifier.width(6.dp))
                    IconBtn(R.drawable.ic_close, "إلغاء النسخ", tint = Qs.muted) { AppState.clip = null }
                }
            }
            if (readOnly) {
                Box(Modifier.padding(horizontal = 20.dp, vertical = 14.dp)) {
                    Note(
                        when {
                            info.fs == "NTFS" -> "NTFS يُفتح للقراءة فقط في هذا الإصدار. يمكنك عرض الملفات ونسخها وتصديرها."
                            info.extra.optBoolean("eow") -> "قرص BitLocker مشفّر جزئياً (Encrypt used space only) يُفتح للقراءة فقط."
                            else -> "مفتوحة للقراءة فقط. يمكنك عرض الملفات ونسخها وتصديرها."
                        },
                        icon = R.drawable.ic_eye,
                    )
                }
            } else {
                Row(Modifier.padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 22.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(Modifier.weight(1.4f)) {
                        PrimaryButton("أضف", icon = R.drawable.ic_plus) { addMenu = true }
                        DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }, containerColor = Qs.surface) {
                            DropdownMenuItem(text = { Text("ملفات من الجهاز", style = T.item) }, onClick = {
                                addMenu = false
                                AppState.pickerOpen = true
                                importer.launch(arrayOf("*/*"))
                            })
                            DropdownMenuItem(text = { Text("مجلد كامل من الجهاز", style = T.item) }, onClick = {
                                addMenu = false
                                AppState.pickerOpen = true
                                folderImporter.launch(null)
                            })
                        }
                    }
                    SecondaryButton("مجلد جديد", modifier = Modifier.weight(1f), icon = R.drawable.ic_folderplus) { newFolder = true }
                }
            }
        }
    }

    job?.let { j -> JobDialog(j, onClose = { job = null }) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
    if (newFolder) {
        InputDialog("مجلد جديد", "", "إنشاء", placeholder = "اسم المجلد", onConfirm = { name ->
            newFolder = false
            runOp { QsCore.mkdir(handle, childPath(path, name)) }
        }, onDismiss = { newFolder = false })
    }
    renameFor?.let { e ->
        InputDialog("إعادة تسمية", e.name, "حفظ", onConfirm = { name ->
            renameFor = null
            selected = emptySet()
            if (name != e.name) runOp { QsCore.rename(handle, childPath(path, e.name), name) }
        }, onDismiss = { renameFor = null })
    }
    deleteNames?.let { names ->
        val one = all.firstOrNull { it.name == names.singleOrNull() }
        QsAlert(
            title = if (names.size > 1) "حذف ${names.size} عناصر" else if (one?.dir == true) "حذف المجلد" else "حذف الملف",
            text = when {
                names.size > 1 -> "ستُحذف العناصر المحددة وكل ما بداخل المجلدات منها نهائياً."
                one?.dir == true -> "سيُحذف «${names[0]}» وكل ما بداخله نهائياً."
                else -> "سيُحذف «${names[0]}» نهائياً."
            },
            confirm = "حذف",
            danger = true,
            onConfirm = {
                deleteNames = null
                selected = emptySet()
                if (names.size == 1) runOp { QsCore.remove(handle, childPath(path, names[0])) } else job = Transfers.delete(context, session, path, names, ended)
            },
            onDismiss = { deleteNames = null },
        )
    }
    cannotView?.let { e ->
        QsAlert(
            title = e.name,
            text = "لا يُعرض هذا النوع داخل التطبيق. يمكنك تصديره وفتحه بتطبيق آخر، علماً أن النسخة المصدّرة تكون غير مشفّرة.",
            confirm = "تصدير",
            onConfirm = {
                cannotView = null
                export(e)
            },
            onDismiss = { cannotView = null },
        )
    }
    if (confirmClose) {
        QsAlert(
            title = "عملية جارية",
            text = "تعمل عملية في الخلفية على هذه الخزنة. إغلاقها الآن يلغي العملية (ويمكن استئناف النسخ وملء الفراغ لاحقاً).",
            confirm = "ألغِ وأغلق",
            danger = true,
            onConfirm = {
                confirmClose = false
                AppState.safeClose(context, session)
            },
            onDismiss = { confirmClose = false },
        )
    }
    if (tools) VaultTools(session, onJob = { job = it }) { tools = false }
}

/** A picture's thumbnail, read and shrunk in memory, or the file's icon. */
@Composable
private fun Thumb(handle: Long, dir: String, e: Entry, size: Dp, radius: Dp) {
    val (icon, color) = iconFor(e)
    if (!isImage(e.name)) {
        Tile(icon, color, size = size, radius = radius, iconSize = size / 2)
        return
    }
    val path = childPath(dir, e.name)
    val img by produceState(Thumbs.cached(handle, path), handle, path) {
        if (value == null) value = withContext(Dispatchers.IO) { Thumbs.load(handle, path, e.size) }
    }
    val bmp = img
    if (bmp == null) {
        Tile(icon, color, size = size, radius = radius, iconSize = size / 2)
    } else {
        Image(bmp, contentDescription = null, contentScale = ContentScale.Crop, modifier = Modifier.size(size).clip(RoundedCornerShape(radius)))
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun GridCell(handle: Long, dir: String, e: Entry, selected: Boolean, onClick: () -> Unit, onLongClick: () -> Unit) {
    Column(
        Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(if (selected) Qs.brass.copy(alpha = 0.18f) else Qs.surface)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box {
            Thumb(handle, dir, e, 92.dp, 12.dp)
            if (selected) {
                Box(Modifier.align(Alignment.TopEnd).padding(4.dp).size(22.dp).clip(CircleShape).background(Qs.brass), contentAlignment = Alignment.Center) {
                    QsIcon(R.drawable.ic_check, Qs.base, 14.dp)
                }
            }
            if (isVideo(e.name)) {
                Box(Modifier.align(Alignment.Center).size(30.dp).clip(CircleShape).background(Qs.base.copy(alpha = 0.6f)), contentAlignment = Alignment.Center) {
                    QsIcon(R.drawable.ic_video, Qs.ivory, 16.dp)
                }
            }
        }
        Gap(6.dp)
        Text(e.name, style = T.small.copy(color = Qs.ivory, fontSize = 12.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FileRow(
    handle: Long,
    dir: String,
    e: Entry,
    readOnly: Boolean,
    selecting: Boolean,
    selected: Boolean,
    onOpen: () -> Unit,
    onLongClick: () -> Unit,
    onExport: () -> Unit,
    onCopy: () -> Unit,
    onCut: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    Box(Modifier.background(if (selected) Qs.brass.copy(alpha = 0.12f) else androidx.compose.ui.graphics.Color.Transparent)) {
        Row(Modifier.fillMaxWidth().height(62.dp).combinedClickable(onClick = onOpen, onLongClick = onLongClick), verticalAlignment = Alignment.CenterVertically) {
            Box {
                Thumb(handle, dir, e, 42.dp, 13.dp)
                if (selected) {
                    Box(Modifier.align(Alignment.BottomEnd).size(18.dp).clip(CircleShape).background(Qs.brass), contentAlignment = Alignment.Center) {
                        QsIcon(R.drawable.ic_check, Qs.base, 12.dp)
                    }
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(e.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(if (e.dir) "مجلد" else humanSize(e.size), style = if (e.dir) T.small.copy(fontSize = 12.sp) else T.mono)
                    val date = friendlyDate(e.mtime)
                    if (date.isNotEmpty()) Text(" – $date", style = T.small.copy(fontSize = 12.sp))
                }
            }
            if (!selecting) IconBtn(R.drawable.ic_more, "خيارات", tint = Qs.muted) { menu = true }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line).align(Alignment.BottomCenter))
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }, containerColor = Qs.surface) {
            DropdownMenuItem(text = { Text(if (e.dir) "فتح" else "عرض", style = T.item) }, onClick = { menu = false; onOpen() })
            DropdownMenuItem(text = { Text("تحديد", style = T.item) }, onClick = { menu = false; onLongClick() })
            DropdownMenuItem(text = { Text("نسخ إلى خزنة أو مجلد", style = T.item) }, onClick = { menu = false; onCopy() })
            if (!readOnly) DropdownMenuItem(text = { Text("نقل (قص)", style = T.item) }, onClick = { menu = false; onCut() })
            DropdownMenuItem(text = { Text(if (e.dir) "تصدير المجلد" else "تصدير", style = T.item) }, onClick = { menu = false; onExport() })
            if (!readOnly) {
                DropdownMenuItem(text = { Text("إعادة تسمية", style = T.item) }, onClick = { menu = false; onRename() })
                DropdownMenuItem(text = { Text("حذف", style = T.item.copy(color = Qs.coral)) }, onClick = { menu = false; onDelete() })
            }
        }
    }
}

private const val VIEW_LIMIT_IMAGE = 64L shl 20
private const val VIEW_LIMIT_TEXT = 4L shl 20

private fun decodeSampled(bytes: ByteArray, maxSide: Int = 2560): ImageBitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / sample > maxSide) sample *= 2
    val opts = BitmapFactory.Options().apply { inSampleSize = sample }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)?.asImageBitmap()
}

@Composable
fun ViewerScreen(handle: Long, path: String, name: String, size: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var image by remember { mutableStateOf<ImageBitmap?>(null) }
    var text by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }

    LaunchedEffect(path) {
        val limit = if (isImage(name)) VIEW_LIMIT_IMAGE else VIEW_LIMIT_TEXT
        if (size > limit) {
            error = "الملف أكبر من أن يُعرض هنا (${humanSize(size)}). صدّره لفتحه بتطبيق آخر."
            return@LaunchedEffect
        }
        withContext(Dispatchers.IO) {
            val bytes = QsCore.readFile(handle, path, limit)
            if (bytes == null) {
                error = "تعذّرت قراءة الملف."
            } else {
                if (isImage(name)) {
                    image = decodeSampled(bytes)
                    if (image == null) error = "تعذّر عرض الصورة. قد تكون بصيغة غير مدعومة على هذا الجهاز."
                } else {
                    text = String(bytes, Charsets.UTF_8)
                }
                bytes.fill(0)
            }
        }
    }

    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        busy = Busy("تصدير الملف", 0f, name)
        scope.launch {
            val r = exportTo(context, handle, path, uri, Progress { d, t ->
                busy = busy?.copy(fraction = if (t > 0) d.toFloat() / t else null)
                !cancel.get()
            })
            busy = null
            message = if (r.ok) "تم التصدير. النسخة المصدّرة غير مشفّرة." else r.error
        }
    }

    Column(Modifier.fillMaxSize()) {
        Box(Modifier.padding(horizontal = 20.dp, vertical = 12.dp)) {
            TopBar(name, onBack = { AppState.pop() }) {
                IconBtn(R.drawable.ic_export, "تصدير") {
                    AppState.pickerOpen = true
                    exporter.launch(name)
                }
            }
        }
        Box(Modifier.weight(1f).fillMaxWidth().background(androidx.compose.ui.graphics.Color(0xFF061A14)), contentAlignment = Alignment.Center) {
            when {
                error != null -> Text(error!!, style = T.body.copy(color = Qs.muted), textAlign = TextAlign.Center, modifier = Modifier.padding(32.dp))
                image != null -> Image(
                    bitmap = image!!,
                    contentDescription = name,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .fillMaxSize()
                        .pointerInput(Unit) {
                            detectTransformGestures { _, pan, zoom, _ ->
                                scale = (scale * zoom).coerceIn(1f, 6f)
                                offset = if (scale == 1f) Offset.Zero else offset + pan
                            }
                        }
                        .graphicsLayer(scaleX = scale, scaleY = scale, translationX = offset.x, translationY = offset.y),
                )
                text != null -> SelectionContainer {
                    Text(
                        text!!,
                        style = if (ext(name) in setOf("txt", "md", "srt")) T.body.copy(fontSize = 15.sp, lineHeight = 26.sp) else T.monoLarge,
                        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                    )
                }
                else -> CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(32.dp))
            }
        }
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = { cancel.set(true) }) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}


/** A search hit somewhere below the folder being viewed. */
data class Found(val path: String, val entry: Entry)

/** Folders first, then by name, date or size. */
fun entryOrder(by: Int, desc: Boolean): Comparator<Entry> {
    val collator = java.text.Collator.getInstance(java.util.Locale("ar")).apply { strength = java.text.Collator.SECONDARY }
    val byName = Comparator<Entry> { a, b -> collator.compare(a.name, b.name) }
    val key: Comparator<Entry> = when (by) {
        1 -> compareBy<Entry> { it.mtime }.then(byName)
        2 -> compareBy<Entry> { if (it.dir) 0L else it.size }.then(byName)
        else -> byName
    }
    val ordered = if (desc) key.reversed() else key
    return compareBy<Entry> { !it.dir }.then(ordered)
}

@Composable
private fun FoundRow(f: Found, from: String, onOpen: () -> Unit) {
    val e = f.entry
    val parent = f.path.substringBeforeLast('/').ifEmpty { "/" }
    val where = if (from != "/" && parent.startsWith(from)) parent.removePrefix(from).ifEmpty { "/" } else parent
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onOpen).padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Tile(
            when {
                e.dir -> R.drawable.ic_folder
                isImage(e.name) -> R.drawable.ic_image
                isVideo(e.name) -> R.drawable.ic_video
                isAudio(e.name) -> R.drawable.ic_music
                else -> R.drawable.ic_file
            },
            if (e.dir) Qs.brass else Qs.ivory,
            size = 40.dp,
            radius = 12.dp,
            iconSize = 20.dp,
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(e.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(where, style = T.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (!e.dir) Text(humanSize(e.size), style = T.small)
    }
}
