package com.qscrypt.app.ui

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.items
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.Entry
import com.qscrypt.app.Progress
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.Screen
import com.qscrypt.app.VolumeInfo
import com.qscrypt.app.humanSize
import com.qscrypt.app.parseEntries
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Calendar
import java.util.concurrent.atomic.AtomicBoolean

private val IMAGES = setOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif")
private val VIDEOS = setOf("mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v")
private val AUDIO = setOf("mp3", "m4a", "aac", "wav", "ogg", "flac", "opus")
private val TEXT = setOf("txt", "md", "csv", "json", "xml", "log", "html", "htm", "ini", "cfg", "conf", "yaml", "yml", "srt", "kt", "java", "py", "js")
private val DOCS = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "epub") + TEXT
private val ARCHIVES = setOf("zip", "rar", "7z", "tar", "gz", "xz", "apk")
private val KEYS = setOf("kdbx", "key", "pem", "p12", "pfx", "asc", "gpg")

fun ext(name: String) = name.substringAfterLast('.', "").lowercase()
fun isImage(name: String) = ext(name) in IMAGES
fun isText(name: String) = ext(name) in TEXT

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
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf<Busy?>(null) }
    val cancel = remember { AtomicBoolean(false) }
    var newFolder by remember { mutableStateOf(false) }
    var renameFor by remember { mutableStateOf<Entry?>(null) }
    var deleteFor by remember { mutableStateOf<Entry?>(null) }
    var cannotView by remember { mutableStateOf<Entry?>(null) }
    var pendingExport by remember { mutableStateOf<Entry?>(null) }
    var message by remember { mutableStateOf<String?>(null) }

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

    val progress = Progress { done, total ->
        busy = busy?.copy(fraction = if (total > 0) done.toFloat() / total else null)
        !cancel.get()
    }

    val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        cancel.set(false)
        scope.launch {
            var failed: String? = null
            for ((i, uri) in uris.withIndex()) {
                val meta = Saf.meta(context, uri)
                busy = Busy("إضافة الملفات (${i + 1}/${uris.size})", 0f, meta.name)
                val r = withContext(Dispatchers.IO) { importOne(context, handle, path, uri, meta.name, meta.size, progress) }
                if (!r.ok) {
                    failed = if (r.code == "cancelled") null else "«${meta.name}»: ${r.error}"
                    break
                }
            }
            busy = null
            refresh++
            if (failed != null) message = failed
        }
    }

    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val e = pendingExport
        pendingExport = null
        if (uri == null || e == null) return@rememberLauncherForActivityResult
        cancel.set(false)
        busy = Busy("تصدير الملف", 0f, e.name)
        scope.launch {
            val r = exportTo(context, handle, childPath(path, e.name), uri, progress)
            busy = null
            message = if (r.ok) "تم تصدير «${e.name}». تذكّر أن النسخة المصدّرة غير مشفّرة." else r.error
        }
    }

    fun export(e: Entry) {
        pendingExport = e
        AppState.pickerOpen = true
        exporter.launch(e.name)
    }

    fun open(e: Entry) {
        when {
            e.dir -> AppState.push(Screen.Vault(handle, childPath(path, e.name)))
            isImage(e.name) || isText(e.name) -> AppState.push(Screen.Viewer(handle, childPath(path, e.name), e.name, e.size))
            else -> cannotView = e
        }
    }

    fun runOp(op: () -> String) {
        scope.launch {
            val r = Reply(withContext(Dispatchers.IO) { op() })
            if (!r.ok) message = r.error
            refresh++
        }
    }

    val shown = (entries ?: emptyList()).filter { e ->
        (query.isBlank() || e.name.contains(query, ignoreCase = true)) &&
            when (filter) {
                1 -> e.dir || ext(e.name) in IMAGES
                2 -> e.dir || ext(e.name) in DOCS
                3 -> e.dir || ext(e.name) in VIDEOS
                else -> true
            }
    }
    val used = (info.total - info.free).coerceAtLeast(0)
    val fileCount = entries?.count { !it.dir } ?: 0
    val title = if (path == "/") session.container.name.substringBeforeLast('.').ifBlank { session.container.name } else path.substringAfterLast('/')

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                IconBtn(R.drawable.ic_back, "رجوع") { AppState.pop() }
                Spacer(Modifier.width(6.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(title, style = T.h1.copy(lineHeight = 30.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Tag(info.format)
                        Tag(info.ea)
                        Tag(info.fs)
                        if (info.readOnly) Tag("للقراءة فقط", TagKind.Outline)
                        if (info.hidden) Tag("مخفية", TagKind.Mint)
                    }
                }
                Row(
                    Modifier
                        .height(40.dp)
                        .clickable { AppState.closeSession(handle) }
                        .padding(horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    QsIcon(R.drawable.ic_lock, Qs.brass, 18.dp)
                    Spacer(Modifier.width(6.dp))
                    Text("أقفل", style = T.label.copy(color = Qs.brass))
                }
            }
            if (path != "/") {
                Gap(6.dp)
                Text(path, style = T.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Gap(16.dp)
            Row {
                Text("${humanSize(used)} من ${humanSize(info.total)} مستخدمة", style = T.small, modifier = Modifier.weight(1f))
                Text("$fileCount ملفاً", style = T.small)
            }
            Gap(8.dp)
            UsageBar(if (info.total > 0) used.toFloat() / info.total else 0f)
            Gap(16.dp)
            QsField(value = query, onValueChange = { query = it }, placeholder = "ابحث داخل الخزنة", height = 48.dp, leading = { QsIcon(R.drawable.ic_search, Qs.muted) })
            Gap(14.dp)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("الكل", "صور", "مستندات", "فيديو").forEachIndexed { i, label -> Chip(label, filter == i) { filter = i } }
            }
            Gap(10.dp)
            when {
                error != null -> Note(error!!, icon = R.drawable.ic_alert, color = Qs.coral, background = Qs.warm, border = Qs.coral)
                entries == null -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp)
                }
                shown.isEmpty() -> Column(Modifier.fillMaxWidth().padding(vertical = 40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    QsIcon(R.drawable.ic_folder, Qs.muted, 40.dp)
                    Gap(12.dp)
                    Text(if (entries!!.isEmpty()) "الخزنة فارغة" else "لا نتائج", style = T.item.copy(color = Qs.muted))
                    if (entries!!.isEmpty() && !info.readOnly) {
                        Gap(6.dp)
                        Text("أضف ملفات لتُشفَّر داخلها تلقائياً.", style = T.small)
                    }
                }
                else -> LazyColumn(Modifier.fillMaxWidth()) {
                    items(shown, key = { it.name }) { e ->
                        FileRow(
                            e,
                            readOnly = info.readOnly,
                            onOpen = { open(e) },
                            onExport = { export(e) },
                            onRename = { renameFor = e },
                            onDelete = { deleteFor = e },
                        )
                    }
                    item { Gap(16.dp) }
                }
            }
        }
        Column(Modifier.fillMaxWidth().background(Qs.base)) {
            Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line))
            if (info.readOnly) {
                Box(Modifier.padding(horizontal = 20.dp, vertical = 14.dp)) {
                    Note(
                        if (info.fs == "exFAT") "الكتابة على exFAT قادمة في الإصدار التالي. يمكنك عرض الملفات وتصديرها." else "الخزنة مفتوحة للقراءة فقط. يمكنك عرض الملفات وتصديرها.",
                        icon = R.drawable.ic_eye,
                    )
                }
            } else {
                Row(Modifier.padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 22.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    PrimaryButton("أضف ملفات", modifier = Modifier.weight(1.4f), icon = R.drawable.ic_plus) {
                        AppState.pickerOpen = true
                        importer.launch(arrayOf("*/*"))
                    }
                    SecondaryButton("مجلد جديد", modifier = Modifier.weight(1f), icon = R.drawable.ic_folderplus) { newFolder = true }
                }
            }
        }
    }

    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail, onCancel = { cancel.set(true) }) }
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
            if (name != e.name) runOp { QsCore.rename(handle, childPath(path, e.name), name) }
        }, onDismiss = { renameFor = null })
    }
    deleteFor?.let { e ->
        QsAlert(
            title = if (e.dir) "حذف المجلد" else "حذف الملف",
            text = if (e.dir) "سيُحذف «${e.name}» وكل ما بداخله نهائياً من الخزنة." else "سيُحذف «${e.name}» نهائياً من الخزنة.",
            confirm = "حذف",
            danger = true,
            onConfirm = {
                deleteFor = null
                runOp { QsCore.remove(handle, childPath(path, e.name)) }
            },
            onDismiss = { deleteFor = null },
        )
    }
    cannotView?.let { e ->
        QsAlert(
            title = e.name,
            text = "عرض هذا النوع داخل التطبيق قادم لاحقاً. يمكنك تصديره وفتحه بتطبيق آخر، علماً أن النسخة المصدّرة تكون غير مشفّرة.",
            confirm = "تصدير",
            onConfirm = {
                cannotView = null
                export(e)
            },
            onDismiss = { cannotView = null },
        )
    }
}

/** Imports one document, picking "name (2).ext" etc. if the name is taken. */
private fun importOne(context: Context, handle: Long, dir: String, uri: Uri, name: String, size: Long, progress: Progress): Reply {
    val base = name.substringBeforeLast('.', name)
    val extension = if (name.contains('.')) "." + name.substringAfterLast('.') else ""
    for (n in 1..99) {
        val candidate = if (n == 1) name else "$base ($n)$extension"
        val pfd = Saf.open(context, uri, "r") ?: return Reply("{\"ok\":false,\"code\":\"io\"}")
        val r = pfd.use { Reply(QsCore.importFile(handle, it.fd, size, childPath(dir, candidate), false, progress)) }
        if (r.code != "exists") return r
    }
    return Reply("{\"ok\":false,\"code\":\"exists\"}")
}

@Composable
private fun FileRow(e: Entry, readOnly: Boolean, onOpen: () -> Unit, onExport: () -> Unit, onRename: () -> Unit, onDelete: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    val (icon, color) = iconFor(e)
    Box {
        Row(Modifier.fillMaxWidth().height(62.dp).clickable(onClick = onOpen), verticalAlignment = Alignment.CenterVertically) {
            Tile(icon, color, size = 42.dp, radius = 13.dp, iconSize = 21.dp)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(e.name, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(if (e.dir) "مجلد" else humanSize(e.size), style = if (e.dir) T.small.copy(fontSize = 12.sp) else T.mono)
                    val date = friendlyDate(e.mtime)
                    if (date.isNotEmpty()) Text(" – $date", style = T.small.copy(fontSize = 12.sp))
                }
            }
            IconBtn(R.drawable.ic_more, "خيارات", tint = Qs.muted) { menu = true }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(Qs.line).align(Alignment.BottomCenter))
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }, containerColor = Qs.surface) {
            DropdownMenuItem(text = { Text(if (e.dir) "فتح" else "عرض", style = T.item) }, onClick = { menu = false; onOpen() })
            if (!e.dir) DropdownMenuItem(text = { Text("تصدير", style = T.item) }, onClick = { menu = false; onExport() })
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
