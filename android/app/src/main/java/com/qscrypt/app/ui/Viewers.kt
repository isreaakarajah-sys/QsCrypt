package com.qscrypt.app.ui

import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.media.MediaPlayer
import android.os.Build
import android.os.ParcelFileDescriptor
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.qscrypt.app.AppState
import com.qscrypt.app.Entry
import com.qscrypt.app.Jobs
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.VaultMediaSource
import com.qscrypt.app.VaultProxy
import com.qscrypt.app.decodePicture
import com.qscrypt.app.humanSize
import com.qscrypt.app.parseEntries
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private val VIEWER_BG = Color(0xFF061A14)
private const val MAX_PICTURE = 96L shl 20

/** Exports the file shown by a viewer, as a background job with its dialog. */
@Composable
private fun rememberExport(handle: Long, path: String, name: String, onJob: (Jobs.Job) -> Unit): () -> Unit {
    val context = LocalContext.current
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        onJob(
            Jobs.start(context, "export", "تصدير «$name»", listOf(handle)) work@{
                val r = exportTo(context, handle, path, uri, progress())
                if (!r.ok) return@work r
                Reply(org.json.JSONObject().put("ok", true).put("summary", "صُدّر الملف. النسخة المصدّرة غير مشفّرة.").toString())
            },
        )
    }
    return {
        AppState.pickerOpen = true
        exporter.launch(name)
    }
}

// ------------------------------------------------------------------ pictures

/** One picture, pinch to zoom, double tap to zoom in or out; swipes go to the pager when not zoomed. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ZoomablePicture(handle: Long, path: String, size: Long, name: String, onZoomed: (Boolean) -> Unit) {
    val img by produceState<Any?>(null, path) {
        value = withContext(Dispatchers.IO) {
            if (size > MAX_PICTURE) return@withContext "الصورة أكبر من أن تُعرض هنا (${humanSize(size)})."
            val bytes = QsCore.readFile(handle, path, MAX_PICTURE) ?: return@withContext "تعذّرت قراءة الصورة."
            try {
                decodePicture(bytes, 2560)?.asImageBitmap() ?: "تعذّر عرض الصورة. قد تكون بصيغة غير مدعومة على هذا الجهاز."
            } catch (e: OutOfMemoryError) {
                "الصورة كبيرة على ذاكرة الجهاز."
            } finally {
                bytes.fill(0)
            }
        }
    }
    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    val state = rememberTransformableState { zoom, pan, _ ->
        scale = (scale * zoom).coerceIn(1f, 6f)
        offset = if (scale <= 1.01f) Offset.Zero else offset + pan * scale
        onZoomed(scale > 1.01f)
    }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        when (val v = img) {
            null -> CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(30.dp))
            is String -> Text(v, style = T.body.copy(color = Qs.muted), textAlign = TextAlign.Center, modifier = Modifier.padding(32.dp))
            is ImageBitmap -> Image(
                bitmap = v,
                contentDescription = name,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(Unit) {
                        detectTapGestures(onDoubleTap = {
                            if (scale > 1.01f) {
                                scale = 1f
                                offset = Offset.Zero
                                onZoomed(false)
                            } else {
                                scale = 2.5f
                                onZoomed(true)
                            }
                        })
                    }
                    .transformable(state, canPan = { scale > 1.01f })
                    .graphicsLayer(scaleX = scale, scaleY = scale, translationX = offset.x, translationY = offset.y),
            )
        }
    }
}

/** The pictures of a folder, swiped one after another. Nothing is written to disk. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun GalleryScreen(handle: Long, dir: String, start: String) {
    var pictures by remember { mutableStateOf<List<Entry>?>(null) }
    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    LaunchedEffect(dir) {
        val r = Reply(withContext(Dispatchers.IO) { QsCore.list(handle, dir) })
        pictures = if (r.ok) parseEntries(r.json).filter { !it.dir && isImage(it.name) } else emptyList()
    }
    val list = pictures
    if (list == null) {
        Box(Modifier.fillMaxSize().background(VIEWER_BG), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp) }
        return
    }
    if (list.isEmpty()) {
        LaunchedEffect(Unit) { AppState.pop() }
        return
    }
    val pager = rememberPagerState(initialPage = list.indexOfFirst { it.name == start }.coerceAtLeast(0)) { list.size }
    var zoomed by remember { mutableStateOf(false) }
    val current = list[pager.currentPage.coerceIn(0, list.size - 1)]
    val export = rememberExport(handle, childPath(dir, current.name), current.name) { job = it }
    Column(Modifier.fillMaxSize().background(VIEWER_BG)) {
        Box(Modifier.background(Qs.base).padding(horizontal = 20.dp, vertical = 12.dp)) {
            TopBar(current.name, onBack = { AppState.pop() }) {
                Text("${pager.currentPage + 1} / ${list.size}", style = T.mono)
                Spacer(Modifier.width(8.dp))
                IconBtn(R.drawable.ic_export, "تصدير", onClick = export)
            }
        }
        HorizontalPager(state = pager, modifier = Modifier.weight(1f).fillMaxWidth(), userScrollEnabled = !zoomed, key = { list[it].name }) { page ->
            val e = list[page]
            ZoomablePicture(handle, childPath(dir, e.name), e.size, e.name) { z -> if (page == pager.currentPage) zoomed = z }
        }
        Row(Modifier.fillMaxWidth().background(Qs.base).padding(horizontal = 20.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(humanSize(current.size), style = T.mono)
            val date = friendlyDate(current.mtime)
            if (date.isNotEmpty()) Text(" – $date", style = T.small)
            Spacer(Modifier.weight(1f))
            Text("انقر مرتين للتكبير", style = T.small)
        }
    }
    job?.let { j -> JobDialog(j, onClose = { job = null }) }
}

// ------------------------------------------------------------------ video and audio

private fun clock(ms: Int): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return if (s >= 3600) "%d:%02d:%02d".format(s / 3600, (s / 60) % 60, s % 60) else "%d:%02d".format(s / 60, s % 60)
}

/** Video and audio streamed from the vault into the player, in memory only. */
@Composable
fun MediaScreen(handle: Long, path: String, name: String, size: Long) {
    val video = isVideo(name)
    val player = remember { MediaPlayer() }
    var prepared by remember { mutableStateOf(false) }
    var playing by remember { mutableStateOf(false) }
    var position by remember { mutableIntStateOf(0) }
    var duration by remember { mutableIntStateOf(0) }
    var seeking by remember { mutableStateOf<Float?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var aspect by remember { mutableFloatStateOf(16f / 9f) }
    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    val export = rememberExport(handle, path, name) { job = it }
    @Suppress("DEPRECATION")
    val lifecycle = androidx.compose.ui.platform.LocalLifecycleOwner.current.lifecycle

    DisposableEffect(Unit) {
        val source = VaultMediaSource(handle, path, size)
        player.setOnPreparedListener {
            duration = it.duration.coerceAtLeast(0)
            prepared = true
            it.start()
            playing = true
        }
        player.setOnErrorListener { _, _, _ ->
            error = "تعذّر تشغيل الملف. قد تكون صيغته غير مدعومة على هذا الجهاز؛ يمكنك تصديره وفتحه بتطبيق آخر."
            playing = false
            true
        }
        player.setOnCompletionListener { playing = false }
        player.setOnVideoSizeChangedListener { _, w, h -> if (w > 0 && h > 0) aspect = w.toFloat() / h }
        runCatching {
            player.setDataSource(source)
            player.prepareAsync()
        }.onFailure { error = "تعذّر فتح الملف للتشغيل." }
        // Leaving the app pauses playback.
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && playing) {
                runCatching { player.pause() }
                playing = false
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            runCatching { player.stop() }
            player.release()
            source.close()
        }
    }
    LaunchedEffect(playing) {
        while (playing) {
            if (seeking == null) position = runCatching { player.currentPosition }.getOrDefault(position)
            delay(250)
        }
    }

    fun toggle() {
        if (!prepared) return
        if (playing) {
            player.pause()
            playing = false
        } else {
            player.start()
            playing = true
        }
    }

    fun skip(ms: Int) {
        if (!prepared) return
        val to = (position + ms).coerceIn(0, duration)
        player.seekTo(to)
        position = to
    }

    Column(Modifier.fillMaxSize().background(VIEWER_BG)) {
        Box(Modifier.background(Qs.base).padding(horizontal = 20.dp, vertical = 12.dp)) {
            TopBar(name, onBack = { AppState.pop() }) {
                IconBtn(R.drawable.ic_export, "تصدير", onClick = export)
            }
        }
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
            if (video) {
                AndroidView(
                    factory = { ctx ->
                        SurfaceView(ctx).apply {
                            // Keeps the picture out of screenshots and the recents preview.
                            setSecure(true)
                            holder.addCallback(object : SurfaceHolder.Callback {
                                override fun surfaceCreated(h: SurfaceHolder) {
                                    runCatching { player.setDisplay(h) }
                                }

                                override fun surfaceChanged(h: SurfaceHolder, format: Int, width: Int, height: Int) {}

                                override fun surfaceDestroyed(h: SurfaceHolder) {
                                    runCatching { player.setDisplay(null) }
                                }
                            })
                        }
                    },
                    modifier = Modifier.fillMaxWidth().aspectRatio(aspect.coerceIn(0.3f, 4f)).pointerInput(Unit) { detectTapGestures(onTap = { toggle() }) },
                )
            } else {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(Modifier.size(140.dp).clip(CircleShape).background(Qs.surface), contentAlignment = Alignment.Center) {
                        QsIcon(R.drawable.ic_music, Qs.brass, 60.dp)
                    }
                    Gap(18.dp)
                    Text(name, style = T.title, textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(horizontal = 32.dp))
                }
            }
            if (!prepared && error == null) CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(32.dp))
            error?.let { Text(it, style = T.body.copy(color = Qs.muted), textAlign = TextAlign.Center, modifier = Modifier.background(VIEWER_BG).padding(32.dp)) }
        }
        Column(Modifier.fillMaxWidth().background(Qs.base).padding(horizontal = 20.dp, vertical = 12.dp)) {
            Slider(
                value = seeking ?: position.toFloat(),
                onValueChange = { seeking = it },
                onValueChangeFinished = {
                    seeking?.let { v ->
                        runCatching { player.seekTo(v.toInt()) }
                        position = v.toInt()
                    }
                    seeking = null
                },
                valueRange = 0f..duration.coerceAtLeast(1).toFloat(),
                enabled = prepared && duration > 0,
                colors = SliderDefaults.colors(thumbColor = Qs.brass, activeTrackColor = Qs.brass, inactiveTrackColor = Qs.line),
            )
            Row(Modifier.fillMaxWidth()) {
                Text(clock((seeking ?: position.toFloat()).toInt()), style = T.mono)
                Spacer(Modifier.weight(1f))
                Text(clock(duration), style = T.mono)
            }
            Gap(6.dp)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                Pill("10− ث", Qs.ivory, enabled = prepared) { skip(-10_000) }
                Spacer(Modifier.width(18.dp))
                Box(
                    Modifier.size(62.dp).clip(CircleShape).background(if (prepared) Qs.brass else Qs.line).pointerInput(prepared) { detectTapGestures(onTap = { toggle() }) },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(if (playing) "❚❚" else "▶", style = T.title.copy(color = Qs.base))
                }
                Spacer(Modifier.width(18.dp))
                Pill("10+ ث", Qs.ivory, enabled = prepared) { skip(10_000) }
            }
            Gap(10.dp)
        }
    }
    job?.let { j -> JobDialog(j, onClose = { job = null }) }
}

// ------------------------------------------------------------------ PDF

/** PDF pages rendered from the vault through a proxy descriptor (Android 8+); nothing on disk. */
@Composable
fun PdfScreen(handle: Long, path: String, name: String, size: Long) {
    val context = LocalContext.current
    var job by remember { mutableStateOf<Jobs.Job?>(null) }
    val export = rememberExport(handle, path, name) { job = it }
    var renderer by remember { mutableStateOf<PdfRenderer?>(null) }
    var fd by remember { mutableStateOf<ParcelFileDescriptor?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var wide by remember { mutableStateOf(false) }
    val lock = remember { Any() }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT < 26) {
            error = "قارئ PDF داخل الخزنة يحتاج أندرويد 8 أو أحدث. يمكنك تصدير الملف وفتحه بتطبيق آخر."
            return@LaunchedEffect
        }
        withContext(Dispatchers.IO) {
            val f = VaultProxy.open(context, handle, path, size)
            if (f == null) {
                error = "تعذّر فتح الملف."
                return@withContext
            }
            try {
                renderer = PdfRenderer(f)
                fd = f
            } catch (e: Exception) {
                runCatching { f.close() }
                error = "تعذّر فتح الملف: قد يكون محمياً بكلمة مرور أو تالفاً."
            }
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            synchronized(lock) {
                runCatching { renderer?.close() }
                runCatching { fd?.close() }
            }
        }
    }
    Column(Modifier.fillMaxSize().background(VIEWER_BG)) {
        Box(Modifier.background(Qs.base).padding(horizontal = 20.dp, vertical = 12.dp)) {
            TopBar(name, onBack = { AppState.pop() }) {
                renderer?.let { Text("${it.pageCount} صفحة", style = T.mono) }
                Spacer(Modifier.width(6.dp))
                IconBtn(R.drawable.ic_search, if (wide) "حجم الشاشة" else "تكبير", tint = if (wide) Qs.brass else Qs.ivory) { wide = !wide }
                IconBtn(R.drawable.ic_export, "تصدير", onClick = export)
            }
        }
        val r = renderer
        when {
            error != null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(error!!, style = T.body.copy(color = Qs.muted), textAlign = TextAlign.Center, modifier = Modifier.padding(32.dp))
            }
            r == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp) }
            else -> BoxWithConstraints(Modifier.fillMaxSize()) {
                val pageWidth = if (wide) maxWidth * 2 else maxWidth
                val px = with(LocalDensity.current) { pageWidth.roundToPx() }
                Box(Modifier.fillMaxSize().then(if (wide) Modifier.horizontalScroll(rememberScrollState()) else Modifier)) {
                    LazyColumn(Modifier.width(pageWidth).fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(r.pageCount) { i -> PdfPage(r, i, px, lock) }
                        item { Gap(16.dp) }
                    }
                }
            }
        }
    }
    job?.let { j -> JobDialog(j, onClose = { job = null }) }
}

@Composable
private fun PdfPage(r: PdfRenderer, index: Int, width: Int, lock: Any) {
    val bmp by produceState<ImageBitmap?>(null, index, width) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                synchronized(lock) {
                    // PdfRenderer opens one page at a time.
                    r.openPage(index).use { page ->
                        val scale = width.toFloat() / page.width.coerceAtLeast(1)
                        val h = (page.height * scale).toInt().coerceIn(1, 12_000)
                        val b = Bitmap.createBitmap(width.coerceAtLeast(1), h, Bitmap.Config.ARGB_8888)
                        b.eraseColor(android.graphics.Color.WHITE)
                        page.render(b, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        b.asImageBitmap()
                    }
                }
            }.getOrNull()
        }
    }
    val b = bmp
    if (b == null) {
        Box(Modifier.fillMaxWidth().aspectRatio(0.707f).background(Qs.surface), contentAlignment = Alignment.Center) {
            Text("${index + 1}", style = T.mono)
        }
    } else {
        Image(b, contentDescription = "صفحة ${index + 1}", contentScale = ContentScale.FillWidth, modifier = Modifier.fillMaxWidth())
    }
}
