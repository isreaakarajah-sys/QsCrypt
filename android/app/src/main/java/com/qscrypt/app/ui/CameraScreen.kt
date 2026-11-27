package com.qscrypt.app.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.Diag
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.childOf
import kotlinx.coroutines.delay
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * The secure camera: photos are taken into memory and written straight into
 * the vault (never into the gallery or a plain file). Videos are recorded
 * into the app's own protected storage, moved into the vault encrypted the
 * moment recording stops, and the temporary file is deleted.
 */
@SuppressLint("MissingPermission")
@Composable
fun CameraScreen(handle: Long, dir: String) {
    val context = LocalContext.current
    val owner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    fun granted(p: String) = ContextCompat.checkSelfPermission(context, p) == PackageManager.PERMISSION_GRANTED
    var camera by remember { mutableStateOf(granted(Manifest.permission.CAMERA)) }
    var mic by remember { mutableStateOf(granted(Manifest.permission.RECORD_AUDIO)) }
    val askCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { camera = it }
    val askMic = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { mic = it }
    var video by remember { mutableStateOf(false) }
    var back by remember { mutableStateOf(true) }
    var flash by remember { mutableStateOf(false) }
    var recording by remember { mutableStateOf<Recording?>(null) }
    var recordStart by remember { mutableLongStateOf(0L) }
    var elapsed by remember { mutableLongStateOf(0L) }
    var saved by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val worker = remember { Executors.newSingleThreadExecutor() }
    val main = remember { ContextCompat.getMainExecutor(context) }
    val imageCapture = remember { ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY).build() }
    val videoCapture = remember {
        VideoCapture.withOutput(Recorder.Builder().setQualitySelector(QualitySelector.from(Quality.FHD, FallbackStrategy.lowerQualityOrHigherThan(Quality.SD))).build())
    }
    val preview = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    val session = AppState.session(handle)

    LaunchedEffect(Unit) {
        if (!camera) {
            AppState.pickerOpen = true
            askCamera.launch(Manifest.permission.CAMERA)
        }
    }
    // Binds the camera to the screen: preview plus photo or video.
    DisposableEffect(camera, back, video) {
        if (!camera) return@DisposableEffect onDispose {}
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            runCatching {
                val provider = future.get()
                provider.unbindAll()
                val p = Preview.Builder().build().also { it.setSurfaceProvider(preview.surfaceProvider) }
                val selector = if (back) CameraSelector.DEFAULT_BACK_CAMERA else CameraSelector.DEFAULT_FRONT_CAMERA
                provider.bindToLifecycle(owner, selector, p, if (video) videoCapture else imageCapture)
            }.onFailure {
                Diag.error("camera", it)
                message = "تعذّر تشغيل الكاميرا"
            }
        }, main)
        onDispose { runCatching { future.get().unbindAll() } }
    }
    DisposableEffect(Unit) {
        onDispose {
            recording?.stop()
            worker.shutdown()
        }
    }
    LaunchedEffect(recording) {
        while (recording != null) {
            elapsed = System.currentTimeMillis() - recordStart
            delay(250)
        }
    }
    // Leaving the vault or the app's lock closes the camera.
    if (session == null) {
        LaunchedEffect(Unit) { AppState.pop() }
        return
    }
    BackHandler(enabled = recording != null) { recording?.stop() }

    fun stamp() = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    fun freePath(base: String, ext: String): String {
        var name = "$base.$ext"
        var n = 2
        val taken = com.qscrypt.app.parseEntries(Reply(QsCore.list(handle, dir)).json).map { it.name }.toSet()
        while (name in taken) name = "$base ($n).$ext".also { n++ }
        return childOf(dir, name)
    }

    fun takePhoto() {
        if (busy) return
        busy = true
        imageCapture.flashMode = if (flash) ImageCapture.FLASH_MODE_ON else ImageCapture.FLASH_MODE_OFF
        val out = ByteArrayOutputStream()
        // Written to memory with its orientation (EXIF), never to a file.
        imageCapture.takePicture(ImageCapture.OutputFileOptions.Builder(out).build(), worker, object : ImageCapture.OnImageSavedCallback {
            override fun onImageSaved(result: ImageCapture.OutputFileResults) {
                val bytes = out.toByteArray()
                val r = Call("fs.put").put("handle", handle).put("path", freePath("IMG_${stamp()}", "jpg")).blob("data", bytes).run()
                main.execute {
                    busy = false
                    if (r.ok) saved++ else message = "تعذّر الحفظ: " + r.error
                }
            }

            override fun onError(e: ImageCaptureException) {
                Diag.error("camera photo", e)
                main.execute {
                    busy = false
                    message = "تعذّر التقاط الصورة"
                }
            }
        })
    }

    fun toggleVideo() {
        recording?.let {
            it.stop()
            return
        }
        // Into the app's own protected storage, only until it is in the vault.
        val tmp = File(context.noBackupFilesDir, "camera").apply { mkdirs() }.let { File(it, "rec-${System.nanoTime()}.mp4") }
        val prepared = videoCapture.output.prepareRecording(context, FileOutputOptions.Builder(tmp).build())
        if (mic) prepared.withAudioEnabled()
        recordStart = System.currentTimeMillis()
        recording = prepared.start(main) { e ->
            if (e is VideoRecordEvent.Finalize) {
                recording = null
                busy = true
                worker.execute {
                    val ok = e.hasError().not() || e.error == VideoRecordEvent.Finalize.ERROR_SOURCE_INACTIVE
                    val r = if (ok && tmp.length() > 0) runCatching {
                        ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                            Reply(QsCore.importFile(handle, pfd.fd, tmp.length(), freePath("VID_${stamp()}", "mp4"), false, null))
                        }
                    }.getOrNull() else null
                    tmp.delete()
                    main.execute {
                        busy = false
                        when {
                            r?.ok == true -> saved++
                            else -> message = "تعذّر حفظ الفيديو" + (r?.error?.let { ": $it" } ?: "")
                        }
                    }
                }
            }
        }
    }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        if (camera) {
            AndroidView(factory = { preview }, modifier = Modifier.fillMaxSize())
        } else {
            Column(Modifier.align(Alignment.Center).padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                QsIcon(R.drawable.ic_camera, Qs.brass, 40.dp)
                Gap(12.dp)
                Text("الكاميرا الآمنة تحتاج إذن الكاميرا. الصور تُكتب مباشرة داخل الخزنة ولا تمر بالمعرض.", style = T.body.copy(color = Qs.ivory))
                Gap(16.dp)
                PrimaryButton("اسمح بالكاميرا", icon = R.drawable.ic_camera) {
                    AppState.pickerOpen = true
                    askCamera.launch(Manifest.permission.CAMERA)
                }
            }
        }
        // Top: back, where it goes, flash, camera side.
        Row(Modifier.fillMaxWidth().systemBarsPadding().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconBtn(R.drawable.ic_back, "رجوع", tint = Color.White) { if (recording == null) AppState.pop() }
            Spacer(Modifier.size(8.dp))
            Column(Modifier.weight(1f)) {
                Text("الكاميرا الآمنة", style = T.item.copy(color = Color.White))
                Text("إلى ${session.container.name.substringBeforeLast('.')} · ${if (dir == "/") "الجذر" else dir.substringAfterLast('/')}", style = T.small.copy(color = Color(0xCCFFFFFF)))
            }
            if (!video) IconBtn(R.drawable.ic_flash, if (flash) "إيقاف الفلاش" else "تشغيل الفلاش", tint = if (flash) Qs.brass else Color.White) { flash = !flash }
            IconBtn(R.drawable.ic_switch, "تبديل الكاميرا", tint = Color.White, enabled = recording == null) { back = !back }
        }
        // Bottom: mode, shutter, count.
        Column(Modifier.align(Alignment.BottomCenter).fillMaxWidth().systemBarsPadding().padding(bottom = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            message?.let {
                Text(it, style = T.small.copy(color = Qs.coral), modifier = Modifier.clip(RoundedCornerShape(10.dp)).background(Color(0x99000000)).padding(horizontal = 12.dp, vertical = 6.dp).clickable { message = null })
                Gap(10.dp)
            }
            if (recording != null) {
                val s = elapsed / 1000
                Text("● %02d:%02d".format(s / 60, s % 60), style = T.item.copy(color = Qs.coral))
                Gap(10.dp)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Chip("صورة", !video, enabled = recording == null) { video = false }
                Chip("فيديو", video, enabled = recording == null) {
                    video = true
                    if (!mic) {
                        AppState.pickerOpen = true
                        askMic.launch(Manifest.permission.RECORD_AUDIO)
                    }
                }
            }
            Gap(16.dp)
            Row(Modifier.fillMaxWidth().padding(horizontal = 32.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.weight(1f)) {
                    if (saved > 0) Text("حُفظ $saved في الخزنة", style = T.small.copy(color = Qs.mint))
                }
                Box(
                    Modifier
                        .size(76.dp)
                        .clip(CircleShape)
                        .border(4.dp, Color.White, CircleShape)
                        .padding(8.dp)
                        .clip(if (recording != null) RoundedCornerShape(8.dp) else CircleShape)
                        .background(if (video) Qs.coral else Color.White)
                        .clickable(enabled = camera && !busy) { if (video) toggleVideo() else takePhoto() },
                )
                Box(Modifier.weight(1f), contentAlignment = Alignment.CenterEnd) {
                    if (busy) Text("يُشفَّر…", style = T.small.copy(color = Color.White))
                }
            }
        }
    }
}
