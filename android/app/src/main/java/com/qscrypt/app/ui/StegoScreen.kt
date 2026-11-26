package com.qscrypt.app.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qscrypt.app.AppState
import com.qscrypt.app.Call
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Reply
import com.qscrypt.app.Saf
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.sqrt

private const val MAX_PIXELS = 8_000_000L

private data class Cover(val uri: Uri, val name: String, val width: Int, val height: Int, val capacity: Long)

private fun capacityOf(w: Int, h: Int): Long =
    Call("stego.capacity").put("w", w).put("h", h).run().json.optLong("bytes")

/** Cover size after limiting it to [MAX_PIXELS] (larger photos are scaled down). */
private fun coverSize(w: Int, h: Int): Pair<Int, Int> {
    val px = w.toLong() * h
    if (px <= MAX_PIXELS) return w to h
    val f = sqrt(MAX_PIXELS.toDouble() / px)
    return (w * f).toInt() to (h * f).toInt()
}

private fun readCover(context: Context, uri: Uri): Cover? = runCatching {
    val b = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, b) }
    if (b.outWidth <= 0 || b.outHeight <= 0) return null
    val (w, h) = coverSize(b.outWidth, b.outHeight)
    Cover(uri, Saf.meta(context, uri).name, w, h, capacityOf(w, h))
}.getOrNull()

/** Decodes an image to opaque ARGB pixels, scaled to exactly w×h. */
private fun loadPixels(context: Context, uri: Uri, w: Int, h: Int, exact: Boolean): Pair<IntArray, Pair<Int, Int>>? {
    val opts = BitmapFactory.Options().apply {
        inPreferredConfig = Bitmap.Config.ARGB_8888
        inScaled = false
        if (!exact) {
            val b = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, b) }
            var s = 1
            while (b.outWidth / (s * 2) >= w && b.outHeight / (s * 2) >= h) s *= 2
            inSampleSize = s
        }
    }
    var bmp = context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) } ?: return null
    if (!exact && (bmp.width != w || bmp.height != h)) bmp = Bitmap.createScaledBitmap(bmp, w, h, true)
    val px = IntArray(bmp.width * bmp.height)
    bmp.getPixels(px, 0, bmp.width, 0, 0, bmp.width, bmp.height)
    return px to (bmp.width to bmp.height)
}

@Composable
fun StegoScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableIntStateOf(0) }
    var cover by remember { mutableStateOf<Cover?>(null) }
    var secret by remember { mutableStateOf<Saf.Meta?>(null) }
    var secretUri by remember { mutableStateOf<Uri?>(null) }
    var image by remember { mutableStateOf<Uri?>(null) }
    var imageName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf<Busy?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var revealed by remember { mutableStateOf<File?>(null) }
    var revealedName by remember { mutableStateOf("") }
    // Encrypted payload is the file plus a small header; keep a margin.
    val fits = cover != null && secret != null && secret!!.size + 4096 <= cover!!.capacity

    val pickCover = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            val c = withContext(Dispatchers.IO) { readCover(context, uri) }
            if (c == null) message = "تعذّرت قراءة الصورة." else cover = c
        }
    }
    val pickSecret = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        secretUri = uri
        secret = Saf.meta(context, uri)
    }
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        image = uri
        imageName = Saf.meta(context, uri).name
    }

    val saveImage = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { out ->
        val c = cover
        val s = secretUri
        val meta = secret
        if (out == null || c == null || s == null || meta == null) return@rememberLauncherForActivityResult
        val pw = password.toByteArray(Charsets.UTF_8)
        busy = Busy("الإخفاء في الصورة", null, "تشفير الملف ثم توزيعه على البكسلات")
        scope.launch {
            val err = withContext(Dispatchers.IO) {
                val tmp = File(context.cacheDir, "stego.qsc")
                try {
                    val mode = android.os.ParcelFileDescriptor.MODE_READ_WRITE or android.os.ParcelFileDescriptor.MODE_CREATE or android.os.ParcelFileDescriptor.MODE_TRUNCATE
                    val enc = Saf.open(context, s, "r")?.use { i ->
                        android.os.ParcelFileDescriptor.open(tmp, mode).use { o ->
                            Call("qsc.encrypt").put("size", meta.size).put("name", meta.name)
                                .put("mtime", System.currentTimeMillis() / 1000).put("now", System.currentTimeMillis() / 1000)
                                .blob("password", pw.copyOf()).fd("in", i.fd).fd("out", o.fd).run()
                        }
                    } ?: return@withContext "تعذّر فتح الملف."
                    if (!enc.ok) return@withContext enc.error
                    val payload = tmp.readBytes()
                    val (px, size) = loadPixels(context, c.uri, c.width, c.height, exact = false) ?: return@withContext "تعذّرت قراءة الصورة."
                    for (i in px.indices) px[i] = px[i] or 0xFF000000.toInt()
                    val r = Reply(QsCore.stegoHide(px, pw.copyOf(), payload))
                    payload.fill(0)
                    if (!r.ok) return@withContext if (r.code == "no_space") "الملف أكبر من سعة الصورة." else r.error
                    val bmp = Bitmap.createBitmap(px, size.first, size.second, Bitmap.Config.ARGB_8888)
                    val ok = Saf.open(context, out, "w")?.use { pfd ->
                        java.io.FileOutputStream(pfd.fileDescriptor).use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
                    } ?: false
                    if (!ok) "تعذّر حفظ الصورة." else null
                } catch (e: OutOfMemoryError) {
                    "الصورة كبيرة جداً لذاكرة هذا الهاتف. اختر صورة أصغر."
                } finally {
                    tmp.delete()
                }
            }
            pw.fill(0)
            busy = null
            if (err != null) {
                Saf.delete(context, out)
                message = err
            } else {
                password = ""
                confirm = ""
                message = "أُخفي «${meta.name}» في الصورة.\n\nأرسلها «كملف» أو «مستند» لا كصورة: تطبيقات المراسلة تضغط الصور فيضيع ما بداخلها. لاستخراجه: «داخل صورة» ← «استخراج» بنفس كلمة المرور."
            }
        }
    }

    val saveRevealed = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { out ->
        val f = revealed
        if (out == null || f == null) return@rememberLauncherForActivityResult
        val pw = password.toByteArray(Charsets.UTF_8)
        busy = Busy("فك التشفير", null)
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                val output = Saf.open(context, out, "w") ?: return@withContext null
                android.os.ParcelFileDescriptor.open(f, android.os.ParcelFileDescriptor.MODE_READ_ONLY).use { i ->
                    output.use { o -> Call("qsc.decrypt").blob("password", pw.copyOf()).fd("in", i.fd).fd("out", o.fd).context().run() }
                }
            }
            pw.fill(0)
            busy = null
            f.delete()
            revealed = null
            if (r == null || !r.ok) {
                Saf.delete(context, out)
                message = r?.error ?: "تعذّر حفظ الملف."
            } else {
                password = ""
                message = "استُخرج «$revealedName» من الصورة وحُفظ."
            }
        }
    }

    fun reveal() {
        val img = image ?: return
        val pw = password.toByteArray(Charsets.UTF_8)
        busy = Busy("البحث في الصورة", null)
        scope.launch {
            val (file, err) = withContext(Dispatchers.IO) {
                try {
                    val (px, _) = loadPixels(context, img, 0, 0, exact = true) ?: return@withContext null to "تعذّرت قراءة الصورة."
                    val payload = QsCore.stegoReveal(px, pw.copyOf()) ?: return@withContext null to "لا يوجد شيء مخفي بكلمة المرور هذه، أو أن الصورة ضُغطت بعد الإخفاء."
                    val tmp = File(context.cacheDir, "revealed.qsc")
                    tmp.writeBytes(payload)
                    payload.fill(0)
                    // Verify and learn the original name before asking where to save.
                    val check = android.os.ParcelFileDescriptor.open(tmp, android.os.ParcelFileDescriptor.MODE_READ_ONLY).use { i ->
                        Call("qsc.decrypt").blob("password", pw.copyOf()).fd("in", i.fd).context().run()
                    }
                    if (!check.ok) {
                        tmp.delete()
                        null to check.error
                    } else {
                        revealedName = check.json.optString("name", "file")
                        tmp to null
                    }
                } catch (e: OutOfMemoryError) {
                    null to "الصورة كبيرة جداً لذاكرة هذا الهاتف."
                }
            }
            pw.fill(0)
            busy = null
            if (file == null) {
                message = err
            } else {
                revealed = file
                AppState.pickerOpen = true
                saveRevealed.launch(revealedName)
            }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("داخل صورة", onBack = { AppState.pop() })
        Gap(16.dp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Chip("إخفاء", tab == 0) { tab = 0; password = ""; confirm = "" }
            Chip("استخراج", tab == 1) { tab = 1; password = ""; confirm = "" }
        }
        Gap(18.dp)
        if (tab == 0) {
            Note("يُشفَّر الملف بـ QsCrypt ثم يتوزّع على البكسلات بترتيب لا يعرفه إلا صاحب كلمة المرور. تبقى الصورة كما تبدو، وتُحفظ بصيغة PNG.", icon = R.drawable.ic_image)
            Gap(16.dp)
            Text("الصورة الغطاء", style = T.label)
            Gap(8.dp)
            QsCard(onClick = { AppState.pickerOpen = true; pickCover.launch("image/*") }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_image, if (cover != null) Qs.brass else Qs.muted, size = 42.dp, radius = 14.dp, iconSize = 21.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(cover?.name ?: "اختر صورة", style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(cover?.let { "${it.width}×${it.height} · تتسع لـ ${humanSize(it.capacity)}" } ?: "صورة كبيرة بتفاصيل كثيرة أفضل من صورة سادة", style = T.small)
                    }
                }
            }
            Gap(12.dp)
            Text("الملف المخفي", style = T.label)
            Gap(8.dp)
            QsCard(onClick = { AppState.pickerOpen = true; pickSecret.launch(arrayOf("*/*")) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_file, if (secret != null) Qs.brass else Qs.muted, size = 42.dp, radius = 14.dp, iconSize = 21.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(secret?.name ?: "اختر ملفاً", style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(secret?.let { humanSize(it.size) } ?: "مستند، صورة صغيرة، ملاحظات…", style = T.small)
                    }
                }
            }
            if (cover != null && secret != null && !fits) {
                Gap(8.dp)
                Text("الملف أكبر من سعة هذه الصورة. اختر صورة أكبر أو ملفاً أصغر.", style = T.small.copy(color = Qs.coral))
            }
            Gap(20.dp)
            PasswordPair(password, confirm, { password = it }, { confirm = it })
            Gap(24.dp)
            PrimaryButton("أخفِ واحفظ الصورة", icon = R.drawable.ic_lock, enabled = fits && password.isNotEmpty() && password == confirm) {
                AppState.pickerOpen = true
                saveImage.launch("IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".png")
            }
        } else {
            Note("اختر الصورة كما وصلتك (ملف PNG)، وأدخل كلمة المرور التي أُخفي بها الملف.", icon = R.drawable.ic_image)
            Gap(16.dp)
            QsCard(onClick = { AppState.pickerOpen = true; pickImage.launch(arrayOf("image/*")) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tile(R.drawable.ic_image, if (image != null) Qs.brass else Qs.muted, size = 42.dp, radius = 14.dp, iconSize = 21.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(imageName.ifEmpty { "اختر الصورة" }, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                }
            }
            Gap(18.dp)
            Text("كلمة المرور", style = T.label)
            Gap(8.dp)
            QsField(value = password, onValueChange = { password = it }, placeholder = "••••••••••••", password = true, highlighted = true)
            Gap(24.dp)
            PrimaryButton("استخرج الملف", icon = R.drawable.ic_unlock, enabled = image != null && password.isNotEmpty()) { reveal() }
        }
        Gap(24.dp)
    }
    busy?.let { b -> ProgressDialog(b.title, b.fraction, b.detail) }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}
