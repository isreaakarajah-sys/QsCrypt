package com.qscrypt.app.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.fragment.app.FragmentActivity
import com.qscrypt.app.AppState
import com.qscrypt.app.PhoneAuth
import com.qscrypt.app.Prefs
import com.qscrypt.app.QsCore
import com.qscrypt.app.R
import com.qscrypt.app.Screen
import com.qscrypt.app.SelfTest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

@Suppress("DEPRECATION")
fun appVersion(context: Context): String =
    runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "?"

/** SHA-256 of the APK signing certificate, to check a copy received from a friend. */
@Suppress("DEPRECATION")
fun signingFingerprint(context: Context): String = runCatching {
    val pm = context.packageManager
    val signatures = if (Build.VERSION.SDK_INT >= 28) {
        pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
    } else {
        pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
    }
    val cert = signatures?.firstOrNull()?.toByteArray() ?: return@runCatching ""
    MessageDigest.getInstance("SHA-256").digest(cert).joinToString(":") { "%02X".format(it) }
}.getOrDefault("")

/** Shares this APK (Bluetooth, Nearby Share...) so friends can install the same build. */
fun shareApk(context: Context) {
    runCatching {
        val dir = File(context.cacheDir, "share").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val out = File(dir, "QsCrypt-${appVersion(context)}.apk")
        File(context.applicationInfo.sourceDir).copyTo(out, overwrite = true)
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.share", out)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        AppState.pickerOpen = true
        context.startActivity(Intent.createChooser(send, "شارك QsCrypt"))
    }.onFailure { Toast.makeText(context, "تعذّرت مشاركة التطبيق", Toast.LENGTH_LONG).show() }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Gap(22.dp)
    Text(title, style = T.label)
    Gap(10.dp)
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(Qs.surface).padding(horizontal = 16.dp, vertical = 6.dp)) {
        content()
    }
}

@Composable
private fun SettingRow(icon: Int, title: String, subtitle: String? = null, onClick: (() -> Unit)? = null, trailing: @Composable () -> Unit = {}) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 60.dp)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Tile(icon, Qs.brass, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = T.item)
            if (subtitle != null) Text(subtitle, style = T.small)
        }
        trailing()
    }
}

private val AUTOLOCK = listOf(0L to "فوراً", 30_000L to "30 ثانية", 60_000L to "دقيقة", 300_000L to "5 دقائق")

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var autoLock by remember { mutableLongStateOf(Prefs.autoLockMs) }
    var closeOnLock by remember { mutableStateOf(Prefs.closeVaultsOnLock) }
    var askOldPin by remember { mutableStateOf(false) }
    var settingPin by remember { mutableStateOf(false) }
    var soon by remember { mutableStateOf<String?>(null) }
    var testing by remember { mutableStateOf(false) }
    var lockMode by remember { mutableStateOf(PhoneAuth.mode(context)) }
    var disguised by remember { mutableStateOf(Prefs.disguised) }
    var askDisguise by remember { mutableStateOf(false) }
    val phoneAuth = remember { PhoneAuth.available(context) }
    val test = AppState.selfTest

    if (settingPin) {
        PinSetupScreen(onDone = { settingPin = false; Toast.makeText(context, "تم تغيير الرمز", Toast.LENGTH_SHORT).show() })
        return
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            Row(Modifier.height(48.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("الإعدادات", style = T.display.copy(lineHeight = 36.sp))
            }
            Section("الأمان") {
                SettingRow(R.drawable.ic_key, "تغيير الرمز السري", "رمز قفل التطبيق", onClick = { askOldPin = true })
                SettingRow(R.drawable.ic_lock, "أقفل التطبيق الآن", onClick = { AppState.lock() })
                Column(Modifier.padding(vertical = 8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Tile(R.drawable.ic_clock, Qs.brass, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text("القفل التلقائي", style = T.item)
                            Text("بعد مغادرة التطبيق", style = T.small)
                        }
                    }
                    Gap(10.dp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        AUTOLOCK.forEach { (ms, label) ->
                            Chip(label, autoLock == ms) {
                                autoLock = ms
                                Prefs.autoLockMs = ms
                            }
                        }
                    }
                }
                SettingRow(R.drawable.ic_vault, "أقفل الخزنات مع التطبيق", "تُغلق كل الخزنات المفتوحة عند القفل") {
                    QsSwitch(closeOnLock) {
                        closeOnLock = it
                        Prefs.closeVaultsOnLock = it
                    }
                }
                Column(Modifier.padding(vertical = 8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Tile(R.drawable.ic_finger, Qs.brass, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text("طريقة فتح التطبيق", style = T.item)
                            Text(if (phoneAuth) "البصمة أو الوجه أو قفل الهاتف" else "لا يوجد قفل شاشة على هذا الهاتف", style = T.small)
                        }
                    }
                    Gap(10.dp)
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Chip("الرمز فقط", lockMode == PhoneAuth.Mode.Pin) {
                                Prefs.lockMode = PhoneAuth.Mode.Pin.id
                                lockMode = PhoneAuth.Mode.Pin
                            }
                            Chip("الرمز + قفل الهاتف", lockMode == PhoneAuth.Mode.TwoFactor, enabled = phoneAuth) {
                                val a = context as? FragmentActivity ?: return@Chip
                                PhoneAuth.prompt(a, "QsCrypt", "تأكيد قفل الهاتف كخطوة ثانية") { ok, _ ->
                                    if (ok) {
                                        Prefs.lockMode = PhoneAuth.Mode.TwoFactor.id
                                        lockMode = PhoneAuth.Mode.TwoFactor
                                    }
                                }
                            }
                        }
                        Chip("قفل الهاتف أو الرمز", lockMode == PhoneAuth.Mode.Either, enabled = phoneAuth) {
                            val a = context as? FragmentActivity ?: return@Chip
                            PhoneAuth.prompt(a, "QsCrypt", "تأكيد الفتح بقفل الهاتف") { ok, _ ->
                                if (ok) {
                                    Prefs.lockMode = PhoneAuth.Mode.Either.id
                                    lockMode = PhoneAuth.Mode.Either
                                }
                            }
                        }
                    }
                    Gap(6.dp)
                    Text(
                        when (lockMode) {
                            PhoneAuth.Mode.TwoFactor -> "مصادقة ثنائية: الرمز السري ثم بصمتك أو قفل الهاتف. الأقوى."
                            PhoneAuth.Mode.Either -> "أيّهما شئت: الأسرع، لكن من يعرف قفل هاتفك يفتح التطبيق."
                            else -> "رمز QsCrypt المكوّن من 6 أرقام وحده."
                        },
                        style = T.small,
                    )
                }
                SettingRow(R.drawable.ic_sliders, "وضع التمويه", "يظهر التطبيق كآلة حاسبة تعمل") {
                    QsSwitch(disguised) { on ->
                        if (on) {
                            askDisguise = true
                        } else if (Disguise.apply(context, false)) {
                            disguised = false
                            Toast.makeText(context, "عادت أيقونة QsCrypt. قد يستغرق ظهورها دقيقة.", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            Section("المحرك") {
                Column(Modifier.padding(vertical = 10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Tile(R.drawable.ic_shield, if (test?.ok == true) Qs.mint else Qs.coral, size = 38.dp, radius = 12.dp, iconSize = 19.dp)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text("فحص التشفير", style = T.item)
                            Text(
                                when {
                                    test == null -> "جاري الفحص…"
                                    test.ok -> "كل الخوارزميات تطابق القيم المرجعية"
                                    else -> "بعض الخوارزميات لم تطابق، ولن تُعرض عند الإنشاء"
                                },
                                style = T.small,
                            )
                        }
                        Text(if (testing) "…" else "أعد", style = T.label.copy(color = Qs.brass), modifier = Modifier.clickable(enabled = !testing) {
                            testing = true
                            scope.launch {
                                AppState.selfTest = withContext(Dispatchers.Default) { SelfTest.run() }
                                testing = false
                            }
                        }.padding(8.dp))
                    }
                    if (test != null) {
                        Gap(10.dp)
                        test.items.forEach { item ->
                            Row(Modifier.fillMaxWidth().height(26.dp), verticalAlignment = Alignment.CenterVertically) {
                                QsIcon(if (item.ok) R.drawable.ic_check else R.drawable.ic_close, if (item.ok) Qs.mint else Qs.coral, 16.dp)
                                Spacer(Modifier.width(8.dp))
                                Text(item.name, style = T.mono.copy(fontSize = 12.sp, color = Qs.ivory))
                            }
                        }
                        Gap(6.dp)
                        Text("المحرك ${test.engine} – ${test.backend}", style = T.mono)
                    }
                }
            }
            Section("التطبيق") {
                SettingRow(R.drawable.ic_share, "شارك التطبيق", "أرسله لصديق عبر البلوتوث أو المشاركة القريبة", onClick = { shareApk(context) })
                SettingRow(R.drawable.ic_info, "حول QsCrypt", "الإصدار ${appVersion(context)}", onClick = { AppState.push(Screen.About) })
            }
            Gap(24.dp)
        }
        BottomNav(Screen.Settings)
    }

    if (askOldPin) {
        var pin by remember { mutableStateOf("") }
        var wrong by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { askOldPin = false },
            containerColor = Qs.surface,
            title = { Text("الرمز الحالي", style = T.title) },
            text = {
                Column {
                    QsField(value = pin, onValueChange = { v -> pin = v.filter { it.isDigit() }.take(6); wrong = false }, placeholder = "••••••", password = true, highlighted = true,
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword)
                    if (wrong) {
                        Gap(8.dp)
                        Text("رمز خاطئ", style = T.small.copy(color = Qs.coral))
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val attempt = pin
                    scope.launch {
                        val ok = withContext(Dispatchers.Default) { Prefs.checkPin(attempt) }
                        if (ok) {
                            askOldPin = false
                            settingPin = true
                        } else {
                            wrong = true
                        }
                    }
                }, enabled = pin.length == 6) { Text("متابعة", style = T.button.copy(color = Qs.brass, fontSize = 15.sp)) }
            },
            dismissButton = { TextButton(onClick = { askOldPin = false }) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
        )
    }
    soon?.let { s -> QsAlert("قريباً", s, "حسناً", { soon = null }, { soon = null }, dismiss = null) }
    if (askDisguise) {
        QsAlert(
            "وضع التمويه",
            "ستختفي أيقونة QsCrypt وتظهر مكانها «الآلة الحاسبة»، وهي حاسبة تعمل فعلاً.\n\nلفتح QsCrypt: اكتب رمزك السري (6 أرقام) ثم اضغط «=».\n\nقد يستغرق تغيّر الأيقونة دقيقة، وقد تحتاج لإضافتها إلى الشاشة الرئيسية من جديد. لا تنسَ رمزك: لا يظهر أي شيء آخر يدل على التطبيق.",
            "فعّل التمويه",
            {
                askDisguise = false
                if (Disguise.apply(context, true)) disguised = true
                else Toast.makeText(context, "تعذّر تفعيل التمويه على هذا الهاتف.", Toast.LENGTH_LONG).show()
            },
            { askDisguise = false },
        )
    }
}

@Composable
fun AboutScreen() {
    val context = LocalContext.current
    val fingerprint = remember { signingFingerprint(context) }
    val engine = remember { runCatching { QsCore.version() }.getOrDefault("?") }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        Gap(20.dp)
        TopBar("حول QsCrypt", onBack = { AppState.pop() })
        Gap(24.dp)
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(120.dp))
            Gap(16.dp)
            Image(painterResource(R.drawable.qs_wordmark), contentDescription = "QsCrypt", modifier = Modifier.size(width = 180.dp, height = 45.dp))
            Gap(10.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tag("الإصدار ${appVersion(context)}")
                Tag(RELEASE_NAME, TagKind.Brass)
            }
            Gap(6.dp)
            Text("المحرك $engine", style = T.mono.copy(color = Qs.brass, fontSize = 13.sp))
            Gap(10.dp)
            Text(
                "$DEVELOPER  ©  $RELEASE_YEAR",
                style = TextStyle(fontFamily = FontFamily.Serif, fontStyle = FontStyle.Italic, fontSize = 17.sp, color = Qs.brass),
            )
        }
        Gap(24.dp)
        Note("التطبيق لا يطلب صلاحية الإنترنت أصلاً: لا شيء يغادر جهازك، ولا يمكن لأي ملف أن يتسرّب عبر الشبكة.", icon = R.drawable.ic_wifioff)
        Gap(12.dp)
        QsCard {
            Column {
                Text("بصمة التوقيع (SHA-256)", style = T.item)
                Gap(6.dp)
                Text("قارنها مع نسخة صديقك: إن تطابقت فالتطبيق نفسه ولم يُعدَّل.", style = T.small)
                Gap(10.dp)
                Text(fingerprint.ifBlank { "غير متاحة" }, style = T.mono.copy(fontSize = 11.5.sp, lineHeight = 18.sp, color = Qs.ivory))
            }
        }
        Gap(12.dp)
        QsCard {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("في هذا الإصدار", style = T.item)
                listOf(
                    "فتح وإنشاء حاويات VeraCrypt وTrueCrypt، مع المجلد المخفي وحمايته وملفات المفاتيح وPIM",
                    "فتح أقراص BitLocker من ويندوز بكلمة المرور أو مفتاح الاسترداد، وإنشاؤها كملف VHD أو على فلاشة",
                    "فلاشات وهاردات USB عبر OTG مباشرة، دون روت، وتشفيرها بالكامل بأي صيغة",
                    "صيغة QsCrypt: AES ثم Twofish ثم XChaCha20-Poly1305 مع Argon2id، وحاويات QsCrypt",
                    "جهات الاتصال برمز QR: تشفير لا يفتحه إلا من تختار (X25519 + ML-KEM-768) وتوقيع Ed25519",
                    "مزايا الحماية: بلا إنترنت، صلاحية زمنية، مرة واحدة، عدد محاولات، كلمة طوارئ، مفتاح استرداد، فتح تلقائي",
                    "الكتابة على FAT وexFAT، وقراءة NTFS",
                    "الإخفاء داخل الصور، ووضع التمويه كآلة حاسبة",
                    "قفل بالرمز ومصادقة ثنائية بقفل الهاتف، ومنع لقطات الشاشة",
                ).forEach { Text("•  $it", style = T.body.copy(fontSize = 13.sp, color = Qs.muted)) }
            }
        }
        Gap(12.dp)
        Text("الخطوط: Hacen Liner (نسخة غير تجارية حتى النشر) وIBM Plex Mono (OFL).", style = T.small, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        Gap(28.dp)
    }
}

