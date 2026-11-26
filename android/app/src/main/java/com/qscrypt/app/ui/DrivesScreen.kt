package com.qscrypt.app.ui

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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.R
import com.qscrypt.app.Screen
import com.qscrypt.app.UsbDrives
import com.qscrypt.app.UsbTarget
import com.qscrypt.app.humanSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What a partition or drive holds, in words. */
fun kindText(kind: String): Pair<String, TagKind> = when (kind) {
    "bitlocker" -> "BitLocker" to TagKind.Brass
    "qscrypt" -> "QsCrypt" to TagKind.Brass
    "encrypted" -> "مشفّر أو غير معروف" to TagKind.Outline
    "fat" -> "FAT غير مشفّر" to TagKind.Neutral
    "exfat" -> "exFAT غير مشفّر" to TagKind.Neutral
    "ntfs" -> "NTFS غير مشفّر" to TagKind.Neutral
    "empty" -> "فارغ" to TagKind.Neutral
    "partitioned" -> "مقسّم" to TagKind.Neutral
    else -> kind.ifEmpty { "—" } to TagKind.Neutral
}

private val ENCRYPT_FORMATS = listOf(
    "VeraCrypt" to "يُفتح بـ VeraCrypt على أي حاسوب، ويدعم المجلد المخفي",
    "BitLocker" to "يفتحه ويندوز مباشرة دون أي برنامج",
    "QsCrypt" to "الأقوى، ويُفتح بـ QsCrypt فقط",
    "TrueCrypt" to "للبرامج القديمة فقط",
)

@Composable
fun DrivesScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var drives by remember { mutableStateOf(UsbDrives.list(context)) }
    var connecting by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var encrypt by remember { mutableStateOf<UsbTarget?>(null) }

    // Drives come and go, and permission answers arrive asynchronously.
    LaunchedEffect(Unit) {
        while (true) {
            drives = UsbDrives.list(context)
            delay(1500)
        }
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Gap(20.dp)
            Text("الأقراص", style = T.display.copy(lineHeight = 36.sp))
            Gap(4.dp)
            Text("فلاشات وهاردات USB موصولة بالجوال عبر OTG", style = T.small)
            Gap(20.dp)
            if (drives.isEmpty()) {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Tile(R.drawable.ic_usb, Qs.muted, size = 84.dp, radius = 26.dp, iconSize = 40.dp) }
                Gap(16.dp)
                Text("لا يوجد قرص موصول", style = T.title, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                Gap(6.dp)
                Text("وصّل فلاشة أو هارداً خارجياً بوصلة OTG، وسيظهر هنا خلال ثوانٍ.", style = T.body.copy(color = Qs.muted), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
            }
            drives.forEach { d ->
                val session = UsbDrives.sessions.firstOrNull { it.drive.key == d.key }
                QsCard {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Tile(R.drawable.ic_usb, if (session != null) Qs.brass else Qs.muted, size = 48.dp, radius = 15.dp, iconSize = 24.dp)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(d.title, style = T.itemLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                if (session != null) {
                                    val info = session.info
                                    Text(
                                        listOf(humanSize(info.optLong("size")), info.optString("vendor").trim(), info.optString("product").trim()).filter { it.isNotEmpty() }.joinToString(" · "),
                                        style = T.mono.copy(fontSize = 12.sp), maxLines = 1, overflow = TextOverflow.Ellipsis,
                                    )
                                } else {
                                    Text("غير متصل بالتطبيق", style = T.small)
                                }
                            }
                            if (session != null) {
                                if (session.info.optBoolean("writeProtected")) Tag("للقراءة فقط", TagKind.Outline)
                                IconBtn(R.drawable.ic_close, "فصل", tint = Qs.muted) {
                                    UsbDrives.close(session)
                                }
                            }
                        }
                        Gap(12.dp)
                        when {
                            session != null -> {
                                UsbDrives.targets(session).forEach { t ->
                                    TargetRow(t, onOpen = {
                                        val c = UsbDrives.container(session, t)
                                        val open = AppState.sessionFor(c)
                                        if (open != null) AppState.push(Screen.Vault(open.handle)) else AppState.push(Screen.Unlock(c, t))
                                    }, onEncrypt = {
                                        if (session.info.optBoolean("writeProtected")) message = "هذا القرص محمي من الكتابة."
                                        else encrypt = t
                                    })
                                }
                            }
                            connecting == d.key -> Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(10.dp))
                                Text("جاري الاتصال بالقرص…", style = T.label)
                            }
                            !UsbDrives.hasPermission(context, d) -> SecondaryButton("اسمح لـ QsCrypt بالوصول", icon = R.drawable.ic_unlock) {
                                UsbDrives.requestPermission(context, d)
                            }
                            else -> PrimaryButton("اتصل بالقرص", icon = R.drawable.ic_drive) {
                                connecting = d.key
                                scope.launch {
                                    val r = withContext(Dispatchers.IO) { UsbDrives.open(context, d) }
                                    connecting = null
                                    if (!r.ok) message = "تعذّر الاتصال بالقرص: ${r.error}\nجرّب فصله ووصله مجدداً، أو وصلة OTG أخرى."
                                }
                            }
                        }
                    }
                }
                Gap(12.dp)
            }
            Gap(6.dp)
            Note("يتعامل QsCrypt مع القرص مباشرة (USB Mass Storage)، فيفتح أقراص VeraCrypt وBitLocker وQsCrypt التي لا يقرؤها أندرويد، دون روت. أثناء اتصاله هنا لا يراه أندرويد، فافصله من هنا قبل نزعه.", icon = R.drawable.ic_info)
            Gap(10.dp)
            Note("الحاويات المحفوظة كملفات على فلاشة تُفتح من «خزناتي» ← «افتح حاوية».", icon = R.drawable.ic_folder)
            Gap(24.dp)
        }
        BottomNav(Screen.Drives)
    }
    encrypt?.let { t ->
        AlertDialog(
            onDismissRequest = { encrypt = null },
            containerColor = Qs.surface,
            title = { Text("تشفير «${t.title}»", style = T.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("اختر الصيغة. سيُمسح القرص بالكامل.", style = T.body.copy(color = Qs.muted))
                    ENCRYPT_FORMATS.forEach { (f, desc) ->
                        Column(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Qs.surface2)
                                .clickable { encrypt = null; AppState.push(Screen.NewContainer(f, t)) }.padding(12.dp),
                        ) {
                            Text(f, style = T.item)
                            Text(desc, style = T.small)
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { encrypt = null }) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
        )
    }
    message?.let { m -> QsAlert("QsCrypt", m, "حسناً", { message = null }, { message = null }, dismiss = null) }
}

@Composable
private fun TargetRow(t: UsbTarget, onOpen: () -> Unit, onEncrypt: () -> Unit) {
    val (kind, tagKind) = kindText(t.kind)
    val encrypted = t.kind in setOf("bitlocker", "qscrypt", "encrypted")
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Qs.base).padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(t.title, style = T.item, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(humanSize(t.size), style = T.mono.copy(fontSize = 12.sp))
                    Spacer(Modifier.width(8.dp))
                    Tag(kind, tagKind)
                }
            }
        }
        Gap(10.dp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (t.kind != "partitioned" && t.kind != "empty") {
                SecondaryButton("فتح", modifier = Modifier.weight(1f).height(44.dp), icon = R.drawable.ic_unlock, color = if (encrypted) Qs.brass else Qs.ivory) { onOpen() }
            }
            SecondaryButton("تشفير", modifier = Modifier.weight(1f).height(44.dp), icon = R.drawable.ic_lock, color = Qs.coral) { onEncrypt() }
        }
    }
    Gap(8.dp)
}
