package com.qscrypt.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.qscrypt.app.Activation
import com.qscrypt.app.Prefs
import com.qscrypt.app.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** First launch: the activation password, asked once. */
@Composable
fun ActivationScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val waitMs = (Prefs.activationLockUntil - now).coerceAtLeast(0L)

    LaunchedEffect(waitMs > 0L) {
        while (Prefs.activationLockUntil > System.currentTimeMillis()) {
            now = System.currentTimeMillis()
            delay(500)
        }
        now = System.currentTimeMillis()
    }

    fun submit() {
        if (code.isBlank() || busy || waitMs > 0L) return
        busy = true
        error = null
        val attempt = code
        scope.launch {
            val ok = withContext(Dispatchers.Default) { Activation.activate(context, attempt) }
            busy = false
            if (ok) {
                Prefs.activationFails = 0
                Prefs.activationLockUntil = 0
                onDone()
            } else {
                val n = Prefs.activationFails + 1
                Prefs.activationFails = n
                if (n >= 5) {
                    val seconds = (30L shl (n - 5).coerceAtMost(7)).coerceAtMost(3600)
                    Prefs.activationLockUntil = System.currentTimeMillis() + seconds * 1000
                }
                now = System.currentTimeMillis()
                error = "كلمة التفعيل غير صحيحة."
            }
        }
    }

    // The app's fonts are still sealed here, so every text on this screen is
    // drawn from outlines of those fonts (android/tools/text_art.py).
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Gap(72.dp)
        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(92.dp))
        Gap(20.dp)
        Image(painterResource(R.drawable.qs_wordmark), contentDescription = "QsCrypt", modifier = Modifier.size(width = 168.dp, height = 42.dp))
        Gap(24.dp)
        Art(R.drawable.art_act_title, "تفعيل التطبيق", Qs.ivory)
        Gap(12.dp)
        Art(R.drawable.art_act_intro, "أدخل كلمة التفعيل التي وصلتك مع التطبيق. تُطلب مرة واحدة فقط على هذا الجهاز.", Qs.muted)
        Gap(28.dp)
        QsField(
            value = code,
            onValueChange = { code = it.take(40); error = null },
            placeholder = "رمز التفعيل",
            password = true,
            highlighted = true,
            placeholderContent = { Art(R.drawable.art_act_field, "رمز التفعيل", Qs.muted) },
        )
        Gap(10.dp)
        if (waitMs > 0L) {
            val seconds = ((waitMs + 999) / 1000).toString()
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.semantics(mergeDescendants = true) {}) {
                Art(R.drawable.art_act_wait, "محاولات كثيرة خاطئة. انتظر", Qs.coral)
                Spacer(Modifier.width(6.dp))
                Text(seconds, style = T.monoLarge.copy(color = Qs.coral))
                Spacer(Modifier.width(6.dp))
                Art(R.drawable.art_act_seconds, "ثانية", Qs.coral)
            }
            Gap(10.dp)
        } else if (error != null) {
            Art(R.drawable.art_act_wrong, error, Qs.coral)
            Gap(10.dp)
        }
        Gap(8.dp)
        if (busy) {
            Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Art(R.drawable.art_act_checking, "جاري التحقق", Qs.ivory)
            }
        } else {
            PrimaryArtButton(R.drawable.art_act_button, "تفعيل", icon = R.drawable.ic_key, enabled = code.isNotBlank() && waitMs == 0L) { submit() }
        }
        Gap(20.dp)
        ArtNote(R.drawable.art_act_note, "هذه النسخة خاصة بك وبمن تشاركه معهم. كلمة التفعيل تفكّ أيضًا خطوط التطبيق المشفّرة، ولا تُحفظ على الجهاز.")
        Gap(24.dp)
    }
}
