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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Gap(72.dp)
        Image(painterResource(R.drawable.qs_emblem), contentDescription = null, modifier = Modifier.size(92.dp))
        Gap(20.dp)
        Image(painterResource(R.drawable.qs_wordmark), contentDescription = "QsCrypt", modifier = Modifier.size(width = 168.dp, height = 42.dp))
        Gap(24.dp)
        Text("تفعيل التطبيق", style = T.display, textAlign = TextAlign.Center)
        Gap(8.dp)
        Text(
            "أدخل كلمة التفعيل التي وصلتك مع التطبيق. تُطلب مرة واحدة فقط على هذا الجهاز.",
            style = T.body.copy(fontSize = 15.sp, lineHeight = 24.sp, color = Qs.muted),
            textAlign = TextAlign.Center,
        )
        Gap(28.dp)
        QsField(
            value = code,
            onValueChange = { code = it.take(40); error = null },
            placeholder = "رمز التفعيل",
            password = true,
            highlighted = true,
        )
        Gap(10.dp)
        val message = when {
            waitMs > 0L -> "محاولات كثيرة خاطئة. انتظر ${(waitMs + 999) / 1000} ثانية"
            else -> error
        }
        if (message != null) {
            Text(message, style = T.small.copy(color = Qs.coral), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
            Gap(10.dp)
        }
        Gap(8.dp)
        if (busy) {
            Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(color = Qs.brass, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Text("جاري التحقق…", style = T.label.copy(color = Qs.ivory))
            }
        } else {
            PrimaryButton("تفعيل", icon = R.drawable.ic_key, enabled = code.isNotBlank() && waitMs == 0L) { submit() }
        }
        Gap(20.dp)
        Note("هذه النسخة خاصة بك وبمن تشاركه معهم. كلمة التفعيل تفكّ أيضاً خطوط التطبيق المشفّرة، ولا تُحفظ على الجهاز.", icon = R.drawable.ic_shield)
        Gap(24.dp)
    }
}
