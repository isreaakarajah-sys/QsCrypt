package com.qscrypt.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.R
import kotlinx.coroutines.launch

/** How long the opening screen stays, and cannot be skipped. */
const val SPLASH_MS = 7_000

// Set in the app's own Hacen fonts, which carry every letter and haraka of the
// verse; only the ornate brackets come from the system's Naskh face.
private const val VERSE = "فَاللَّهُ خَيْرٌ حَافِظًا وَهُوَ أَرْحَمُ الرَّاحِمِينَ"
private const val OPEN = "\uFD3F"
private const val CLOSE = "\uFD3E"
private const val DUA_1 = "اللَّهُمَّ انْصُرِ الْإِسْلَامَ وَالْمُسْلِمِينَ"
private const val DUA_2 = "اللَّهُمَّ أَعِزَّ الْإِسْلَامَ وَالْمُسْلِمِينَ"
const val RELEASE_YEAR = "2026"
const val RELEASE_NAME = "الإصدار الأول"

/**
 * The opening screen, shown on every launch before any lock or password:
 * the emblem and name, the verse, the supplication, and the edition.
 * The Arabic texts use the system Naskh font, which carries the full
 * diacritics of the Qur'anic text.
 */
@Composable
fun SplashScreen(onDone: () -> Unit) {
    BackHandler(enabled = true) {}
    val context = LocalContext.current
    val logo = remember { Animatable(0f) }
    val verse = remember { Animatable(0f) }
    val dua = remember { Animatable(0f) }
    val footer = remember { Animatable(0f) }
    val progress = remember { Animatable(0f) }
    LaunchedEffect(Unit) {
        launch { progress.animateTo(1f, tween(SPLASH_MS, easing = LinearEasing)) }
        launch { logo.animateTo(1f, tween(1100, easing = FastOutSlowInEasing)) }
        launch { verse.animateTo(1f, tween(1400, delayMillis = 900, easing = FastOutSlowInEasing)) }
        launch { dua.animateTo(1f, tween(1400, delayMillis = 2200, easing = FastOutSlowInEasing)) }
        launch { footer.animateTo(1f, tween(1000, delayMillis = 3200)) }
        kotlinx.coroutines.delay(SPLASH_MS.toLong())
        onDone()
    }
    // Brackets as brass ornaments around the verse.
    val verseText = remember {
        buildAnnotatedString {
            val bracket = SpanStyle(fontFamily = FontFamily.Serif, color = Qs.brass, fontWeight = FontWeight.Normal)
            withStyle(bracket) { append(OPEN) }
            append("  ")
            append(VERSE)
            append("  ")
            withStyle(bracket) { append(CLOSE) }
        }
    }
    Box(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF0C3326), Qs.base, Color(0xFF071F18))))
            .semantics { contentDescription = "QsCrypt. $VERSE. $DUA_1. $DUA_2. $RELEASE_NAME $RELEASE_YEAR" },
    ) {
        // A faint brass halo behind the emblem.
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(
                Brush.radialGradient(listOf(Qs.brass.copy(alpha = 0.16f * logo.value), Color.Transparent), center = Offset(size.width / 2, size.height * 0.24f), radius = size.width * 0.62f),
                radius = size.width * 0.62f,
                center = Offset(size.width / 2, size.height * 0.24f),
            )
        }
        Column(
            Modifier.fillMaxSize().padding(horizontal = 30.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.weight(0.9f))
            Image(
                painterResource(R.drawable.qs_emblem),
                contentDescription = null,
                modifier = Modifier.size(112.dp).alpha(logo.value).scale(0.86f + 0.14f * logo.value),
            )
            Gap(18.dp)
            Image(
                painterResource(R.drawable.qs_wordmark),
                contentDescription = "QsCrypt",
                modifier = Modifier.height(34.dp).alpha(logo.value),
            )
            Gap(8.dp)
            Text(
                "التشفير بثقة",
                style = TextStyle(fontFamily = HacenXL, fontSize = 13.sp, color = Qs.muted, letterSpacing = 1.sp),
                modifier = Modifier.alpha(logo.value),
            )
            Spacer(Modifier.weight(0.7f))

            Ornament(Modifier.alpha(verse.value))
            Gap(22.dp)
            Text(
                verseText,
                style = TextStyle(fontFamily = HacenXL, fontSize = 31.sp, lineHeight = 58.sp, color = Qs.ivory),
                textAlign = TextAlign.Center,
                modifier = Modifier.alpha(verse.value),
            )
            Gap(30.dp)
            Column(
                Modifier.alpha(dua.value).clip(RoundedCornerShape(18.dp)).background(Qs.surface.copy(alpha = 0.55f)).padding(horizontal = 20.dp, vertical = 14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                val style = TextStyle(fontFamily = HacenPrint, fontSize = 21.sp, lineHeight = 40.sp, color = Color(0xFFE8DDBF))
                Text(DUA_1, style = style, textAlign = TextAlign.Center)
                Text(DUA_2, style = style, textAlign = TextAlign.Center)
            }
            Gap(22.dp)
            Ornament(Modifier.alpha(dua.value))
            Spacer(Modifier.weight(1f))

            // Edition: year and "first edition", set like a book's colophon.
            Row(Modifier.alpha(footer.value), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.width(34.dp).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
                Spacer(Modifier.width(12.dp))
                Text(RELEASE_NAME, style = TextStyle(fontFamily = HacenXL, fontSize = 15.sp, color = Qs.ivory))
                Spacer(Modifier.width(10.dp))
                Box(Modifier.size(4.dp).clip(RoundedCornerShape(2.dp)).background(Qs.brass))
                Spacer(Modifier.width(10.dp))
                Text(RELEASE_YEAR, style = TextStyle(fontFamily = PlexMono, fontSize = 15.sp, color = Qs.brass, letterSpacing = 2.sp))
                Spacer(Modifier.width(12.dp))
                Box(Modifier.width(34.dp).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
            }
            Gap(6.dp)
            Text("v" + appVersion(context), style = T.mono.copy(color = Qs.muted.copy(alpha = 0.7f)), modifier = Modifier.alpha(footer.value))
            Gap(18.dp)
            Box(Modifier.fillMaxWidth(0.42f).height(2.dp).clip(RoundedCornerShape(1.dp)).background(Qs.line)) {
                Box(Modifier.fillMaxWidth(progress.value).height(2.dp).background(Qs.brass))
            }
            Gap(26.dp)
        }
    }
}

/** A thin brass rule with a small diamond in the middle. */
@Composable
private fun Ornament(modifier: Modifier = Modifier) = CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.width(64.dp).height(1.dp).background(Brush.horizontalGradient(listOf(Color.Transparent, Qs.brass))))
        Spacer(Modifier.width(8.dp))
        Canvas(Modifier.size(8.dp)) {
            rotate(45f) { drawRect(Qs.brass) }
        }
        Spacer(Modifier.width(8.dp))
        Box(Modifier.width(64.dp).height(1.dp).background(Brush.horizontalGradient(listOf(Qs.brass, Color.Transparent))))
    }
}
