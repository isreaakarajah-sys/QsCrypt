package com.qscrypt.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
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
import androidx.compose.ui.text.font.FontStyle
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
// Two balanced lines, broken at the verse's natural pause.
private const val VERSE = "فَاللَّهُ خَيْرٌ حَافِظًا\nوَهُوَ أَرْحَمُ الرَّاحِمِينَ"
private const val OPEN = "\uFD3F"
private const val CLOSE = "\uFD3E"

/** The supplication, one clause per line. */
private val DUA = listOf(
    "اللَّهُمَّ اكْسِرْ بِنَا شَوْكَتَهُمْ",
    "اللَّهُمَّ نَكِّسْ بِنَا رَايَتَهُمْ",
    "اللَّهُمَّ أَذِلَّ بِنَا قَادَتَهُمْ",
    "اللَّهُمَّ حَطِّمْ بِنَا هَيْبَتَهُمْ",
    "اللَّهُمَّ أَنْفِذْ بِنَا قَدَرَكَ فِيهِمْ",
)
const val RELEASE_YEAR = "2026"
const val RELEASE_NAME = "الإصدار الأول"
const val DEVELOPER = "SaJedApps"

/**
 * The opening screen, shown on every launch after activation and before any
 * lock: the emblem and name, the verse, the supplication, the edition and
 * the developer's signature. Everything scales down together on short or
 * narrow screens, so nothing is cut or wrapped.
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
        launch { dua.animateTo(1f, tween(1600, delayMillis = 2200, easing = FastOutSlowInEasing)) }
        launch { footer.animateTo(1f, tween(1000, delayMillis = 3400)) }
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
    BoxWithConstraints(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF0C3326), Qs.base, Color(0xFF071F18))))
            .semantics { contentDescription = "QsCrypt. ${VERSE.replace('\n', ' ')}. ${DUA.joinToString("، ")}. $RELEASE_NAME. $DEVELOPER $RELEASE_YEAR" },
    ) {
        // Laid out for 860 x 400 dp; smaller screens scale everything down.
        val k = minOf(maxHeight / 860.dp, maxWidth / 400.dp, 1f).coerceAtLeast(0.62f)
        fun d(v: Int) = (v * k).dp
        fun s(v: Int) = (v * k).sp

        // A faint brass halo behind the emblem.
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(
                Brush.radialGradient(listOf(Qs.brass.copy(alpha = 0.16f * logo.value), Color.Transparent), center = Offset(size.width / 2, size.height * 0.2f), radius = size.width * 0.62f),
                radius = size.width * 0.62f,
                center = Offset(size.width / 2, size.height * 0.2f),
            )
        }
        Column(
            Modifier.fillMaxSize().padding(horizontal = d(26)),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.weight(0.8f))
            Image(
                painterResource(R.drawable.qs_emblem),
                contentDescription = null,
                modifier = Modifier.size(d(100)).alpha(logo.value).scale(0.86f + 0.14f * logo.value),
            )
            Gap(d(14))
            Image(
                painterResource(R.drawable.qs_wordmark),
                contentDescription = "QsCrypt",
                modifier = Modifier.height(d(30)).alpha(logo.value),
            )
            Gap(d(6))
            Text(
                "التشفير بثقة",
                style = TextStyle(fontFamily = HacenXL, fontSize = s(13), color = Qs.muted, letterSpacing = 1.sp),
                modifier = Modifier.alpha(logo.value),
            )
            Spacer(Modifier.weight(0.6f))

            Ornament(Modifier.alpha(verse.value))
            Gap(d(16))
            Text(
                verseText,
                style = TextStyle(fontFamily = HacenXL, fontSize = s(34), lineHeight = s(60), color = Qs.ivory),
                textAlign = TextAlign.Center,
                softWrap = false,
                modifier = Modifier.alpha(verse.value),
            )
            Gap(d(22))
            Column(
                Modifier.alpha(dua.value).clip(RoundedCornerShape(d(18))).background(Qs.surface.copy(alpha = 0.55f)).padding(horizontal = d(20), vertical = d(12)),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                val style = TextStyle(fontFamily = HacenPrint, fontSize = s(21), lineHeight = s(40), color = Color(0xFFE8DDBF))
                DUA.forEachIndexed { i, line ->
                    // Each clause fades in a moment after the one before it.
                    val a = ((dua.value * (DUA.size + 1)) - i).coerceIn(0f, 1f)
                    Text(line, style = style, textAlign = TextAlign.Center, softWrap = false, modifier = Modifier.alpha(a))
                }
            }
            Gap(d(18))
            Ornament(Modifier.alpha(dua.value))
            Spacer(Modifier.weight(1f))

            // The edition, then the developer's signature and the year.
            Row(Modifier.alpha(footer.value), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.width(d(34)).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
                Spacer(Modifier.width(d(12)))
                Text(RELEASE_NAME, style = TextStyle(fontFamily = HacenXL, fontSize = s(16), color = Qs.ivory))
                Spacer(Modifier.width(d(12)))
                Box(Modifier.width(d(34)).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
            }
            Gap(d(8))
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Row(Modifier.alpha(footer.value), verticalAlignment = Alignment.Bottom) {
                    Text(
                        DEVELOPER,
                        style = TextStyle(fontFamily = FontFamily.Serif, fontStyle = FontStyle.Italic, fontWeight = FontWeight.Medium, fontSize = s(19), color = Qs.brass, letterSpacing = 0.6.sp),
                    )
                    Spacer(Modifier.width(d(8)))
                    Text(
                        "© $RELEASE_YEAR",
                        style = TextStyle(fontFamily = PlexMono, fontSize = s(12), color = Qs.muted, letterSpacing = 1.sp),
                        modifier = Modifier.padding(bottom = d(2)),
                    )
                }
            }
            Gap(d(4))
            Text("v" + appVersion(context), style = T.mono.copy(color = Qs.muted.copy(alpha = 0.6f), fontSize = s(11)), modifier = Modifier.alpha(footer.value))
            Gap(d(14))
            Box(Modifier.fillMaxWidth(0.42f).height(2.dp).clip(RoundedCornerShape(1.dp)).background(Qs.line)) {
                Box(Modifier.fillMaxWidth(progress.value).height(2.dp).background(Qs.brass))
            }
            Gap(d(22))
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
