package com.qscrypt.app.ui

import android.view.HapticFeedbackConstants
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.sin

/** How long the opening screen stays by itself. */
const val SPLASH_MS = 13_000

/** From this moment a tap anywhere opens the app without waiting for the rest. */
const val SPLASH_SKIP_MS = 7_000

private const val TAGLINE = "صَوْنُ الأماناتِ وتحصينُ الأسرار"

// The verse on a single line, in the app's Hacen XL, between brass brackets
// drawn as vectors (the same on every phone).
private const val VERSE = "فَاللَّهُ خَيْرٌ حَافِظًا وَهُوَ أَرْحَمُ الرَّاحِمِينَ"

/** Every clause opens with this word, set in brass. */
private const val ALLAHUMMA = "اللَّهُمَّ"

/** The supplication: two clauses on each of the first two lines, the last one alone between brass wings. */
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

// Layout rules. android/tools/splash_preview.py (frame "cartouche") follows the
// same numbers, so the preview image matches the phone.
private const val VERSE_SIDE = 6       // dp, side margin of the verse
private const val PANEL_SIDE = 8       // dp, side margin of the supplication's frame
private const val PANEL_INSET = 12     // dp, inside the frame
private const val BRACKET_H = 1.15f    // bracket height, in verse ems (the drawing is 1:3)
private const val BRACKET_GAP = 0.14f  // between a bracket and the verse, in verse ems
private const val SEP = 1.5f           // between the two clauses of a line, in dua ems (a star sits in it)
private const val WING = 2.6f          // least room for each wing of the last line, in dua ems
private const val LINE_H = 2.15f       // dua line height, in ems
private const val VERSE_MAX = 46f      // sp, on wide screens
private const val DUA_MAX = 30f
private const val SIGNATURE_ASPECT = 719.2f / 133.7f   // qs_signature.xml viewport
private val DUA_COLOR = Color(0xFFE8DDBF)
private val TAG_COLOR = Color(0xFFD6C8A0)
private val MEDALLION = Color(0xFF0D3226)
private val DUST = Color(0xFFE9CD82)

/**
 * The opening screen's way out, shared with the screen underneath: the app
 * appears through a brass portal that opens from the safe dial.
 */
@Stable
class SplashExit {
    /** The app may be composed underneath (the portal is about to open). */
    var revealing by mutableStateOf(false)
    /** How far the portal has opened, 0 to 1. */
    var progress by mutableFloatStateOf(0f)
}

/** The app underneath the opening screen while the portal opens: it rises from slightly further away. */
fun Modifier.underSplash(exit: SplashExit, active: Boolean): Modifier =
    if (!active) this else graphicsLayer {
        val p = exit.progress
        val s = 1.08f - 0.08f * p
        scaleX = s
        scaleY = s
        alpha = 0.3f + 0.7f * p
    }

/**
 * The opening screen, shown on every launch after activation and before any
 * lock: the emblem and name, the motto, the verse on one line, the
 * supplication framed in three lines of one width, the edition and the
 * developer's signature.
 *
 * The verse and the supplication are as large as the screen's width allows:
 * their widths are measured in the real font and the sizes worked out from
 * them, so nothing wraps or gets cut, from small phones to tablets.
 *
 * Leaving: the dial turns with three ticks, the words fade, and a brass ring
 * opens from the dial's centre like a portal, scattering gold dust, with the
 * app rising behind it.
 */
@Composable
fun SplashScreen(exit: SplashExit, onDone: () -> Unit) {
    BackHandler(enabled = true) {}
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    val done by rememberUpdatedState(onDone)
    var leavingStarted by remember { mutableStateOf(false) }
    var canSkip by remember { mutableStateOf(false) }
    val logo = remember { Animatable(0f) }
    val verse = remember { Animatable(0f) }
    val dua = remember { Animatable(0f) }
    val footer = remember { Animatable(0f) }
    val progress = remember { Animatable(0f) }
    val hint = remember { Animatable(0f) }
    val leaving = remember { Animatable(0f) }   // the dial turns, the words fade
    val portal = remember { Animatable(0f) }    // the ring opens

    fun leave() {
        if (leavingStarted) return
        leavingStarted = true
        exit.revealing = true
        scope.launch {
            launch {
                for (t in listOf(90L, 150L, 150L)) {
                    delay(t)
                    view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                }
            }
            launch { leaving.animateTo(1f, tween(560, easing = FastOutSlowInEasing)) }
            delay(400)
            portal.animateTo(1f, tween(1150, easing = CubicBezierEasing(0.45f, 0f, 0.2f, 1f))) {
                exit.progress = value
            }
            done()
        }
    }

    LaunchedEffect(Unit) {
        launch { progress.animateTo(1f, tween(SPLASH_MS, easing = LinearEasing)) }
        launch { logo.animateTo(1f, tween(1100, easing = FastOutSlowInEasing)) }
        launch { verse.animateTo(1f, tween(1400, delayMillis = 900, easing = FastOutSlowInEasing)) }
        launch { dua.animateTo(1f, tween(2600, delayMillis = 2200, easing = LinearEasing)) }
        launch { footer.animateTo(1f, tween(1000, delayMillis = 4400)) }
        launch {
            delay(SPLASH_SKIP_MS.toLong())
            canSkip = true
            hint.animateTo(1f, tween(700))
        }
        delay(SPLASH_MS.toLong())
        leave()
    }

    // Where the dial is, in this screen's coordinates: the portal opens there.
    var rootBounds by remember { mutableStateOf(Rect.Zero) }
    var dialBounds by remember { mutableStateOf(Rect.Zero) }
    val dust = remember { Dust.make(64) }

    BoxWithConstraints(
        Modifier
            .fillMaxSize()
            .onGloballyPositioned { rootBounds = it.boundsInRoot() }
            .graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }
            .drawWithContent {
                drawContent()
                val p = portal.value
                if (p <= 0f) return@drawWithContent
                val c = if (dialBounds != Rect.Zero) dialBounds.center - rootBounds.topLeft else Offset(size.width / 2, size.height * 0.25f)
                val far = maxOf(hypot(c.x, c.y), hypot(size.width - c.x, c.y), hypot(c.x, size.height - c.y), hypot(size.width - c.x, size.height - c.y))
                val r = p * (far + 40.dp.toPx())
                if (r < 1f) return@drawWithContent
                val soft = 34.dp.toPx()
                // The portal: the screen clears inside the ring, softly at its edge.
                drawCircle(
                    Brush.radialGradient(
                        0f to Color.Black,
                        ((r - soft).coerceAtLeast(0f) / r) to Color.Black,
                        1f to Color.Transparent,
                        center = c,
                        radius = r,
                    ),
                    radius = r,
                    center = c,
                    blendMode = BlendMode.DstOut,
                )
                // The brass rim with its glow, fading as it reaches the edges.
                val fade = (1f - p * p).coerceIn(0f, 1f)
                val rim = (r - soft * 0.55f).coerceAtLeast(1f)
                drawCircle(Qs.brass.copy(alpha = 0.18f * fade), radius = rim, center = c, style = Stroke(width = 22.dp.toPx()))
                drawCircle(Qs.brass.copy(alpha = 0.35f * fade), radius = rim, center = c, style = Stroke(width = 7.dp.toPx()))
                drawCircle(DUST.copy(alpha = 0.95f * fade), radius = rim, center = c, style = Stroke(width = 2.dp.toPx()))
                // Gold dust thrown off the rim.
                val unit = 1.dp.toPx()
                for (d in dust) {
                    val pr = rim * (1f + d.speed * p) + d.jitter * unit
                    val a = fade * (0.55f + 0.45f * sin(d.phase + p * 14f))
                    drawCircle(DUST.copy(alpha = a.coerceIn(0f, 1f)), radius = d.size * unit, center = c + Offset(cos(d.angle) * pr, sin(d.angle) * pr))
                }
            }
            .background(Brush.verticalGradient(listOf(Color(0xFF0C3326), Qs.base, Color(0xFF071F18))))
            .drawBehind {
                // A faint brass halo behind the emblem, stronger while the dial turns.
                val c = if (dialBounds != Rect.Zero) dialBounds.center - rootBounds.topLeft else Offset(size.width / 2, size.height * 0.2f)
                drawCircle(
                    Brush.radialGradient(listOf(Qs.brass.copy(alpha = 0.16f * logo.value * (1f + 0.9f * leaving.value)), Color.Transparent), center = c, radius = size.width * 0.62f),
                    radius = size.width * 0.62f,
                    center = c,
                )
            }
            .pointerInput(Unit) { detectTapGestures { if (canSkip) leave() } }
            .semantics { contentDescription = "QsCrypt. $TAGLINE. $VERSE. ${DUA.joinToString("، ")}. $RELEASE_NAME. $DEVELOPER $RELEASE_YEAR" }
            .systemBarsPadding(),
    ) {
        val density = LocalDensity.current
        val measurer = rememberTextMeasurer()
        // Short screens (or a phone on its side) shrink the fixed parts; the texts follow the width.
        val kv = (maxHeight / 800.dp).coerceAtMost(1f)
        fun d(v: Float) = (v * kv).dp
        val out = 1f - leaving.value

        val refPx = with(density) { 40.sp.toPx() }
        val xl = HacenXL
        // Widths in ems, measured once per font.
        val verseEm = remember(xl, density) {
            measurer.measure(AnnotatedString(VERSE), TextStyle(fontFamily = xl, fontSize = 40.sp), softWrap = false, maxLines = 1).size.width / refPx
        } + 2 * (BRACKET_H / 3f + BRACKET_GAP)
        val clauseEm = remember(xl, density) {
            DUA.map { measurer.measure(AnnotatedString(it), TextStyle(fontFamily = xl, fontSize = 40.sp), softWrap = false, maxLines = 1).size.width / refPx }
        }
        val lineEm = maxOf(clauseEm[0] + clauseEm[1] + SEP, clauseEm[2] + clauseEm[3] + SEP, clauseEm[4] + 2 * WING)
        // Largest sizes that fit, a hair under, so rounding never wraps a line.
        val verseWidthPx = with(density) { (maxWidth - (2 * VERSE_SIDE).dp).toPx() }
        val duaWidthPx = with(density) { (maxWidth - (2 * (PANEL_SIDE + PANEL_INSET)).dp).toPx() }
        val versePx = minOf(verseWidthPx / verseEm * 0.99f, with(density) { VERSE_MAX.sp.toPx() }, with(density) { (42f * kv).sp.toPx() })
        val duaPx = minOf(duaWidthPx / lineEm * 0.99f, with(density) { DUA_MAX.sp.toPx() }, with(density) { (26f * kv).sp.toPx() })
        val verseSize = with(density) { versePx.toSp() }
        val duaSize = with(density) { duaPx.toSp() }
        val verseEmDp = with(density) { versePx.toDp() }
        val duaEmDp = with(density) { duaPx.toDp() }
        val lineWidth = with(density) { (lineEm * duaPx).toDp() } + 2.dp

        Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.weight(0.8f))
            Image(
                painterResource(R.drawable.qs_emblem),
                contentDescription = null,
                modifier = Modifier
                    .size(d(100f))
                    .onGloballyPositioned { dialBounds = it.boundsInRoot() }
                    .graphicsLayer {
                        val grow = 0.86f + 0.14f * logo.value
                        val pass = 1f + 1.4f * portal.value
                        scaleX = grow * pass
                        scaleY = grow * pass
                        rotationZ = 200f * leaving.value
                        alpha = logo.value * (1f - portal.value).coerceIn(0f, 1f)
                    },
            )
            Gap(d(12f))
            Image(
                painterResource(R.drawable.qs_wordmark),
                contentDescription = "QsCrypt",
                modifier = Modifier.height(d(28f)).alpha(logo.value * out),
            )
            Gap(d(8f))
            Text(
                TAGLINE,
                style = TextStyle(fontFamily = HacenXL, fontSize = (15f * kv).sp, color = TAG_COLOR),
                softWrap = false,
                maxLines = 1,
                modifier = Modifier.alpha(logo.value * out),
            )
            Spacer(Modifier.weight(0.6f))

            Ornament(Modifier.alpha(verse.value * out))
            Gap(d(14f))
            // The verse: bracket, verse, bracket, on one line.
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                Row(
                    Modifier.height(verseEmDp * 1.9f).graphicsLayer {
                        alpha = verse.value * out
                        val s = 1f - 0.03f * leaving.value
                        scaleX = s
                        scaleY = s
                    },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val bh = verseEmDp * BRACKET_H
                    // The first child sits on the right: the bracket opening towards the verse.
                    Image(painterResource(R.drawable.qs_bracket), null, Modifier.size(bh / 3f, bh).graphicsLayer(scaleX = -1f))
                    Spacer(Modifier.width(verseEmDp * BRACKET_GAP))
                    Text(VERSE, style = TextStyle(fontFamily = HacenXL, fontSize = verseSize, color = Qs.ivory), softWrap = false, maxLines = 1)
                    Spacer(Modifier.width(verseEmDp * BRACKET_GAP))
                    Image(painterResource(R.drawable.qs_bracket), null, Modifier.size(bh / 3f, bh))
                }
            }
            Gap(d(18f))
            // The supplication, framed: three lines of one width, clause by clause.
            val style = TextStyle(fontFamily = HacenXL, fontSize = duaSize, color = DUA_COLOR)
            val lineHeight = duaEmDp * LINE_H
            fun shown(i: Int) = ((dua.value * DUA.size) - i).coerceIn(0f, 1f)
            val clauses = remember { DUA.map { clause(it) } }
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                Box(
                    Modifier
                        .graphicsLayer {
                            alpha = dua.value.coerceIn(0f, 1f).let { if (it > 0f) 1f else 0f } * out
                            val s = 1f - 0.03f * leaving.value
                            scaleX = s
                            scaleY = s
                        }
                        .drawBehind { panel() },
                ) {
                    Column(Modifier.padding(horizontal = PANEL_INSET.dp, vertical = (PANEL_INSET * 0.6f).dp).width(lineWidth)) {
                        for ((a, b) in listOf(0 to 1, 2 to 3)) {
                            Row(Modifier.fillMaxWidth().height(lineHeight), verticalAlignment = Alignment.CenterVertically) {
                                Text(clauses[a], style = style, softWrap = false, maxLines = 1, modifier = Modifier.alpha(shown(a)))
                                Spacer(Modifier.weight(1f))
                                Star(15.dp, Modifier.alpha(shown(b)))
                                Spacer(Modifier.weight(1f))
                                Text(clauses[b], style = style, softWrap = false, maxLines = 1, modifier = Modifier.alpha(shown(b)))
                            }
                        }
                        Row(Modifier.fillMaxWidth().height(lineHeight).alpha(shown(4)), verticalAlignment = Alignment.CenterVertically) {
                            Dot(3.dp)
                            Wing(fadeRight = true)
                            Star(12.dp)
                            Spacer(Modifier.width(duaEmDp * 0.5f))
                            Text(clauses[4], style = style, softWrap = false, maxLines = 1)
                            Spacer(Modifier.width(duaEmDp * 0.5f))
                            Star(12.dp)
                            Wing(fadeRight = false)
                            Dot(3.dp)
                        }
                    }
                    Medallion(Modifier.align(Alignment.TopCenter).offset(y = (-11).dp).alpha(shown(0)))
                    Medallion(Modifier.align(Alignment.BottomCenter).offset(y = 11.dp).alpha(shown(4)))
                }
            }
            Spacer(Modifier.weight(0.8f))

            // The edition, then the developer's signature and the year.
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Row(Modifier.alpha(footer.value * out), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.width(d(34f)).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
                    Spacer(Modifier.width(d(12f)))
                    Text(RELEASE_NAME, style = TextStyle(fontFamily = HacenXL, fontSize = (16f * kv).sp, color = Qs.ivory))
                    Spacer(Modifier.width(d(12f)))
                    Box(Modifier.width(d(34f)).height(1.dp).background(Qs.brass.copy(alpha = 0.6f)))
                }
                Gap(d(8f))
                Row(Modifier.alpha(footer.value * out), verticalAlignment = Alignment.Bottom) {
                    Image(
                        painterResource(R.drawable.qs_signature),
                        contentDescription = DEVELOPER,
                        modifier = Modifier.size(d(18f) * SIGNATURE_ASPECT, d(18f)),
                    )
                    Spacer(Modifier.width(d(8f)))
                    Text(
                        "© $RELEASE_YEAR",
                        style = TextStyle(fontFamily = PlexMono, fontSize = (12f * kv).sp, color = Qs.muted, letterSpacing = 1.sp),
                    )
                }
            }
            Gap(d(14f))
            Box(Modifier.fillMaxWidth(0.42f).height(2.dp).alpha(out).clip(RoundedCornerShape(1.dp)).background(Qs.line)) {
                Box(Modifier.fillMaxWidth(progress.value).height(2.dp).background(Qs.brass))
            }
            Gap(d(10f))
            Text(
                "اضغط في أي مكان للمتابعة",
                style = TextStyle(fontFamily = HacenPrint, fontSize = (12f * kv).sp, color = Qs.muted.copy(alpha = 0.8f)),
                modifier = Modifier.alpha(hint.value * out),
            )
            Gap(d(16f))
        }
    }
}

/** A clause with its opening word in brass. */
private fun clause(text: String) = buildAnnotatedString {
    if (text.startsWith(ALLAHUMMA)) {
        withStyle(SpanStyle(color = Qs.brass)) { append(ALLAHUMMA) }
        append(text.substring(ALLAHUMMA.length))
    } else {
        append(text)
    }
}

/** The frame behind the supplication: a soft panel with a double brass line. */
private fun androidx.compose.ui.graphics.drawscope.DrawScope.panel() {
    val r = 18.dp.toPx()
    val inner = 4.dp.toPx()
    val line = 1.dp.toPx()
    drawRoundRect(Qs.surface.copy(alpha = 0.47f), cornerRadius = CornerRadius(r))
    drawRoundRect(Qs.brass.copy(alpha = 0.43f), cornerRadius = CornerRadius(r), style = Stroke(width = line))
    drawRoundRect(
        Qs.brass.copy(alpha = 0.22f),
        topLeft = Offset(inner, inner),
        size = Size(size.width - 2 * inner, size.height - 2 * inner),
        cornerRadius = CornerRadius(r - inner),
        style = Stroke(width = line),
    )
}

/** An eight-pointed star (two squares) with an open centre. */
private fun starPath(cx: Float, cy: Float, size: Float): Path = Path().apply {
    val outer = size / 2
    val inner = outer * (cos(PI / 4) / cos(PI / 8)).toFloat()
    for (k in 0 until 16) {
        val rad = if (k % 2 == 0) outer else inner
        val a = k * PI / 8 - PI / 2
        val x = cx + rad * cos(a).toFloat()
        val y = cy + rad * sin(a).toFloat()
        if (k == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
    addOval(Rect(Offset(cx, cy), size * 0.17f))
    fillType = PathFillType.EvenOdd
}

@Composable
private fun Star(size: Dp, modifier: Modifier = Modifier) = Canvas(modifier.size(size)) {
    drawPath(starPath(this.size.width / 2, this.size.height / 2, this.size.minDimension), Qs.brass)
}

@Composable
private fun Dot(size: Dp) = Box(Modifier.size(size).clip(CircleShape).background(Qs.brass))

/** A star on a round plate, sitting on the frame's line. */
@Composable
private fun Medallion(modifier: Modifier) = Box(modifier.size(22.dp).clip(CircleShape).background(MEDALLION), contentAlignment = Alignment.Center) {
    Star(15.dp)
}

/** A thin brass rule beside the last line, fading out towards the frame's edge. */
@Composable
private fun RowScope.Wing(fadeRight: Boolean) = Canvas(Modifier.weight(1f).height(1.dp).padding(horizontal = 4.dp)) {
    val colors = if (fadeRight) listOf(Qs.brass, Color.Transparent) else listOf(Color.Transparent, Qs.brass)
    drawRect(Brush.horizontalGradient(colors))
}

/** Rules, dots and a star: the ornament above the verse. */
@Composable
private fun Ornament(modifier: Modifier = Modifier) = CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.width(60.dp).height(1.dp).background(Brush.horizontalGradient(listOf(Color.Transparent, Qs.brass))))
        Spacer(Modifier.width(3.5.dp))
        Dot(3.dp)
        Spacer(Modifier.width(5.5.dp))
        Star(14.dp)
        Spacer(Modifier.width(5.5.dp))
        Dot(3.dp)
        Spacer(Modifier.width(3.5.dp))
        Box(Modifier.width(60.dp).height(1.dp).background(Brush.horizontalGradient(listOf(Qs.brass, Color.Transparent))))
    }
}

/** Gold dust for the portal: fixed at random once, animated by the portal's progress. */
private class Dust(val angle: Float, val speed: Float, val size: Float, val phase: Float, val jitter: Float) {
    companion object {
        fun make(n: Int): List<Dust> {
            val rnd = java.util.Random(7)
            return List(n) { i ->
                Dust(
                    angle = (i + rnd.nextFloat() * 0.8f) / n * (2 * PI).toFloat(),
                    speed = 0.06f + rnd.nextFloat() * 0.32f,
                    size = 0.9f + rnd.nextFloat() * 2.1f,
                    phase = rnd.nextFloat() * 6.28f,
                    jitter = (rnd.nextFloat() - 0.5f) * 18f,
                )
            }
        }
    }
}
