package com.qscrypt.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.qscrypt.app.Fonts
import com.qscrypt.app.R

/** The approved QsCrypt palette: emerald, ivory, brass. */
object Qs {
    val base = Color(0xFF0A2A20)
    val surface = Color(0xFF0F3D2E)
    val surface2 = Color(0xFF134836)
    val line = Color(0xFF1F5543)
    val ivory = Color(0xFFF4EFE3)
    val muted = Color(0xFFA9BBB0)
    val brass = Color(0xFFC9A24A)
    val mint = Color(0xFF7FD1A6)
    val coral = Color(0xFFF08A6E)
    val warm = Color(0xFF2E2A1F)
    val brassGlow = Color(0x73C9A24A)
}

// The Hacen fonts are licensed, so they ship encrypted and are unlocked by
// the activation password (see Activation.kt). Until then the system font is used.
val HacenXXL: FontFamily get() = Fonts.xxl
val HacenXL: FontFamily get() = Fonts.xl
val HacenPrint: FontFamily get() = Fonts.print
val PlexMono = FontFamily(Font(R.font.ibm_plex_mono_regular), Font(R.font.ibm_plex_mono_medium, FontWeight.Medium))

/** Text styles from the design kit (getters: the fonts can change at activation). */
object T {
    val display get() = TextStyle(fontFamily = HacenXXL, fontSize = 28.sp, lineHeight = 38.sp, color = Qs.ivory)
    val h1 get() = TextStyle(fontFamily = HacenXXL, fontSize = 24.sp, lineHeight = 32.sp, color = Qs.ivory)
    val title get() = TextStyle(fontFamily = HacenXL, fontSize = 19.sp, lineHeight = 26.sp, color = Qs.ivory)
    val itemLarge get() = TextStyle(fontFamily = HacenXL, fontSize = 17.sp, lineHeight = 22.sp, color = Qs.ivory)
    val item get() = TextStyle(fontFamily = HacenXL, fontSize = 15.sp, lineHeight = 20.sp, color = Qs.ivory)
    val label get() = TextStyle(fontFamily = HacenXL, fontSize = 14.sp, lineHeight = 20.sp, color = Qs.muted)
    val button get() = TextStyle(fontFamily = HacenXL, fontSize = 17.sp, lineHeight = 22.sp)
    val body get() = TextStyle(fontFamily = HacenPrint, fontSize = 14.sp, lineHeight = 23.sp, color = Qs.ivory)
    val small get() = TextStyle(fontFamily = HacenPrint, fontSize = 12.5.sp, lineHeight = 18.sp, color = Qs.muted)
    val mono get() = TextStyle(fontFamily = PlexMono, fontSize = 11.sp, lineHeight = 14.sp, color = Qs.muted)
    val monoLarge get() = TextStyle(fontFamily = PlexMono, fontSize = 13.sp, lineHeight = 18.sp, color = Qs.ivory)
}

@Composable
fun QsTheme(content: @Composable () -> Unit) {
    val scheme = darkColorScheme(
        primary = Qs.brass,
        onPrimary = Qs.base,
        secondary = Qs.mint,
        onSecondary = Qs.base,
        background = Qs.base,
        onBackground = Qs.ivory,
        surface = Qs.surface,
        onSurface = Qs.ivory,
        surfaceVariant = Qs.surface2,
        onSurfaceVariant = Qs.muted,
        surfaceContainer = Qs.surface,
        surfaceContainerHigh = Qs.surface,
        surfaceContainerHighest = Qs.surface2,
        outline = Qs.line,
        outlineVariant = Qs.line,
        error = Qs.coral,
        onError = Qs.base,
    )
    val typography = Typography(
        bodyLarge = T.body,
        bodyMedium = T.body,
        bodySmall = T.small,
        titleLarge = T.title,
        titleMedium = T.item,
        labelLarge = T.button,
        headlineSmall = T.title,
    )
    MaterialTheme(colorScheme = scheme, typography = typography, content = content)
}
