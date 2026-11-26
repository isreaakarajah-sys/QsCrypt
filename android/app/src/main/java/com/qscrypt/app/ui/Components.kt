package com.qscrypt.app.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.R

@Composable
fun QsIcon(@DrawableRes id: Int, tint: Color = Qs.ivory, size: Dp = 22.dp, description: String? = null) {
    Icon(painter = painterResource(id), contentDescription = description, tint = tint, modifier = Modifier.size(size))
}

@Composable
fun IconBtn(@DrawableRes id: Int, description: String, tint: Color = Qs.ivory, border: Color? = null, enabled: Boolean = true, onClick: () -> Unit) {
    val ring = if (border != null) Modifier.border(1.5.dp, border, CircleShape) else Modifier
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(CircleShape)
            .then(ring)
            .clickable(enabled = enabled, onClick = onClick)
            .semantics { contentDescription = description }
            .alpha(if (enabled) 1f else 0.4f),
        contentAlignment = Alignment.Center,
    ) {
        QsIcon(id, tint)
    }
}

@Composable
fun Tile(@DrawableRes id: Int, color: Color, size: Dp = 44.dp, radius: Dp = 14.dp, iconSize: Dp = 22.dp, background: Color = Qs.surface2) {
    Box(
        modifier = Modifier.size(size).clip(RoundedCornerShape(radius)).background(background),
        contentAlignment = Alignment.Center,
    ) {
        QsIcon(id, color, iconSize)
    }
}

enum class TagKind { Neutral, Brass, Coral, Outline, Mint }

@Composable
fun Tag(text: String, kind: TagKind = TagKind.Neutral) {
    val shape = RoundedCornerShape(7.dp)
    val (bg, fg, border) = when (kind) {
        TagKind.Neutral -> Triple(Qs.surface2, Color(0xFFCFDAD3), null)
        TagKind.Brass -> Triple(Qs.brass, Qs.base, null)
        TagKind.Coral -> Triple(Color.Transparent, Qs.coral, Qs.coral)
        TagKind.Outline -> Triple(Color.Transparent, Qs.muted, Qs.line)
        TagKind.Mint -> Triple(Color.Transparent, Qs.mint, Qs.mint)
    }
    val style = if (kind == TagKind.Neutral) T.mono.copy(color = fg, fontSize = 11.sp) else T.label.copy(color = fg, fontSize = 12.sp, lineHeight = 14.sp)
    Box(
        modifier = Modifier
            .height(22.dp)
            .clip(shape)
            .background(bg)
            .then(if (border != null) Modifier.border(1.dp, border, shape) else Modifier)
            .padding(horizontal = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = style, maxLines = 1)
    }
}

@Composable
fun QsSwitch(checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    val track = if (checked) Qs.brass else Qs.line
    val knob = if (checked) Qs.base else Qs.muted
    Box(
        modifier = Modifier
            .width(48.dp)
            .height(28.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(track)
            .toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChange)
            .alpha(if (enabled) 1f else 0.45f)
            .padding(3.dp),
        contentAlignment = if (checked) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Box(Modifier.size(22.dp).clip(CircleShape).background(knob))
    }
}

@Composable
fun PrimaryButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), @DrawableRes icon: Int? = null, enabled: Boolean = true, onClick: () -> Unit) {
    Row(
        modifier = modifier
            .height(56.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(if (enabled) Qs.brass else Qs.surface2)
            .clickable(enabled = enabled, onClick = onClick),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val fg = if (enabled) Qs.base else Qs.muted
        if (icon != null) {
            QsIcon(icon, fg, 20.dp)
            Spacer(Modifier.width(10.dp))
        }
        Text(text, style = T.button.copy(color = fg))
    }
}

/**
 * Text drawn from outlines in the app's own fonts (see android/tools/text_art.py),
 * for the screens shown before activation unlocks the fonts.
 */
@Composable
fun Art(@DrawableRes id: Int, description: String?, color: Color, modifier: Modifier = Modifier) =
    Image(painterResource(id), contentDescription = description, colorFilter = ColorFilter.tint(color), modifier = modifier)

/** [PrimaryButton] whose label is drawn with [Art]. */
@Composable
fun PrimaryArtButton(@DrawableRes art: Int, description: String, modifier: Modifier = Modifier.fillMaxWidth(), @DrawableRes icon: Int? = null, enabled: Boolean = true, onClick: () -> Unit) {
    Row(
        modifier = modifier
            .height(56.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(if (enabled) Qs.brass else Qs.surface2)
            .clickable(enabled = enabled, onClickLabel = description, onClick = onClick),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val fg = if (enabled) Qs.base else Qs.muted
        if (icon != null) {
            QsIcon(icon, fg, 20.dp)
            Spacer(Modifier.width(10.dp))
        }
        Art(art, description, fg)
    }
}

/** [Note] whose text is drawn with [Art]. */
@Composable
fun ArtNote(@DrawableRes art: Int, description: String, @DrawableRes icon: Int = R.drawable.ic_shield, color: Color = Qs.brass) {
    val shape = RoundedCornerShape(16.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).border(1.dp, Qs.line, shape).padding(horizontal = 14.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(Modifier.padding(top = 4.dp)) { QsIcon(icon, color, 18.dp) }
        Box(Modifier.weight(1f)) { Art(art, description, Qs.muted) }
    }
}

@Composable
fun SecondaryButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), @DrawableRes icon: Int? = null, enabled: Boolean = true, color: Color = Qs.ivory, onClick: () -> Unit) {
    val shape = RoundedCornerShape(18.dp)
    Row(
        modifier = modifier
            .height(56.dp)
            .clip(shape)
            .border(1.dp, Qs.line, shape)
            .clickable(enabled = enabled, onClick = onClick)
            .alpha(if (enabled) 1f else 0.4f),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            QsIcon(icon, color, 20.dp)
            Spacer(Modifier.width(10.dp))
        }
        Text(text, style = T.button.copy(color = color, fontSize = 16.sp))
    }
}

@Composable
fun TopBar(title: String, onBack: (() -> Unit)?, trailing: @Composable RowScope.() -> Unit = {}) {
    Row(Modifier.fillMaxWidth().height(48.dp), verticalAlignment = Alignment.CenterVertically) {
        if (onBack != null) IconBtn(R.drawable.ic_back, "رجوع", onClick = onBack)
        Spacer(Modifier.width(6.dp))
        Text(title, style = T.title, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
        trailing()
    }
}

@Composable
fun StepBar(step: Int, of: Int) {
    Box(Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)).background(Qs.surface2)) {
        Box(Modifier.fillMaxWidth(step.toFloat() / of).height(4.dp).clip(RoundedCornerShape(2.dp)).background(Qs.brass))
    }
}

@Composable
fun UsageBar(fraction: Float) {
    Box(Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)).background(Qs.surface2)) {
        Box(Modifier.fillMaxWidth(fraction.coerceIn(0f, 1f)).height(6.dp).clip(RoundedCornerShape(3.dp)).background(Qs.brass))
    }
}

@Composable
fun SectionLabel(text: String, count: String? = null, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().height(20.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(text, style = T.label, modifier = Modifier.weight(1f))
        if (count != null) Text(count, style = T.mono.copy(fontSize = 12.sp))
    }
}

@Composable
fun Note(text: String, @DrawableRes icon: Int = R.drawable.ic_shield, color: Color = Qs.brass, background: Color = Color.Transparent, border: Color = Qs.line) {
    val shape = RoundedCornerShape(16.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).background(background).border(1.dp, border, shape).padding(horizontal = 14.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(Modifier.padding(top = 2.dp)) { QsIcon(icon, color, 18.dp) }
        Text(text, style = T.body.copy(fontSize = 13.sp, lineHeight = 21.sp, color = Qs.muted), modifier = Modifier.weight(1f))
    }
}

@Composable
fun QsCard(modifier: Modifier = Modifier, glow: Boolean = false, onClick: (() -> Unit)? = null, content: @Composable () -> Unit) {
    val shape = RoundedCornerShape(22.dp)
    Box(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(Qs.surface)
            .then(if (glow) Modifier.border(1.dp, Qs.brassGlow, shape) else Modifier)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(16.dp),
    ) { content() }
}

@Composable
fun QsField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
    password: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
    highlighted: Boolean = false,
    height: Dp = 56.dp,
    textStyle: TextStyle = T.body.copy(fontSize = 16.sp),
    leading: @Composable (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
    placeholderContent: @Composable (() -> Unit)? = null,
) {
    val shape = RoundedCornerShape(16.dp)
    var shown by remember { mutableStateOf(false) }
    val transform = if (password && !shown) PasswordVisualTransformation() else VisualTransformation.None
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        singleLine = true,
        textStyle = if (password) textStyle.copy(fontFamily = PlexMono, fontSize = 17.sp, color = Qs.ivory) else textStyle.copy(color = Qs.ivory),
        cursorBrush = SolidColor(Qs.brass),
        visualTransformation = transform,
        keyboardOptions = KeyboardOptions(keyboardType = if (password) KeyboardType.Password else keyboardType),
        modifier = modifier.fillMaxWidth(),
        decorationBox = { inner ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = height)
                    .clip(shape)
                    .background(Qs.surface)
                    .border(if (highlighted) 1.5.dp else 1.dp, if (highlighted) Qs.brass else Qs.line, shape)
                    .padding(start = 16.dp, end = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (leading != null) {
                    leading()
                    Spacer(Modifier.width(10.dp))
                }
                Box(Modifier.weight(1f)) {
                    if (value.isEmpty()) {
                        if (placeholderContent != null) placeholderContent() else Text(placeholder, style = T.body.copy(color = Qs.muted, fontSize = 15.sp))
                    }
                    inner()
                }
                if (password) {
                    IconBtn(R.drawable.ic_eye, if (shown) "إخفاء كلمة المرور" else "إظهار كلمة المرور", tint = if (shown) Qs.brass else Qs.muted) { shown = !shown }
                } else if (trailing != null) {
                    trailing()
                }
            }
        },
    )
}

/** Small selectable pill used for options. */
/** A small outlined action: pause, resume, cancel, paste… */
@Composable
fun Pill(text: String, color: Color, enabled: Boolean = true, @DrawableRes icon: Int? = null, onClick: () -> Unit) {
    val shape = RoundedCornerShape(17.dp)
    Row(
        Modifier
            .height(34.dp)
            .clip(shape)
            .border(1.dp, color.copy(alpha = 0.7f), shape)
            .clickable(enabled = enabled, onClick = onClick)
            .alpha(if (enabled) 1f else 0.4f)
            .padding(horizontal = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            QsIcon(icon, color, 16.dp)
            Spacer(Modifier.width(6.dp))
        }
        Text(text, style = T.label.copy(color = color), maxLines = 1)
    }
}

@Composable
fun Chip(text: String, selected: Boolean, enabled: Boolean = true, onClick: () -> Unit) {
    val shape = RoundedCornerShape(18.dp)
    Box(
        Modifier
            .height(36.dp)
            .clip(shape)
            .background(if (selected) Qs.brass else Color.Transparent)
            .then(if (selected) Modifier else Modifier.border(1.dp, Qs.line, shape))
            .clickable(enabled = enabled, onClick = onClick)
            .alpha(if (enabled) 1f else 0.4f)
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = T.label.copy(color = if (selected) Qs.base else Qs.ivory), maxLines = 1)
    }
}

@Composable
fun OptionRow(@DrawableRes icon: Int, title: String, subtitle: String, trailing: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        QsIcon(icon, Qs.muted, 20.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = T.item)
            Text(subtitle, style = T.small)
        }
        Spacer(Modifier.width(8.dp))
        trailing()
    }
}

@Composable
fun QsAlert(title: String, text: String, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit, dismiss: String? = "إلغاء", danger: Boolean = false) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Qs.surface,
        title = { Text(title, style = T.title) },
        text = { Text(text, style = T.body.copy(color = Qs.muted)) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(confirm, style = T.button.copy(color = if (danger) Qs.coral else Qs.brass, fontSize = 15.sp)) }
        },
        dismissButton = {
            if (dismiss != null) TextButton(onClick = onDismiss) { Text(dismiss, style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) }
        },
    )
}

@Composable
fun InputDialog(title: String, initial: String, confirm: String, placeholder: String = "", onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Qs.surface,
        title = { Text(title, style = T.title) },
        text = { QsField(value = value, onValueChange = { value = it }, placeholder = placeholder, highlighted = true) },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.trim()) }, enabled = value.isNotBlank()) {
                Text(confirm, style = T.button.copy(color = Qs.brass, fontSize = 15.sp))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("إلغاء", style = T.button.copy(color = Qs.muted, fontSize = 15.sp)) } },
    )
}

/** Determinate (fraction 0..1) or indeterminate (null) progress. */
@Composable
fun ProgressDialog(title: String, fraction: Float?, detail: String = "", onCancel: (() -> Unit)? = null) {
    AlertDialog(
        onDismissRequest = {},
        containerColor = Qs.surface,
        title = { Text(title, style = T.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (fraction == null) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Qs.brass, trackColor = Qs.surface2)
                } else {
                    LinearProgressIndicator(progress = { fraction.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth(), color = Qs.brass, trackColor = Qs.surface2)
                    Text("${(fraction * 100).toInt()}%", style = T.monoLarge, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
                }
                if (detail.isNotEmpty()) Text(detail, style = T.small, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        },
        confirmButton = {
            if (onCancel != null) TextButton(onClick = onCancel) { Text("إلغاء", style = T.button.copy(color = Qs.coral, fontSize = 15.sp)) }
        },
    )
}

@Composable
fun ComingSoonTag() = Tag("قريباً", TagKind.Outline)

@Composable
fun Gap(h: Dp) = Spacer(Modifier.height(h))

/**
 * On wide screens (tablets, foldables, a phone on its side) a screen keeps a
 * comfortable reading width in the middle instead of stretching edge to edge.
 */
@Composable
fun Centered(maxWidth: Dp = 680.dp, content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Box(Modifier.fillMaxHeight().widthIn(max = maxWidth).fillMaxWidth()) { content() }
    }
}
