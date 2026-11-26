package com.qscrypt.app.ui

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qscrypt.app.AppState
import com.qscrypt.app.PhoneAuth
import com.qscrypt.app.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.math.MathContext

/**
 * Disguise mode: the launcher shows a calculator ("Calculator" / "الآلة
 * الحاسبة") instead of QsCrypt, through two activity-aliases of the same
 * activity. The calculator works; typing the PIN and "=" opens QsCrypt.
 */
object Disguise {
    private const val LAUNCHER = "com.qscrypt.app.Launcher"
    private const val CALCULATOR = "com.qscrypt.app.Calculator"

    fun apply(context: Context, on: Boolean): Boolean = runCatching {
        val pm = context.packageManager
        val calc = ComponentName(context, CALCULATOR)
        val main = ComponentName(context, LAUNCHER)
        // Enable the new entry before disabling the old one, so there is always a launcher icon.
        if (on) {
            pm.setComponentEnabledSetting(calc, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
            pm.setComponentEnabledSetting(main, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
        } else {
            pm.setComponentEnabledSetting(main, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT, PackageManager.DONT_KILL_APP)
            pm.setComponentEnabledSetting(calc, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT, PackageManager.DONT_KILL_APP)
        }
        Prefs.disguised = on
        true
    }.getOrDefault(false)
}

private val MC = MathContext.DECIMAL64

/** Evaluates "12.5×4−3÷2%" with the usual precedence; null if incomplete. */
internal fun calculate(s: String): String? {
    if (s.isBlank()) return null
    var i = 0
    fun peek(): Char = if (i < s.length) s[i] else '\u0000'
    fun number(): BigDecimal {
        var negative = false
        while (peek() == '−') {
            negative = !negative
            i++
        }
        val start = i
        while (peek().isDigit() || peek() == '.') i++
        if (start == i) throw IllegalArgumentException()
        var v = BigDecimal(s.substring(start, i))
        while (peek() == '%') {
            v = v.divide(BigDecimal(100), MC)
            i++
        }
        return if (negative) v.negate() else v
    }
    fun term(): BigDecimal {
        var v = number()
        while (peek() == '×' || peek() == '÷') {
            val op = s[i++]
            val r = number()
            v = if (op == '×') v.multiply(r, MC) else v.divide(r, MC)
        }
        return v
    }
    fun sum(): BigDecimal {
        var v = term()
        while (peek() == '+' || peek() == '−') {
            val op = s[i++]
            val r = term()
            v = if (op == '+') v.add(r, MC) else v.subtract(r, MC)
        }
        return v
    }
    return try {
        val v = sum()
        if (i != s.length) return null
        val z = v.stripTrailingZeros()
        val abs = z.abs()
        val text = if (z.signum() != 0 && (abs >= BigDecimal("1e15") || abs < BigDecimal("1e-9"))) z.round(MathContext(10)).toString() else z.toPlainString()
        text.replace('-', '−')
    } catch (e: ArithmeticException) {
        "خطأ"
    } catch (e: Exception) {
        null
    }
}

private val CalcBg = Color(0xFF111214)
private val KeyNum = Color(0xFF26282C)
private val KeyFn = Color(0xFF3A3D42)
private val KeyOp = Color(0xFFE39B32)

@Composable
fun CalculatorScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var expr by remember { mutableStateOf("") }
    var shown by remember { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val preview = if (shown == null) calculate(expr)?.takeIf { it != expr } else null

    fun opened() {
        Prefs.failCount = 0
        Prefs.lockUntil = 0
        expr = ""
        shown = null
        AppState.pinPassed = true
        if (PhoneAuth.mode(context) != PhoneAuth.Mode.TwoFactor) AppState.locked = false
    }

    fun press(k: String) {
        if (checking) return
        val base = shown?.takeIf { it != "خطأ" }
        when (k) {
            "C" -> {
                expr = ""
                shown = null
            }
            "⌫" -> {
                expr = (base ?: expr).dropLast(1)
                shown = null
            }
            "=" -> {
                val code = expr
                if (code.length == 6 && code.all { it.isDigit() } && Prefs.lockUntil <= System.currentTimeMillis()) {
                    checking = true
                    scope.launch {
                        val ok = withContext(Dispatchers.Default) { Prefs.checkPin(code) }
                        checking = false
                        if (ok) {
                            opened()
                        } else {
                            // Looks like an ordinary calculation; counts as a failed attempt.
                            val n = Prefs.failCount + 1
                            Prefs.failCount = n
                            if (n >= 5) Prefs.lockUntil = System.currentTimeMillis() + (30L shl (n - 5).coerceAtMost(7)).coerceAtMost(3600) * 1000
                            shown = code
                        }
                    }
                } else {
                    shown = calculate(expr) ?: if (expr.isEmpty()) null else "خطأ"
                }
            }
            "+", "−", "×", "÷" -> {
                val cur = base ?: expr
                shown = null
                expr = when {
                    cur.isEmpty() -> if (k == "−") "−" else ""
                    cur.last() in "+−×÷" -> if (k == "−" && cur.last() in "×÷") cur + k else cur.dropLast(1) + k
                    else -> cur + k
                }
            }
            "%" -> {
                val cur = base ?: expr
                shown = null
                if (cur.isNotEmpty() && (cur.last().isDigit() || cur.last() == '%')) expr = cur + "%"
            }
            "." -> {
                if (shown != null) {
                    expr = "0."
                    shown = null
                } else {
                    val tail = expr.takeLastWhile { it.isDigit() || it == '.' }
                    if ('.' !in tail) expr += if (tail.isEmpty()) "0." else "."
                }
            }
            else -> {
                if (shown != null) {
                    expr = ""
                    shown = null
                }
                if (expr.length < 40) expr += k
            }
        }
    }

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Column(Modifier.fillMaxSize().background(CalcBg).systemBarsPadding().padding(horizontal = 16.dp, vertical = 12.dp)) {
            Column(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 8.dp), verticalArrangement = Arrangement.Bottom, horizontalAlignment = Alignment.End) {
                val main = shown ?: expr.ifEmpty { "0" }
                Text(
                    main,
                    style = TextStyle(color = Color.White, fontSize = if (main.length > 12) 40.sp else 64.sp, fontWeight = FontWeight.Light, textAlign = TextAlign.End),
                    maxLines = 2,
                )
                Text(
                    if (shown != null) expr else preview ?: "",
                    style = TextStyle(color = Color(0xFF8A8F98), fontSize = 24.sp, textAlign = TextAlign.End),
                    maxLines = 1,
                )
            }
            val rows = listOf(
                listOf("C", "⌫", "%", "÷"),
                listOf("7", "8", "9", "×"),
                listOf("4", "5", "6", "−"),
                listOf("1", "2", "3", "+"),
                listOf("00", "0", ".", "="),
            )
            rows.forEach { row ->
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    row.forEach { k ->
                        val color = when (k) {
                            "C", "⌫", "%" -> KeyFn
                            "÷", "×", "−", "+", "=" -> KeyOp
                            else -> KeyNum
                        }
                        Box(
                            Modifier.weight(1f).aspectRatio(1f).clip(CircleShape).background(color).clickable {
                                if (k == "00") {
                                    press("0")
                                    press("0")
                                } else {
                                    press(k)
                                }
                            },
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(k, style = TextStyle(color = Color.White, fontSize = 28.sp, fontWeight = if (color == KeyOp) FontWeight.Normal else FontWeight.Light))
                        }
                    }
                }
            }
        }
    }
}
