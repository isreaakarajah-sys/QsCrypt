#!/usr/bin/env python3
"""Draws the opening screen (SplashScreen.kt) as a phone screenshot, for review.

It follows the same layout rules as the Kotlin code: the verse and the
supplication are measured in the real Hacen font and sized to the screen's
width. The licensed fonts are not in the repository; point the script at
your local copies:

    splash_preview.py out.png --fonts DIR [--width 384 --height 832 --density 2.8125]

DIR must hold hacen_xl.ttf, hacen_print.ttf and IBMPlexMono-Regular.ttf.
Needs Pillow with libraqm, and rsvg-convert for the vector drawables.
"""
import argparse
import io
import math
import os
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

RES = os.path.join(os.path.dirname(__file__), '..', 'app', 'src', 'main', 'res', 'drawable')
RAQM = ImageFont.Layout.RAQM
BASE = (10, 42, 32); IVORY = (244, 239, 227); MUTED = (169, 187, 176); BRASS = (201, 162, 74)
DUA_COLOR = (232, 221, 191); LINE = (31, 85, 67); TAG_COLOR = (214, 200, 160)
VERSE = "فَاللَّهُ خَيْرٌ حَافِظًا وَهُوَ أَرْحَمُ الرَّاحِمِينَ"
TAGLINE = "صَوْنُ الأماناتِ وتحصينُ الأسرار"
ALLAHUMMA = "اللَّهُمَّ"
DUA = ["اللَّهُمَّ اكْسِرْ بِنَا شَوْكَتَهُمْ", "اللَّهُمَّ نَكِّسْ بِنَا رَايَتَهُمْ", "اللَّهُمَّ أَذِلَّ بِنَا قَادَتَهُمْ",
       "اللَّهُمَّ حَطِّمْ بِنَا هَيْبَتَهُمْ", "اللَّهُمَّ أَنْفِذْ بِنَا قَدَرَكَ فِيهِمْ"]
# Same numbers as SplashScreen.kt.
SIDE, VERSE_SIDE = 16, 6                  # dp
BRACKET_H, BRACKET_GAP = 1.15, 0.14       # verse ems
SEP, WING = 1.5, 2.6                      # dua ems
VERSE_MAX, DUA_MAX = 46, 30               # sp
LINE_H = 2.15                             # dua line height, in ems


def drawable(name, height_px):
    xml = open(os.path.join(RES, name + '.xml'), encoding='utf-8').read()
    vw = float(re.search(r'viewportWidth="([\d.]+)"', xml).group(1))
    vh = float(re.search(r'viewportHeight="([\d.]+)"', xml).group(1))
    tx = re.search(r'translateX="([-\d.]+)"', xml)
    ty = re.search(r'translateY="([-\d.]+)"', xml)
    paths = ''.join(f'<path fill="#{c[-6:]}" d="{d}"/>'
                    for c, d in re.findall(r'fillColor="#([0-9A-Fa-f]+)"\s+android:pathData="([^"]+)"', xml))
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vw} {vh}">'
           f'<g transform="translate({tx.group(1) if tx else 0} {ty.group(1) if ty else 0})">{paths}</g></svg>')
    png = subprocess.run(['rsvg-convert', '-h', str(max(1, round(height_px)))], input=svg.encode(),
                         capture_output=True, check=True).stdout
    return Image.open(io.BytesIO(png)).convert('RGBA')


def render(out, fonts, W=384.0, H=832.0, den=2.8125, status=28.0, nav=48.0, seconds=8.0, frame='cartouche'):
    xl = os.path.join(fonts, 'hacen_xl.ttf')
    pr = os.path.join(fonts, 'hacen_print.ttf')
    mono = os.path.join(fonts, 'IBMPlexMono-Regular.ttf')
    SS = 2                                    # supersampling for smooth ornaments
    WP, HP = round(W * den), round(H * den)
    den *= SS
    WPX, HPX = WP * SS, HP * SS
    img = Image.new('RGB', (WPX, HPX), BASE)
    top = status * den
    ch = H - status - nav                     # the screen's content height, dp
    dp = lambda v: v * den
    kv = min(1.0, ch / 800)

    grad = Image.new('RGBA', (1, 3)); grad.putdata([(12, 51, 38, 255), BASE + (255,), (7, 31, 24, 255)])
    g2 = grad.resize((WPX, HPX), Image.BILINEAR)
    img.paste(g2, (0, 0), g2)
    d = ImageDraw.Draw(img, 'RGBA')

    def em(path, s):
        f = ImageFont.truetype(path, 400, layout_engine=RAQM)
        return f.getlength(s, direction='rtl', language='ar') / 400

    def line_h(path, size):                   # a single line's box height, dp
        a, b = ImageFont.truetype(path, 400, layout_engine=RAQM).getmetrics()
        return (a + b) / 400 * size

    verse_em = em(xl, VERSE) + 2 * (BRACKET_H / 3 + BRACKET_GAP)
    clause = [em(xl, c) for c in DUA]
    line_em = max(clause[0] + clause[1] + SEP, clause[2] + clause[3] + SEP, clause[4] + 2 * WING)
    inset = 12 if frame == 'cartouche' else 0
    side = 8 if frame == 'cartouche' else SIDE
    vs = min((W - 2 * VERSE_SIDE) / verse_em * 0.99, VERSE_MAX, 42 * kv)
    ds = min((W - 2 * side - 2 * inset) / line_em * 0.99, DUA_MAX, 26 * kv)
    lw = line_em * ds + 2
    verse_h, dua_lh = vs * 1.9, ds * LINE_H
    tag = 15 * kv

    fixed = (100 * kv + 12 * kv + 28 * kv + 8 * kv + line_h(xl, tag) + 14 + 14 * kv + verse_h + 18 * kv
             + 3 * dua_lh + 2 * (inset * 0.6) + (0 if frame == 'cartouche' else 12 * kv + 14) + line_h(xl, 16 * kv) + 8 * kv + 18 * kv
             + 14 * kv + 2 + 10 * kv + line_h(pr, 12 * kv) + 16 * kv)
    free = max(0.0, ch - fixed)
    weights = (0.8, 0.6, 0.8)
    y = top + dp(free * weights[0] / sum(weights))
    halo = Image.new('L', (WPX, HPX), 0); hd = ImageDraw.Draw(halo)
    cx, cy, rad = WPX / 2, y + dp(50 * kv), WPX * 0.62
    for i in range(80, 0, -1):
        r = rad * i / 80
        hd.ellipse([cx - r, cy - r, cx + r, cy + r], fill=round(255 * 0.16 * (1 - i / 80)))
    img.paste(Image.new('RGB', halo.size, BRASS), (0, 0), halo)

    def centered(im, y_px):
        img.paste(im, (round(WPX / 2 - im.width / 2), round(y_px)), im)

    def font(path, size):
        return ImageFont.truetype(path, round(dp(size)), layout_engine=RAQM)

    def text_box(path, size, s, x_left, y_top, color, rtl=True):
        f = font(path, size)
        kw = dict(direction='rtl', language='ar') if rtl else {}
        d.text((x_left, y_top), s, font=f, fill=color, **kw)
        return f.getlength(s, **kw)

    def width(path, size, s, rtl=True):
        return font(path, size).getlength(s, **(dict(direction='rtl', language='ar') if rtl else {}))

    def clause_text(size, s, x_left, y_top):
        """A clause with its opening word in brass (the word is on the right)."""
        f = font(xl, size)
        kw = dict(direction='rtl', language='ar')
        w_all = f.getlength(s, **kw)
        w_word = f.getlength(ALLAHUMMA, **kw)
        d.text((x_left, y_top), s, font=f, fill=DUA_COLOR, **kw)
        glyphs = Image.new('L', img.size, 0)
        ImageDraw.Draw(glyphs).text((x_left, y_top), s, font=f, fill=255, **kw)
        keep = Image.new('L', img.size, 0)
        ImageDraw.Draw(keep).rectangle([x_left + w_all - w_word - dp(1), 0, x_left + w_all + dp(2), img.size[1]], fill=255)
        from PIL import ImageChops
        img.paste(Image.new('RGB', img.size, BRASS), (0, 0), ImageChops.multiply(glyphs, keep))
        return w_all

    def star(cx, cy, size, color=BRASS, hole=BASE):
        """Eight-pointed star (two squares), with an open centre."""
        R = size / 2
        r = R * math.cos(math.pi / 4) / math.cos(math.pi / 8)
        pts = [(cx + (R if k % 2 == 0 else r) * math.cos(k * math.pi / 8 - math.pi / 2),
                cy + (R if k % 2 == 0 else r) * math.sin(k * math.pi / 8 - math.pi / 2)) for k in range(16)]
        d.polygon(pts, fill=color)
        h = size * 0.17
        d.ellipse([cx - h, cy - h, cx + h, cy + h], fill=hole)

    def dot(cx, cy, s):
        d.ellipse([cx - s / 2, cy - s / 2, cx + s / 2, cy + s / 2], fill=BRASS)

    def rule(x0, x1, cy, transparent_left, alpha=1.0):
        n = max(1, round(x1 - x0))
        for i in range(n):
            a = (i / n if transparent_left else 1 - i / n) * alpha
            d.line([(x0 + i, cy), (x0 + i + 1, cy)], fill=BRASS + (round(255 * a),), width=max(1, round(den)))

    def ornament(cy):
        cx = WPX / 2
        star(cx, cy, dp(14))
        dot(cx - dp(14), cy, dp(3)); dot(cx + dp(14), cy, dp(3))
        rule(cx - dp(19 + 60), cx - dp(19), cy, True)
        rule(cx + dp(19), cx + dp(19 + 60), cy, False)

    centered(drawable('qs_emblem', dp(100 * kv)), y); y += dp(100 * kv + 12 * kv)
    centered(drawable('qs_wordmark', dp(28 * kv)), y); y += dp(28 * kv + 8 * kv)
    tw = width(xl, tag, TAGLINE)
    text_box(xl, tag, TAGLINE, WPX / 2 - tw / 2, y, TAG_COLOR); y += dp(line_h(xl, tag))
    y += dp(free * weights[1] / sum(weights))

    ornament(y + dp(7)); y += dp(14 + 14 * kv)
    # Verse row.
    vw = width(xl, vs, VERSE)
    bh, gap = dp(vs * BRACKET_H), dp(vs * BRACKET_GAP)
    br = drawable('qs_bracket', bh)
    total = vw + 2 * (br.width + gap)
    x0, cy = WPX / 2 - total / 2, y + dp(verse_h) / 2
    img.paste(br, (round(x0), round(cy - bh / 2)), br)
    text_box(xl, vs, VERSE, x0 + br.width + gap, cy - dp(line_h(xl, vs)) / 2, IVORY)
    bf = br.transpose(Image.FLIP_LEFT_RIGHT)
    img.paste(bf, (round(x0 + br.width + 2 * gap + vw), round(cy - bh / 2)), bf)
    y += dp(verse_h + 18 * kv)

    # Supplication.
    lx0, lx1 = WPX / 2 - dp(lw) / 2, WPX / 2 + dp(lw) / 2
    if frame == 'cartouche':
        fx0, fx1, fy0, fy1 = lx0 - dp(inset), lx1 + dp(inset), y, y + dp(3 * dua_lh + 2 * inset * 0.6)
        d.rounded_rectangle([fx0, fy0, fx1, fy1], radius=dp(18), fill=(15, 61, 46, 120), outline=BRASS + (110,), width=round(den))
        d.rounded_rectangle([fx0 + dp(4), fy0 + dp(4), fx1 - dp(4), fy1 - dp(4)], radius=dp(14), outline=BRASS + (55,), width=round(den))
        for my in (fy0, fy1):
            d.ellipse([WPX / 2 - dp(11), my - dp(11), WPX / 2 + dp(11), my + dp(11)], fill=(13, 50, 38))
            star(WPX / 2, my, dp(15), hole=(13, 50, 38))
        y += dp(inset * 0.6)
    box = dp(line_h(xl, ds))
    for row, (a, b) in enumerate([(0, 1), (2, 3)]):
        cy = y + dp(dua_lh) * (row + 0.5)
        wa, wb = width(xl, ds, DUA[a]), width(xl, ds, DUA[b])
        clause_text(ds, DUA[a], lx1 - wa, cy - box / 2)
        clause_text(ds, DUA[b], lx0, cy - box / 2)
        star((lx1 - wa + lx0 + wb) / 2, cy, dp(15), hole=(13, 50, 38) if frame == 'cartouche' else BASE)
    cy = y + dp(dua_lh) * 2.5
    w5 = width(xl, ds, DUA[4])
    clause_text(ds, DUA[4], WPX / 2 - w5 / 2, cy - box / 2)
    g = dp(ds * 0.5)
    right_s, left_s = WPX / 2 + w5 / 2 + g + dp(6), WPX / 2 - w5 / 2 - g - dp(6)
    star(right_s, cy, dp(12), hole=(13, 50, 38) if frame == 'cartouche' else BASE); rule(right_s + dp(9.5), lx1 - dp(4), cy, False); dot(lx1 - dp(1.5), cy, dp(3))
    star(left_s, cy, dp(12), hole=(13, 50, 38) if frame == 'cartouche' else BASE); rule(lx0 + dp(4), left_s - dp(9.5), cy, True); dot(lx0 + dp(1.5), cy, dp(3))
    if frame == 'dividers':
        for row in (1, 2):
            yy = y + dp(dua_lh) * row
            rule(lx0 + dp(lw) * 0.15, WPX / 2, yy, True, 0.28)
            rule(WPX / 2, lx1 - dp(lw) * 0.15, yy, False, 0.28)
    y += dp(3 * dua_lh) + (dp(inset * 0.6) if frame == 'cartouche' else 0)
    if frame != 'cartouche':
        y += dp(12 * kv)
        ornament(y + dp(7))
        y += dp(14)
    y += dp(free * weights[2] / sum(weights))

    # Footer.
    eh = line_h(xl, 16 * kv)
    ew = width(xl, 16 * kv, "الإصدار الأول")
    text_box(xl, 16 * kv, "الإصدار الأول", WPX / 2 - ew / 2, y, IVORY)
    cy = y + dp(eh) / 2
    d.line([(WPX / 2 - ew / 2 - dp(12 + 34 * kv), cy), (WPX / 2 - ew / 2 - dp(12 * kv), cy)], fill=BRASS + (153,), width=round(den))
    d.line([(WPX / 2 + ew / 2 + dp(12 * kv), cy), (WPX / 2 + ew / 2 + dp(12 + 34 * kv), cy)], fill=BRASS + (153,), width=round(den))
    y += dp(eh + 8 * kv)
    sig = drawable('qs_signature', dp(18 * kv))
    cw = width(mono, 12 * kv, "© 2026", rtl=False)
    sx = WPX / 2 - (sig.width + dp(8 * kv) + cw) / 2
    img.paste(sig, (round(sx), round(y)), sig)
    text_box(mono, 12 * kv, "© 2026", sx + sig.width + dp(8 * kv), y + dp(18 * kv) - dp(line_h(mono, 12 * kv)), MUTED, rtl=False)
    y += dp(18 * kv + 14 * kv)
    bw = WPX * 0.42
    d.rounded_rectangle([WPX / 2 - bw / 2, y, WPX / 2 + bw / 2, y + dp(2)], radius=dp(1), fill=LINE)
    filled = bw * min(1.0, seconds / 13)
    d.rounded_rectangle([WPX / 2 + bw / 2 - filled, y, WPX / 2 + bw / 2, y + dp(2)], radius=dp(1), fill=BRASS)
    y += dp(2 + 10 * kv)
    if seconds >= 7:
        ht = "اضغط في أي مكان للمتابعة"
        text_box(pr, 12 * kv, ht, WPX / 2 - width(pr, 12 * kv, ht) / 2, y, MUTED + (204,))
    img.resize((WP, HP), Image.LANCZOS).save(out)
    return vs, ds


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--fonts', required=True)
    ap.add_argument('--width', type=float, default=384)
    ap.add_argument('--height', type=float, default=832)
    ap.add_argument('--density', type=float, default=2.8125)
    ap.add_argument('--seconds', type=float, default=8)
    ap.add_argument('--frame', default='cartouche', choices=['none', 'dividers', 'cartouche'])
    a = ap.parse_args()
    vs, ds = render(a.out, a.fonts, a.width, a.height, a.density, seconds=a.seconds, frame=a.frame)
    print(f'verse {vs:.1f}sp, supplication {ds:.1f}sp')
