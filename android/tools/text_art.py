#!/usr/bin/env python3
"""Turns short Arabic texts into vector drawables, shaped in the app's own fonts.

The Hacen fonts are sealed until activation, so the activation screen cannot
use them as fonts. Instead its texts ship as outlines: HarfBuzz shapes each
line (joining, harakat, kerning) and fontTools turns the glyphs into one path.
The drawables are white and are tinted in the app. No font file is ever
written into the repository.

    text_art.py --fonts DIR

DIR must hold hacen_xxl.ttf, hacen_xl.ttf and hacen_print.ttf.
Needs libharfbuzz (system) and fontTools.
"""
import argparse
import ctypes
import os

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

RES = os.path.join(os.path.dirname(__file__), '..', 'app', 'src', 'main', 'res', 'drawable')

# name, font, size (sp, drawn as dp), line height (sp, for several lines), alignment, lines
ART = [
    ('art_act_title', 'hacen_xxl', 28, None, 'center', ['تفعيل التطبيق']),
    ('art_act_intro', 'hacen_print', 15, 25, 'center', ['أدخل كلمة التفعيل التي وصلتك مع التطبيق.', 'تُطلب مرة واحدة فقط على هذا الجهاز.']),
    ('art_act_field', 'hacen_print', 15, None, 'start', ['رمز التفعيل']),
    ('art_act_button', 'hacen_xl', 17, None, 'center', ['تفعيل']),
    ('art_act_checking', 'hacen_xl', 14, None, 'center', ['جاري التحقق...']),
    ('art_act_wrong', 'hacen_print', 13, None, 'center', ['كلمة التفعيل غير صحيحة.']),
    ('art_act_wait', 'hacen_print', 13, None, 'center', ['محاولات كثيرة خاطئة. انتظر']),
    ('art_act_seconds', 'hacen_print', 13, None, 'center', ['ثانية']),
    ('art_act_note', 'hacen_print', 13, 21, 'start', ['هذه النسخة خاصة بك وبمن تشاركه معهم.', 'كلمة التفعيل تفكّ أيضًا خطوط التطبيق المشفّرة،', 'ولا تُحفظ على الجهاز.']),
]

UNITS = 10   # viewport units per dp


class Info(ctypes.Structure):
    _fields_ = [('codepoint', ctypes.c_uint32), ('mask', ctypes.c_uint32), ('cluster', ctypes.c_uint32),
                ('var1', ctypes.c_uint32), ('var2', ctypes.c_uint32)]


class Pos(ctypes.Structure):
    _fields_ = [('x_advance', ctypes.c_int32), ('y_advance', ctypes.c_int32), ('x_offset', ctypes.c_int32),
                ('y_offset', ctypes.c_int32), ('var', ctypes.c_uint32)]


hb = ctypes.CDLL('libharfbuzz.so.0')
hb.hb_blob_create_from_file.restype = ctypes.c_void_p
hb.hb_blob_create_from_file.argtypes = [ctypes.c_char_p]
hb.hb_face_create.restype = ctypes.c_void_p
hb.hb_face_create.argtypes = [ctypes.c_void_p, ctypes.c_uint]
hb.hb_font_create.restype = ctypes.c_void_p
hb.hb_font_create.argtypes = [ctypes.c_void_p]
hb.hb_font_set_scale.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
hb.hb_buffer_create.restype = ctypes.c_void_p
hb.hb_buffer_add_utf8.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_int]
hb.hb_buffer_guess_segment_properties.argtypes = [ctypes.c_void_p]
hb.hb_language_from_string.restype = ctypes.c_void_p
hb.hb_language_from_string.argtypes = [ctypes.c_char_p, ctypes.c_int]
hb.hb_buffer_set_language.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
hb.hb_shape.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
hb.hb_buffer_get_glyph_infos.restype = ctypes.POINTER(Info)
hb.hb_buffer_get_glyph_infos.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
hb.hb_buffer_get_glyph_positions.restype = ctypes.POINTER(Pos)
hb.hb_buffer_get_glyph_positions.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
hb.hb_buffer_destroy.argtypes = [ctypes.c_void_p]


class Face:
    def __init__(self, path):
        self.tt = TTFont(path)
        self.upem = self.tt['head'].unitsPerEm
        self.glyphs = self.tt.getGlyphSet()
        self.order = self.tt.getGlyphOrder()
        hhea = self.tt['hhea']
        self.ascent, self.descent = hhea.ascent, -hhea.descent
        blob = hb.hb_blob_create_from_file(path.encode())
        self.font = hb.hb_font_create(hb.hb_face_create(blob, 0))
        hb.hb_font_set_scale(self.font, self.upem, self.upem)

    def shape(self, text):
        """Glyph names with pen positions, in visual order (left to right), in font units."""
        buf = hb.hb_buffer_create()
        raw = text.encode('utf-8')
        hb.hb_buffer_add_utf8(buf, raw, len(raw), 0, -1)
        hb.hb_buffer_guess_segment_properties(buf)
        hb.hb_buffer_set_language(buf, hb.hb_language_from_string(b'ar', -1))
        hb.hb_shape(self.font, buf, None, 0)
        n = ctypes.c_uint()
        infos = hb.hb_buffer_get_glyph_infos(buf, ctypes.byref(n))
        pos = hb.hb_buffer_get_glyph_positions(buf, ctypes.byref(n))
        out, x = [], 0
        for i in range(n.value):
            gid = infos[i].codepoint
            if gid == 0:
                raise SystemExit(f'missing glyph in {text!r}')
            out.append((self.order[gid], x + pos[i].x_offset, pos[i].y_offset))
            x += pos[i].x_advance
        hb.hb_buffer_destroy(buf)
        return out, x


def build(face, size, line_height, align, lines):
    s = size / face.upem                       # dp per font unit
    box = (face.ascent + face.descent) * s     # one line's box, dp
    lh = line_height or box
    shaped = [face.shape(t) for t in lines]
    width = max(w for _, w in shaped) * s
    height = lh * (len(lines) - 1) + box
    cmds = []
    for i, (glyphs, w) in enumerate(shaped):
        x0 = {'center': (width - w * s) / 2, 'start': width - w * s, 'end': 0}[align]   # start = right
        baseline = i * lh + face.ascent * s
        for name, gx, gy in glyphs:
            pen = SVGPathPen(face.glyphs, ntos=lambda v: str(round(v)))
            k = s * UNITS
            face.glyphs[name].draw(TransformPen(pen, (k, 0, 0, -k, (x0 + gx * s) * UNITS, (baseline - gy * s) * UNITS)))
            c = pen.getCommands()
            if c:
                cmds.append(c)
    return cmds, width, height


MAX_PATH = 24_000   # aapt2 refuses strings over 32 767 bytes: several paths when needed


def write(name, cmds, width, height, text):
    w, h = round(width + 0.5), round(height + 0.5)
    chunks, cur = [], ''
    for c in cmds:
        if cur and len(cur) + len(c) + 1 > MAX_PATH:
            chunks.append(cur)
            cur = ''
        cur = (cur + ' ' + c) if cur else c
    if cur:
        chunks.append(cur)
    paths = ''.join(f'    <path\n        android:fillColor="#FFFFFFFF"\n        android:pathData="{d}" />\n' for d in chunks)
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           f'<!-- "{" / ".join(text)}": outlines from the app\'s Hacen font, made by android/tools/text_art.py. Tinted in code. -->\n'
           '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
           f'    android:width="{w}dp"\n    android:height="{h}dp"\n'
           f'    android:viewportWidth="{w * UNITS}"\n    android:viewportHeight="{h * UNITS}">\n'
           f'{paths}</vector>\n')
    with open(os.path.join(RES, name + '.xml'), 'w', encoding='utf-8') as f:
        f.write(xml)
    return w, h


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--fonts', required=True)
    a = ap.parse_args()
    faces = {}
    for name, font, size, lh, align, lines in ART:
        face = faces.setdefault(font, Face(os.path.join(a.fonts, font + '.ttf')))
        cmds, w, h = build(face, size, lh, align, lines)
        print(name, write(name, cmds, w, h, lines), f'{sum(map(len, cmds)) // 1024} KB')
