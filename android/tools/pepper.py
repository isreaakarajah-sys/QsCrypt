#!/usr/bin/env python3
"""Release step: writes the activation pepper into the engine library of APKs.

The fonts are sealed with Argon2id(activation password + pepper) (see
seal_assets.py and core/crates/qscrypt-ffi/src/pepper.rs). The pepper is kept
with the signing key, never in the repository: this tool finds the slot in
every lib/*/libqscrypt_ffi.so of a built APK, writes the pepper there
(masked) and erases the marker. The library is stored uncompressed, so the
APK keeps its layout; only the entries' CRCs change. Sign the APK afterwards
(the old signature no longer matches).

    pepper.py in.apk out.apk --pepper-file QS_ACTIVATION_PEPPER.txt
"""
import argparse
import secrets
import struct
import sys
import zlib

MARKER = b"QsPepperSlot-v1:"
MASK = bytes.fromhex("b23da58d9160770d1b4bfcd7b2363ecc16460dc5bcc5ad99f0441cd62ebdb0e5")


def patch(src: str, dst: str, pepper: bytes) -> int:
    data = bytearray(open(src, "rb").read())
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        sys.exit("not a zip file")
    count = struct.unpack_from("<H", data, eocd + 10)[0]
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    p, done = cd_off, 0
    for _ in range(count):
        if data[p:p + 4] != b"PK\x01\x02":
            sys.exit("broken central directory")
        method = struct.unpack_from("<H", data, p + 10)[0]
        csize, usize = struct.unpack_from("<II", data, p + 20)
        nlen, xlen, clen = struct.unpack_from("<HHH", data, p + 28)
        lho = struct.unpack_from("<I", data, p + 42)[0]
        name = bytes(data[p + 46:p + 46 + nlen]).decode()
        if name.startswith("lib/") and name.endswith("/libqscrypt_ffi.so"):
            if method != 0:
                sys.exit(f"{name} is compressed; expected stored")
            if data[lho:lho + 4] != b"PK\x03\x04":
                sys.exit(f"{name}: broken local header")
            lnlen, lxlen = struct.unpack_from("<HH", data, lho + 26)
            start = lho + 30 + lnlen + lxlen
            body = bytes(data[start:start + usize])
            i = body.find(MARKER)
            if i < 0 or body.find(MARKER, i + 1) >= 0:
                sys.exit(f"{name}: the pepper slot must appear exactly once (already patched?)")
            slot = start + i
            data[slot:slot + 16] = secrets.token_bytes(16)
            data[slot + 16:slot + 48] = bytes(a ^ b for a, b in zip(pepper, MASK))
            crc = zlib.crc32(data[start:start + usize]) & 0xFFFFFFFF
            struct.pack_into("<I", data, lho + 14, crc)
            struct.pack_into("<I", data, p + 16, crc)
            if struct.unpack_from("<H", data, lho + 6)[0] & 8:
                d = start + csize
                struct.pack_into("<I", data, d + 4 if data[d:d + 4] == b"PK\x07\x08" else d, crc)
            done += 1
            print(f"  {name}: pepper written", file=sys.stderr)
        p += 46 + nlen + xlen + clen
    if not done:
        sys.exit("no engine library in this APK")
    open(dst, "wb").write(data)
    return done


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--pepper-file", required=True)
    a = ap.parse_args()
    pep = bytes.fromhex(open(a.pepper_file).read().strip())
    if len(pep) != 32:
        sys.exit("the pepper must be 32 bytes (64 hex digits)")
    patch(a.src, a.dst, pep)
