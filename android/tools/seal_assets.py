#!/usr/bin/env python3
"""Seals licensed files (the Hacen fonts) with the app's activation password.

The repository is public, so the fonts are only stored encrypted: the app
decrypts them on the phone after the activation password is entered once.

    python3 android/tools/seal_assets.py --password 'XXXX-XXXX-XXXX-XXXX' \\
        --pepper-file QS_ACTIVATION_PEPPER.txt \\
        --out android/app/src/main/assets/fonts.qsa \\
        hacen_xxl.ttf=/path/HacenLinerXXL.ttf hacen_xl.ttf=... hacen_print.ttf=...

Format (decrypted by qscrypt_core::qsc::open_asset):
    "QSASSET1" | u32 memory KiB | u32 passes | u32 lanes | salt[16] | nonce[24]
    | XChaCha20-Poly1305(Argon2id(password), header as associated data)
Plaintext bundle: "QSFONTS1" | u32 count | { u16 name length | name | u32 size | bytes }*

The password is normalized like the app does: letters and digits only, upper case.
The key is Argon2id(password + pepper): the pepper (32 bytes, hex in the file)
is kept with the signing key, never in the repository, and written into the
release library by pepper.py.
Needs the `cryptography` package (Argon2id requires version 44 or later).
"""
import argparse
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MEMORY_KIB = 128 * 1024
PASSES = 4
LANES = 1


def normalize(password: str) -> bytes:
    return "".join(c for c in password if c.isalnum()).upper().encode()


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12); _quarter(s, 1, 5, 9, 13); _quarter(s, 2, 6, 10, 14); _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15); _quarter(s, 1, 6, 11, 12); _quarter(s, 2, 7, 8, 13); _quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def seal(password: bytes, plaintext: bytes, memory=MEMORY_KIB, passes=PASSES, lanes=LANES) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(24)
    header = b"QSASSET1" + struct.pack("<III", memory, passes, lanes) + salt + nonce
    key = Argon2id(salt=salt, length=32, iterations=passes, lanes=lanes, memory_cost=memory).derive(password)
    sub = hchacha20(key, nonce[:16])
    ct = ChaCha20Poly1305(sub).encrypt(b"\0\0\0\0" + nonce[16:], plaintext, header)
    return header + ct


def bundle(files) -> bytes:
    out = b"QSFONTS1" + struct.pack("<I", len(files))
    for name, data in files:
        n = name.encode()
        out += struct.pack("<H", len(n)) + n + struct.pack("<I", len(data)) + data
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--password", required=True)
    ap.add_argument("--pepper-file", required=True, help="32 bytes as hex, kept with the signing key")
    ap.add_argument("--out", required=True)
    ap.add_argument("files", nargs="+", help="name=path")
    a = ap.parse_args()
    files = []
    for spec in a.files:
        name, path = spec.split("=", 1)
        with open(path, "rb") as f:
            files.append((name, f.read()))
    pepper = bytes.fromhex(open(a.pepper_file).read().strip())
    if len(pepper) != 32:
        sys.exit("the pepper must be 32 bytes (64 hex digits)")
    sealed = seal(normalize(a.password) + pepper, bundle(files))
    with open(a.out, "wb") as f:
        f.write(sealed)
    print(f"{a.out}: {len(sealed)} bytes, {len(files)} files", file=sys.stderr)


if __name__ == "__main__":
    main()
