#!/usr/bin/env python3
"""Generates known-answer vectors and small VeraCrypt/TrueCrypt test volumes.

Independent of the Rust code: it uses Python's hashlib and the `cryptography`
package, and implements the VeraCrypt header layout from the documentation.
Run from anywhere:  python3 core/testdata/gen_vectors.py
Outputs (next to this script): vectors.rs and *.vol test volumes.
"""
import hashlib
import hmac
import os
import struct
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))


def det_bytes(label: str, n: int) -> bytes:
    """Deterministic pseudo-random bytes so regenerating gives identical files."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha512(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]


def rs_bytes(b: bytes) -> str:
    return "&[" + ", ".join(f"0x{x:02x}" for x in b) + "]"


# ------------------------------------------------------------------ XTS / VC

def xts_encrypt(key1: bytes, key2: bytes, unit: int, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key1 + key2), modes.XTS(unit.to_bytes(16, "little"))).encryptor()
    return enc.update(data) + enc.finalize()


def vc_plain_header(magic, master, data_offset, data_size, volume_size, hidden_size, version, required):
    h = bytearray(448)  # header bytes 64..512
    h[0:4] = magic
    struct.pack_into(">H", h, 4, version)
    struct.pack_into(">H", h, 6, required)
    struct.pack_into(">Q", h, 28, hidden_size)
    struct.pack_into(">Q", h, 36, volume_size)
    struct.pack_into(">Q", h, 44, data_offset)
    struct.pack_into(">Q", h, 52, data_size)
    struct.pack_into(">I", h, 60, 0)
    struct.pack_into(">I", h, 64, 512)
    h[192:448] = master
    struct.pack_into(">I", h, 8, zlib.crc32(bytes(h[192:448])))
    struct.pack_into(">I", h, 188, zlib.crc32(bytes(h[0:188])))
    return bytes(h)


def vc_encrypted_header(plain, salt, password, prf, iterations):
    dk = hashlib.pbkdf2_hmac(prf, password, salt, iterations, 192)
    return salt + xts_encrypt(dk[0:32], dk[32:64], 0, plain)


def data_pattern(label, offset, n):
    return det_bytes(f"{label}@{offset}", n)


def build_volume(name, magic, password, prf, iterations, hidden=None, version=5, required=0x010B):
    """AES volume: 64 KiB normal data area, optional hidden volume inside it."""
    data_size = 65536 + (65536 if hidden else 0)
    size = 262144 + data_size
    vol = bytearray(det_bytes(name + "/noise", size))
    master = det_bytes(name + "/mk", 256)
    salt = det_bytes(name + "/salt", 64)
    plain = vc_plain_header(magic, master, 131072, data_size, data_size, 0, version, required)
    vol[0:512] = vc_encrypted_header(plain, salt, password, prf, iterations)
    salt_b = det_bytes(name + "/salt-backup", 64)
    vol[size - 131072:size - 131072 + 512] = vc_encrypted_header(plain, salt_b, password, prf, iterations)
    regions = [(131072, data_size, master, "outer")]
    if hidden:
        h_pw, h_offset, h_size = hidden
        h_master = det_bytes(name + "/hmk", 256)
        h_salt = det_bytes(name + "/hsalt", 64)
        h_plain = vc_plain_header(magic, h_master, h_offset, h_size, h_size, h_size, version, required)
        vol[65536:65536 + 512] = vc_encrypted_header(h_plain, h_salt, h_pw, prf, iterations)
        regions.append((h_offset, h_size, h_master, "hidden"))
    for off, length, mk, label in regions:
        for u in range(off // 512, (off + length) // 512):
            pt = data_pattern(f"{name}/{label}", u * 512 - off, 512)
            vol[u * 512:(u + 1) * 512] = xts_encrypt(mk[0:32], mk[32:64], u, pt)
    with open(os.path.join(HERE, name + ".vol"), "wb") as f:
        f.write(vol)
    return size


# ------------------------------------------------------------------ XChaCha20

def rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl(s[b], 7)


def hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13); quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12); quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_seal(key, nonce24, aad, pt):
    sub = hchacha20(key, nonce24[:16])
    ct = ChaCha20Poly1305(sub).encrypt(b"\0\0\0\0" + nonce24[16:], pt, aad)
    return ct[:-16], ct[-16:]


def main():
    lines = ["// @generated by gen_vectors.py — do not edit by hand.", "#[allow(dead_code)]", "pub mod v {"]

    def const(name, value):
        lines.append(f"    pub const {name}: &[u8] = {rs_bytes(value)};")

    msgs = [b"", b"abc", b"The quick brown fox jumps over the lazy dog", det_bytes("msg", 1000)]
    lines.append("    pub const HASH_MSGS: &[&[u8]] = &[" + ", ".join(rs_bytes(m) for m in msgs) + "];")
    lines.append("    pub const SHA512: &[&[u8]] = &[" + ", ".join(rs_bytes(hashlib.sha512(m).digest()) for m in msgs) + "];")
    lines.append("    pub const SHA256: &[&[u8]] = &[" + ", ".join(rs_bytes(hashlib.sha256(m).digest()) for m in msgs) + "];")
    lines.append("    pub const RIPEMD160: &[&[u8]] = &[" + ", ".join(rs_bytes(hashlib.new("ripemd160", m).digest()) for m in msgs) + "];")

    key_long = det_bytes("hmac-key", 200)
    const("HMAC_KEY_SHORT", b"key")
    const("HMAC_KEY_LONG", key_long)
    const("HMAC_MSG", msgs[2])
    const("HMAC_SHA512_SHORT", hmac.new(b"key", msgs[2], hashlib.sha512).digest())
    const("HMAC_SHA512_LONG", hmac.new(key_long, msgs[2], hashlib.sha512).digest())

    # PBKDF2: (prf, password, salt, iterations) -> 192 bytes
    pw = "pässwörd 123".encode()
    salt = det_bytes("salt", 64)
    lines.append("    pub const PBKDF2_PW: &[u8] = " + rs_bytes(pw) + ";")
    const("PBKDF2_SALT", salt)
    for prf, tag in (("sha512", "SHA512"), ("sha256", "SHA256"), ("ripemd160", "RIPEMD160")):
        for it in (1, 2, 1000):
            const(f"PBKDF2_{tag}_{it}", hashlib.pbkdf2_hmac(prf, pw, salt, it, 192))

    # XTS-AES-256
    k1, k2 = det_bytes("xts-k1", 32), det_bytes("xts-k2", 32)
    const("XTS_K1", k1)
    const("XTS_K2", k2)
    pt = det_bytes("xts-pt", 512 * 4)
    const("XTS_PT", pt)
    const("XTS_CT_UNIT_256", b"".join(xts_encrypt(k1, k2, 256 + i, pt[i * 512:(i + 1) * 512]) for i in range(4)))
    const("XTS_CT_448_UNIT_0", xts_encrypt(k1, k2, 0, pt[:448]))
    big_unit = 0x0123_4567_89AB_CDEF
    const("XTS_CT_BIG_UNIT", xts_encrypt(k1, k2, big_unit, pt[:512]))
    lines.append(f"    pub const XTS_BIG_UNIT: u64 = 0x{big_unit:x};")

    # AES-256 ECB (FIPS-197 C.3)
    const("AES_KEY", bytes(range(32)))
    const("AES_PT", bytes.fromhex("00112233445566778899aabbccddeeff"))
    const("AES_CT", bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"))

    # HKDF-SHA512
    hk_ikm, hk_salt, hk_info = det_bytes("hk-ikm", 32), b"QsCrypt test salt", b"info"
    const("HKDF_IKM", hk_ikm)
    const("HKDF_SALT", hk_salt)
    const("HKDF_INFO", hk_info)
    const("HKDF_OUT", HKDF(algorithm=hashes.SHA512(), length=160, salt=hk_salt, info=hk_info).derive(hk_ikm))

    # Argon2id (small parameters)
    a_pw, a_salt = b"password", det_bytes("argon-salt", 16)
    const("ARGON2_PW", a_pw)
    const("ARGON2_SALT", a_salt)
    const("ARGON2ID_M1024_T2_P2", Argon2id(salt=a_salt, length=32, iterations=2, lanes=2, memory_cost=1024).derive(a_pw))

    # XChaCha20-Poly1305
    xk, xn, xa = det_bytes("xc-key", 32), det_bytes("xc-nonce", 24), b"header"
    xp = det_bytes("xc-pt", 300)
    xc, xt = xchacha_seal(xk, xn, xa, xp)
    const("XC_KEY", xk)
    const("XC_NONCE", xn)
    const("XC_AAD", xa)
    const("XC_PT", xp)
    const("XC_CT", xc)
    const("XC_TAG", xt)

    # VeraCrypt's own sector self-test (src/Common/Tests.c, TestSectorBufEncryption):
    # 4 units of the IEEE 1619 vector 10-14 plaintext, first unit 0xFFFFFFFFFF - case,
    # primary key rows from key1, secondary keys from key2 (bytes i, first 32 = pi).
    # The CRC32 values are VeraCrypt's; AES is re-derived here as a check.
    e_key = bytes.fromhex("2718281828459045235360287471352662497757247093699959574966967627")
    pi_key = bytes.fromhex("3141592653589793238462643383279502884197169399375105820974944592")
    ieee_ptx = bytes(range(256)) * 2
    aes_crcs = [zlib.crc32(b"".join(xts_encrypt(e_key, pi_key, 0xFFFFFFFFFF - c + i, ieee_ptx) for i in range(4))) for c in range(4)]
    assert aes_crcs == [0x888F2990, 0xEA28EA34, 0xE058F5A2, 0x10473DC9], "procedure no longer matches VeraCrypt"
    const("VC_KEY_E", e_key)
    const("VC_KEY_PI", pi_key)
    const("VC_IEEE_PTX", ieee_ptx)
    vc_crcs = {
        "AES": [0x888F2990, 0xEA28EA34, 0xE058F5A2, 0x10473DC9],
        "Serpent": [0x7EDFECB3, 0x357BAAAA, 0xC7B9FCA5, 0xB5263E0C],
        "Twofish": [0x91525124, 0x2895CC47, 0x6BEE346D, 0xB1C45759],
        "AES-Twofish": [0x6CEA7FA2, 0x69052C4C, 0x88DB8DE5, 0xF16FD8C5],
        "AES-Twofish-Serpent": [0xA2D7D82A, 0xDBF76412, 0xDF0EA03E, 0xDADEDFF7],
        "Serpent-AES": [0x6DD133B3, 0x0E5717D2, 0x39F83CD9, 0x8A79FA2C],
        "Serpent-Twofish-AES": [0xE536DAF8, 0x3AE89E7F, 0x2CC1301A, 0xCAC7BDC7],
        "Twofish-Serpent": [0x2686C859, 0x8A201780, 0x8DD13796, 0xE95196CB],
    }
    lines.append("    pub const VC_SECTOR_CRCS: &[(&str, [u32; 4])] = &[")
    for name, crcs in vc_crcs.items():
        lines.append(f'        ("{name}", [' + ", ".join(f"0x{c:08x}" for c in crcs) + "]),")
    lines.append("    ];")

    # Sealed asset (the activation-password format of android/tools/seal_assets.py).
    import importlib.util
    spec = importlib.util.spec_from_file_location("seal_assets", os.path.join(HERE, "..", "..", "android", "tools", "seal_assets.py"))
    seal_assets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seal_assets)
    asset_plain = seal_assets.bundle([("a.ttf", det_bytes("font-a", 3000)), ("b.ttf", b"tiny")])
    os.urandom = lambda n, _r=iter(range(10**6)): det_bytes(f"asset-rand/{next(_r)}", n)  # deterministic file
    asset = seal_assets.seal(seal_assets.normalize("abcd-EFGH-2345"), asset_plain, memory=1024, passes=1, lanes=1)
    const("ASSET_PW", seal_assets.normalize("abcd-EFGH-2345"))
    const("ASSET_PLAIN", asset_plain)
    const("ASSET_SEALED", asset)

    # Test volumes (PIM 1 -> 16000 iterations keeps tests fast).
    vols = [
        ("vc_aes_sha512", b"VERA", "correct horse".encode(), "sha512", 16000, None),
        ("vc_aes_sha256", b"VERA", "SHA-256 volume".encode(), "sha256", 16000, None),
        ("vc_hidden", b"VERA", "outer password".encode(), "sha512", 16000, ("hidden password".encode(), 196608, 32768)),
        ("tc_aes_sha512", b"TRUE", "truecrypt".encode(), "sha512", 1000, None),
    ]
    for name, magic, password, prf, iters, hidden in vols:
        required = 0x0700 if magic == b"TRUE" else 0x010B
        size = build_volume(name, magic, password, prf, iters, hidden, required=required)
        print(f"{name}.vol: {size} bytes")

    lines.append("}")
    with open(os.path.join(HERE, "vectors.rs"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("vectors.rs written")


if __name__ == "__main__":
    main()
