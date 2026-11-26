//! Small helpers: CRC-32, secure wiping, byte order, civil time.

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{compiler_fence, Ordering};

// ---------------------------------------------------------------- CRC-32

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

/// One step of the raw CRC-32 register (no initial or final inversion),
/// as VeraCrypt's keyfile pool uses it.
pub fn crc32_update(c: u32, b: u8) -> u32 {
    CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8)
}

/// IEEE 802.3 CRC-32 (same as zlib), as used by VeraCrypt headers.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// A GUID in its on-disk mixed-endian form, as text.
pub fn guid_string(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        le32(b, 0),
        le16(b, 4),
        le16(b, 6),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

// ---------------------------------------------------------------- base45 (RFC 9285)

const B45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// Base45: the QR alphanumeric alphabet, so QR codes stay small.
pub fn base45_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3 / 2 + 2);
    for pair in data.chunks(2) {
        let (mut n, digits) = if pair.len() == 2 { ((pair[0] as u32) << 8 | pair[1] as u32, 3) } else { (pair[0] as u32, 2) };
        for _ in 0..digits {
            out.push(B45[(n % 45) as usize] as char);
            n /= 45;
        }
    }
    out
}

pub fn base45_decode(s: &str) -> Option<Vec<u8>> {
    let vals: Vec<u32> = s.bytes().map(|c| B45.iter().position(|&b| b == c).map(|p| p as u32)).collect::<Option<_>>()?;
    let mut out = Vec::with_capacity(vals.len() * 2 / 3 + 1);
    for chunk in vals.chunks(3) {
        match chunk {
            [c, d, e] => {
                let n = c + d * 45 + e * 45 * 45;
                if n > 0xFFFF {
                    return None;
                }
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            [c, d] => {
                let n = c + d * 45;
                if n > 0xFF {
                    return None;
                }
                out.push(n as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- Crockford base32

const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32 (no I, L, O, U), for keys people type.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes, forgiving case, dashes, spaces and the look-alikes O/I/L.
pub fn base32_decode(s: &str, bytes: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = B32.iter().position(|&b| b as char == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.len() == bytes {
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------------- wiping

/// Overwrites `buf` with zeros in a way the optimizer will not remove.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Heap buffer that is wiped when dropped. Used for keys and passwords.
#[derive(Clone, Default)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(len: usize) -> Secret {
        Secret(vec![0u8; len])
    }

    pub fn from_slice(data: &[u8]) -> Secret {
        Secret(data.to_vec())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Secret {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// Constant-time equality for MAC/tag comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

// ---------------------------------------------------------------- byte order

pub fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
pub fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn put_le16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_le32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_le64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn put_be16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn put_be32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn put_be64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_be_bytes());
}

// ---------------------------------------------------------------- time

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of `days_from_civil`: (year, month 1-12, day 1-31).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Broken-down local time, enough for FAT/exFAT timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

pub fn civil_from_unix(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
    }
}

pub fn unix_from_civil(c: &Civil) -> i64 {
    days_from_civil(c.year, c.month, c.day) * 86_400
        + c.hour as i64 * 3600
        + c.minute as i64 * 60
        + c.second as i64
}

pub fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base45_rfc9285_examples() {
        assert_eq!(base45_encode(b"AB"), "BB8");
        assert_eq!(base45_encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(base45_encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(base45_decode("QED8WEX0").unwrap(), b"ietf!");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base45_decode(&base45_encode(&all)).unwrap(), all);
        assert!(base45_decode("GGW").is_none(), "65535 < n is rejected");
    }

    #[test]
    fn base32_round_trip() {
        let k: Vec<u8> = (0..20u8).map(|i| i * 13).collect();
        let s = base32_encode(&k);
        assert_eq!(s.len(), 32);
        assert_eq!(base32_decode(&s, 20).unwrap(), k);
        assert_eq!(base32_decode(&s.to_lowercase().replace('0', "o"), 20).unwrap(), k);
        assert!(base32_decode("UUUU", 2).is_none());
    }

    #[test]
    fn crc32_known_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn civil_round_trip() {
        for days in [-800_000i64, -1, 0, 1, 365, 10_957, 19_000, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        let c = civil_from_unix(1_764_072_000); // 2025-11-25 12:00:00 UTC
        assert_eq!((c.year, c.month, c.day, c.hour), (2025, 11, 25, 12));
        assert_eq!(unix_from_civil(&c), 1_764_072_000);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
