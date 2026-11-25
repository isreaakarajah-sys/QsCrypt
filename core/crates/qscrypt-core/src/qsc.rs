//! The QsCrypt file format, version 1 (experimental: may still change).
//!
//! Password → Argon2id → HKDF-SHA-512 key schedule → three independent
//! layers per chunk: AES-256-CTR, then Twofish-256-CTR, then
//! XChaCha20-Poly1305. Breaking the confidentiality requires breaking all
//! three ciphers; integrity comes from Poly1305 and the header MAC.
//!
//! ```text
//! offset size  field (little-endian)
//! 0      8     "QSCRYPT\0"
//! 8      2     format version (1)
//! 10     2     header length incl. MAC
//! 12     4     flags (0)
//! 16     1     KDF id (1 = Argon2id v1.3)
//! 17     1     Argon2 lanes
//! 18     2     reserved (0)
//! 20     4     Argon2 memory (KiB)
//! 24     4     Argon2 passes
//! 28     32    salt
//! 60     16    nonce prefix
//! 76     4     chunk size (plaintext bytes)
//! 80     8     stream length (metadata block + file data)
//! 88     4     extension length E (0 in v1; reserved for policies, recipients)
//! 92     E     extensions
//! 92+E   32    HMAC-SHA-512(header MAC key, bytes 0..92+E), truncated
//! then   n x   [ciphertext chunk | 16-byte tag]
//! ```
//!
//! The plaintext stream is `u32 meta length | meta | file data`, where meta
//! holds the original name, modification time and size, so the name is
//! encrypted too. Chunk `i` uses nonce `prefix || LE64(i)` and associated
//! data `header MAC || LE64(i) || final flag`, which rejects reordering,
//! truncation and extension.

use crate::crypto::{ctr_xor, Backend, BlockCipher, CipherKind};
use crate::error::{Error, Result};
use crate::util::{ct_eq, le16, le32, le64, put_le16, put_le32, put_le64, Secret};
use std::io::{Read, Write};

pub const MAGIC: [u8; 8] = *b"QSCRYPT\0";
pub const FORMAT_VERSION: u16 = 1;
pub const EXTENSION: &str = "qsc";

const FIXED: usize = 92;
const MAC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KDF_ARGON2ID: u8 = 1;
const MAX_CHUNK: u32 = 1 << 20;
const MIN_CHUNK: u32 = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub chunk_size: u32,
}

impl Default for Params {
    /// RFC 9106's second recommended option (64 MiB, 3 passes, 4 lanes).
    fn default() -> Params {
        Params { memory_kib: 64 * 1024, iterations: 3, lanes: 4, chunk_size: MAX_CHUNK }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub modified: i64,
    pub size: u64,
}

pub fn is_qsc(prefix: &[u8]) -> bool {
    prefix.len() >= 8 && prefix[..8] == MAGIC
}

struct Keys {
    aes: Box<dyn BlockCipher>,
    twofish: Box<dyn BlockCipher>,
    aead: Secret,
    mac: Secret,
    iv_aes: [u8; 8],
    iv_twofish: [u8; 8],
}

fn derive(backend: &dyn Backend, password: &[u8], header: &[u8]) -> Result<Keys> {
    let salt = &header[28..60];
    let mut master = Secret::new(32);
    backend.argon2id(password, salt, le32(header, 20), le32(header, 24), header[17] as u32, &mut master)?;
    let mut okm = Secret::new(32 * 4 + 16);
    // The KDF parameters are bound into the key schedule.
    crate::kdf::hkdf_sha512(backend, b"QsCrypt v1 key schedule", &master, &header[..28], &mut okm)?;
    Ok(Keys {
        aes: backend.cipher(CipherKind::Aes, okm[0..32].try_into().unwrap())?,
        twofish: backend.cipher(CipherKind::Twofish, okm[32..64].try_into().unwrap())?,
        aead: Secret::from_slice(&okm[64..96]),
        mac: Secret::from_slice(&okm[96..128]),
        iv_aes: okm[128..136].try_into().unwrap(),
        iv_twofish: okm[136..144].try_into().unwrap(),
    })
}

fn header_mac(backend: &dyn Backend, keys: &Keys, header: &[u8]) -> [u8; MAC_LEN] {
    backend.hmac_sha512(&keys.mac, &[header])[..MAC_LEN].try_into().unwrap()
}

fn nonce(prefix: &[u8], index: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&index.to_le_bytes());
    n
}

fn aad(mac: &[u8; MAC_LEN], index: u64, last: bool) -> [u8; MAC_LEN + 9] {
    let mut a = [0u8; MAC_LEN + 9];
    a[..MAC_LEN].copy_from_slice(mac);
    a[MAC_LEN..MAC_LEN + 8].copy_from_slice(&index.to_le_bytes());
    a[MAC_LEN + 8] = last as u8;
    a
}

/// CTR counters: chunks are at most 2^16 blocks, so chunk i owns [i·2^16, (i+1)·2^16).
fn counter(index: u64) -> u64 {
    index << 16
}

fn chunk_count(stream_len: u64, chunk: u32) -> u64 {
    stream_len.div_ceil(chunk as u64).max(1)
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

fn meta_block(meta: &Meta) -> Result<Vec<u8>> {
    let name = meta.name.as_bytes();
    if name.len() > 4096 {
        return Err(Error::invalid("file name too long"));
    }
    let mut m = Vec::with_capacity(4 + 2 + name.len() + 16);
    m.extend_from_slice(&((2 + name.len() + 16) as u32).to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(name);
    m.extend_from_slice(&meta.modified.to_le_bytes());
    m.extend_from_slice(&meta.size.to_le_bytes());
    Ok(m)
}

/// Encrypts `input` (exactly `meta.size` bytes) to `output`.
pub fn encrypt(
    backend: &dyn Backend,
    password: &[u8],
    meta: &Meta,
    input: &mut dyn Read,
    output: &mut dyn Write,
    params: Params,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::invalid("empty password"));
    }
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&params.chunk_size) || params.lanes == 0 || params.lanes > 255 || params.iterations == 0 {
        return Err(Error::invalid("bad parameters"));
    }
    let meta_bytes = meta_block(meta)?;
    let stream_len = meta_bytes.len() as u64 + meta.size;

    let mut h = vec![0u8; FIXED];
    h[..8].copy_from_slice(&MAGIC);
    put_le16(&mut h, 8, FORMAT_VERSION);
    put_le16(&mut h, 10, (FIXED + MAC_LEN) as u16);
    h[16] = KDF_ARGON2ID;
    h[17] = params.lanes as u8;
    put_le32(&mut h, 20, params.memory_kib);
    put_le32(&mut h, 24, params.iterations);
    backend.fill_random(&mut h[28..76])?;
    put_le32(&mut h, 76, params.chunk_size);
    put_le64(&mut h, 80, stream_len);
    put_le32(&mut h, 88, 0);

    let keys = derive(backend, password, &h)?;
    let mac = header_mac(backend, &keys, &h);
    output.write_all(&h)?;
    output.write_all(&mac)?;

    let chunk = params.chunk_size as usize;
    let total = chunk_count(stream_len, params.chunk_size);
    let mut buf = vec![0u8; chunk];
    let mut meta_pos = 0usize;
    let mut data_left = meta.size;
    let mut done = 0u64;
    for i in 0..total {
        let want = (stream_len - i * chunk as u64).min(chunk as u64) as usize;
        let mut fill = 0;
        while fill < want && meta_pos < meta_bytes.len() {
            let n = (want - fill).min(meta_bytes.len() - meta_pos);
            buf[fill..fill + n].copy_from_slice(&meta_bytes[meta_pos..meta_pos + n]);
            fill += n;
            meta_pos += n;
        }
        if fill < want {
            let n = want - fill;
            let got = read_full(input, &mut buf[fill..want])?;
            if got != n {
                return Err(Error::invalid("input shorter than its declared size"));
            }
            data_left -= n as u64;
        }
        let data = &mut buf[..want];
        ctr_xor(keys.aes.as_ref(), &keys.iv_aes, counter(i), data);
        ctr_xor(keys.twofish.as_ref(), &keys.iv_twofish, counter(i), data);
        let last = i + 1 == total;
        let tag = backend.xchacha_seal(keys.aead[..].try_into().unwrap(), &nonce(&h[60..76], i), &aad(&mac, i, last), data)?;
        output.write_all(data)?;
        output.write_all(&tag)?;
        done += want as u64;
        if !progress(done.saturating_sub(meta_bytes.len() as u64), meta.size) {
            return Err(Error::Cancelled);
        }
    }
    debug_assert_eq!(data_left, 0);
    crate::util::wipe(&mut buf);
    output.flush()?;
    Ok(())
}

struct Opened {
    header: Vec<u8>,
    mac: [u8; MAC_LEN],
    keys: Keys,
    chunk: u32,
    stream_len: u64,
}

fn open(backend: &dyn Backend, password: &[u8], input: &mut dyn Read) -> Result<Opened> {
    let mut h = vec![0u8; FIXED];
    if read_full(input, &mut h)? != FIXED || h[..8] != MAGIC {
        return Err(Error::corrupt("not a QsCrypt file"));
    }
    let version = le16(&h, 8);
    if version != FORMAT_VERSION {
        return Err(Error::unsupported(format!("QsCrypt format version {version}")));
    }
    let ext_len = le32(&h, 88) as usize;
    if ext_len > 64 * 1024 || le16(&h, 10) as usize != FIXED + ext_len + MAC_LEN {
        return Err(Error::corrupt("bad QsCrypt header length"));
    }
    if h[16] != KDF_ARGON2ID {
        return Err(Error::unsupported("unknown key derivation"));
    }
    // Refuse parameters that would exhaust memory or time on a phone.
    let (mem, passes, lanes, chunk) = (le32(&h, 20), le32(&h, 24), h[17] as u32, le32(&h, 76));
    if !(8..=1 << 20).contains(&mem) || !(1..=64).contains(&passes) || lanes == 0 || mem < 8 * lanes || !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk) {
        return Err(Error::corrupt("QsCrypt parameters out of range"));
    }
    h.resize(FIXED + ext_len, 0);
    if read_full(input, &mut h[FIXED..])? != ext_len {
        return Err(Error::Tampered);
    }
    let mut mac = [0u8; MAC_LEN];
    if read_full(input, &mut mac)? != MAC_LEN {
        return Err(Error::Tampered);
    }
    let keys = derive(backend, password, &h)?;
    if !ct_eq(&header_mac(backend, &keys, &h), &mac) {
        return Err(Error::WrongPassword);
    }
    let stream_len = le64(&h, 80);
    Ok(Opened { header: h, mac, keys, chunk, stream_len })
}

/// Decrypts to `output`, or only reads the metadata when `output` is None.
pub fn decrypt(
    backend: &dyn Backend,
    password: &[u8],
    input: &mut dyn Read,
    mut output: Option<&mut dyn Write>,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<Meta> {
    let o = open(backend, password, input)?;
    let chunk = o.chunk as usize;
    let total = chunk_count(o.stream_len, o.chunk);
    let mut buf = vec![0u8; chunk + TAG_LEN];
    let mut meta_buf: Vec<u8> = Vec::new();
    let mut meta: Option<(Meta, usize)> = None; // (meta, header bytes incl. length prefix)
    let mut pos = 0u64;
    let mut written = 0u64;
    for i in 0..total {
        let want = (o.stream_len - pos).min(chunk as u64) as usize;
        if read_full(input, &mut buf[..want + TAG_LEN])? != want + TAG_LEN {
            return Err(Error::Tampered);
        }
        let (data, tag) = buf[..want + TAG_LEN].split_at_mut(want);
        let last = i + 1 == total;
        backend.xchacha_open(o.keys.aead[..].try_into().unwrap(), &nonce(&o.header[60..76], i), &aad(&o.mac, i, last), data, (&*tag).try_into().unwrap())?;
        ctr_xor(o.keys.twofish.as_ref(), &o.keys.iv_twofish, counter(i), data);
        ctr_xor(o.keys.aes.as_ref(), &o.keys.iv_aes, counter(i), data);

        let mut body: &[u8] = data;
        if meta.is_none() {
            let need = if meta_buf.len() < 4 { 4 } else { 4 + le32(&meta_buf, 0) as usize };
            let take = (need.saturating_sub(meta_buf.len())).min(body.len());
            meta_buf.extend_from_slice(&body[..take]);
            body = &body[take..];
            if meta_buf.len() >= 4 {
                let mlen = le32(&meta_buf, 0) as usize;
                if !(18..=4096 + 18).contains(&mlen) {
                    return Err(Error::corrupt("bad metadata block"));
                }
                let rest = (4 + mlen - meta_buf.len()).min(body.len());
                meta_buf.extend_from_slice(&body[..rest]);
                body = &body[rest..];
                if meta_buf.len() == 4 + mlen {
                    let m = &meta_buf[4..];
                    let nlen = le16(m, 0) as usize;
                    if 2 + nlen + 16 != mlen {
                        return Err(Error::corrupt("bad metadata block"));
                    }
                    let name = String::from_utf8_lossy(&m[2..2 + nlen]).into_owned();
                    let modified = i64::from_le_bytes(m[2 + nlen..10 + nlen].try_into().unwrap());
                    let size = le64(m, 10 + nlen);
                    if (4 + mlen) as u64 + size != o.stream_len {
                        return Err(Error::corrupt("size mismatch"));
                    }
                    meta = Some((Meta { name, modified, size }, 4 + mlen));
                    if output.is_none() {
                        break;
                    }
                }
            }
        }
        if let Some(out) = output.as_deref_mut() {
            if !body.is_empty() {
                out.write_all(body)?;
                written += body.len() as u64;
            }
        }
        pos += want as u64;
        let size = meta.as_ref().map_or(0, |m| m.0.size);
        if !progress(written, size) {
            return Err(Error::Cancelled);
        }
    }
    crate::util::wipe(&mut buf);
    let (meta, _) = meta.ok_or_else(|| Error::corrupt("missing metadata"))?;
    if let Some(out) = output {
        // Nothing may follow the final chunk.
        let mut extra = [0u8; 1];
        if read_full(input, &mut extra)? != 0 {
            return Err(Error::Tampered);
        }
        out.flush()?;
        if written != meta.size {
            return Err(Error::Tampered);
        }
    }
    Ok(meta)
}

// ---------------------------------------------------------------- sealed assets

/// Magic of a blob sealed by `android/tools/seal_assets.py`.
pub const ASSET_MAGIC: [u8; 8] = *b"QSASSET1";
const ASSET_HEADER: usize = 60;

/// Opens a sealed asset (used for the app's licensed fonts, unlocked by the
/// activation password):
///
/// ```text
/// 0  8   "QSASSET1"
/// 8  4   Argon2id memory (KiB, LE)
/// 12 4   Argon2id passes
/// 16 4   Argon2id lanes
/// 20 16  salt
/// 36 24  XChaCha20-Poly1305 nonce
/// 60 ..  ciphertext | 16-byte tag   (associated data: bytes 0..60)
/// ```
///
/// A wrong password and a modified blob both give `Error::WrongPassword`.
pub fn open_asset(backend: &dyn Backend, password: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < ASSET_HEADER + TAG_LEN || data[..8] != ASSET_MAGIC {
        return Err(Error::corrupt("not a sealed asset"));
    }
    let (memory, passes, lanes) = (le32(data, 8), le32(data, 12), le32(data, 16));
    if !(8..=1 << 20).contains(&memory) || !(1..=16).contains(&passes) || !(1..=16).contains(&lanes) || memory < 8 * lanes {
        return Err(Error::corrupt("asset parameters out of range"));
    }
    let mut key = Secret::new(32);
    backend.argon2id(password, &data[20..36], memory, passes, lanes, &mut key)?;
    let nonce: [u8; 24] = data[36..60].try_into().unwrap();
    let body = &data[ASSET_HEADER..];
    let (ct, tag) = body.split_at(body.len() - TAG_LEN);
    let mut out = ct.to_vec();
    backend
        .xchacha_open(key[..].try_into().unwrap(), &nonce, &data[..ASSET_HEADER], &mut out, tag.try_into().unwrap())
        .map_err(|e| match e {
            Error::Tampered => Error::WrongPassword,
            other => other,
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;

    #[test]
    fn asset_rejects_garbage() {
        let b = RefBackend::with_fakes();
        assert!(matches!(open_asset(&b, b"pw", b"short"), Err(Error::Corrupt(_))));
        let mut blob = vec![0u8; 100];
        blob[..8].copy_from_slice(&ASSET_MAGIC);
        blob[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open_asset(&b, b"pw", &blob), Err(Error::Corrupt(_))));
    }

    fn params() -> Params {
        Params { memory_kib: 64, iterations: 1, lanes: 1, chunk_size: 4096 }
    }

    fn roundtrip(size: usize, chunk: u32) {
        let b = RefBackend::with_fakes();
        let content: Vec<u8> = (0..size).map(|i| (i * 31 % 256) as u8).collect();
        let meta = Meta { name: "تقرير سري.pdf".into(), modified: 1_764_000_000, size: size as u64 };
        let mut out = Vec::new();
        let p = Params { chunk_size: chunk, ..params() };
        encrypt(&b, b"pw", &meta, &mut content.as_slice(), &mut out, p, &mut |_, _| true).unwrap();
        assert!(is_qsc(&out));
        // Name and data must not appear in the clear.
        assert!(!out.windows(6).any(|w| w == "تقرير".as_bytes()));
        let mut back = Vec::new();
        let m = decrypt(&b, b"pw", &mut out.as_slice(), Some(&mut back), &mut |_, _| true).unwrap();
        assert_eq!(m, meta);
        assert_eq!(back, content, "size {size} chunk {chunk}");
        let peek = decrypt(&b, b"pw", &mut out.as_slice(), None, &mut |_, _| true).unwrap();
        assert_eq!(peek, meta);
    }

    #[test]
    fn round_trips() {
        for size in [0, 1, 4000, 4096, 4096 * 3 + 7, 50_000] {
            roundtrip(size, 4096);
        }
        roundtrip(100_000, 1 << 20);
    }

    #[test]
    fn detects_wrong_password_and_tampering() {
        let b = RefBackend::with_fakes();
        let content = vec![7u8; 20_000];
        let meta = Meta { name: "a".into(), modified: 0, size: content.len() as u64 };
        let mut enc = Vec::new();
        encrypt(&b, b"right", &meta, &mut content.as_slice(), &mut enc, params(), &mut |_, _| true).unwrap();
        let mut sink = Vec::new();
        assert!(matches!(decrypt(&b, b"wrong", &mut enc.as_slice(), Some(&mut sink), &mut |_, _| true), Err(Error::WrongPassword)));

        let hdr = FIXED + MAC_LEN;
        for (what, f) in [
            ("flip data", Box::new(|v: &mut Vec<u8>| v[hdr + 100] ^= 1) as Box<dyn Fn(&mut Vec<u8>)>),
            ("truncate last chunk", Box::new(|v: &mut Vec<u8>| v.truncate(v.len() - 1))),
            ("drop final chunk", Box::new(move |v: &mut Vec<u8>| v.truncate(hdr + 4 * (4096 + 16)))),
            ("append", Box::new(|v: &mut Vec<u8>| v.push(0))),
            ("flip header", Box::new(|v: &mut Vec<u8>| v[30] ^= 1)),
        ] {
            let mut bad = enc.clone();
            f(&mut bad);
            let mut sink = Vec::new();
            let r = decrypt(&b, b"right", &mut bad.as_slice(), Some(&mut sink), &mut |_, _| true);
            assert!(matches!(r, Err(Error::Tampered) | Err(Error::WrongPassword)), "{what}: {r:?}");
        }
        // Swapping two chunks is caught by the per-chunk nonce.
        let mut swapped = enc.clone();
        let c = 4096 + 16;
        let (a, bb) = (hdr, hdr + c);
        let first: Vec<u8> = swapped[a..a + c].to_vec();
        let second: Vec<u8> = swapped[bb..bb + c].to_vec();
        swapped[a..a + c].copy_from_slice(&second);
        swapped[bb..bb + c].copy_from_slice(&first);
        let mut sink = Vec::new();
        assert!(matches!(decrypt(&b, b"right", &mut swapped.as_slice(), Some(&mut sink), &mut |_, _| true), Err(Error::Tampered)));
    }

    #[test]
    fn rejects_hostile_parameters() {
        let b = RefBackend::with_fakes();
        let meta = Meta { name: "a".into(), modified: 0, size: 0 };
        let mut enc = Vec::new();
        encrypt(&b, b"pw", &meta, &mut &b""[..], &mut enc, params(), &mut |_, _| true).unwrap();
        enc[20..24].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(decrypt(&b, b"pw", &mut enc.as_slice(), None, &mut |_, _| true), Err(Error::Corrupt(_))));
    }
}
