//! An encrypted file disguised as a picture.
//!
//! The output is a real JPEG or PNG followed by the payload: every image
//! viewer stops at the end of the picture and shows it normally, so the
//! file opens as an ordinary photo. After the picture comes
//!
//! ```text
//! salt[16] | chunk 0 | chunk 1 | ...      chunk = XChaCha20-Poly1305(1 MiB) + tag[16]
//! ```
//!
//! with the key from Argon2id(password, salt). Nothing in it is
//! recognisable: the salt is random and the rest is ciphertext, so without
//! the password the trailing bytes cannot be told apart from noise (or from
//! the extra data some cameras append). The app puts a whole QsCrypt file
//! (name, size, three layers) inside, so a disguised picture keeps every
//! property of an ordinary encrypted file.

use crate::crypto::Backend;
use crate::error::{Error, Result};
use std::io::{Read, Seek, SeekFrom, Write};

const SALT: usize = 16;
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;
const LANES: u32 = 1;
/// Covers are read into memory; real photos are far smaller.
pub const MAX_COVER: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Jpeg => "jpeg",
            Kind::Png => "png",
        }
    }
}

fn read_exact_or(r: &mut dyn Read, buf: &mut [u8]) -> Result<bool> {
    let mut done = 0;
    while done < buf.len() {
        let n = r.read(&mut buf[done..])?;
        if n == 0 {
            return Ok(false);
        }
        done += n;
    }
    Ok(true)
}

/// Where the picture ends (the payload starts), reading from the start.
pub fn image_end(r: &mut dyn Read) -> Result<Option<(Kind, u64)>> {
    let mut head = [0u8; 8];
    if !read_exact_or(r, &mut head[..2])? {
        return Ok(None);
    }
    if head[..2] == [0xFF, 0xD8] {
        return jpeg_end(r).map(|e| e.map(|e| (Kind::Jpeg, e)));
    }
    if !read_exact_or(r, &mut head[2..])? || head != [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Ok(None);
    }
    let mut pos = 8u64;
    loop {
        let mut ch = [0u8; 8];
        if !read_exact_or(r, &mut ch)? {
            return Ok(None);
        }
        let len = u32::from_be_bytes(ch[..4].try_into().unwrap()) as u64;
        if len > 0x7FFF_FFFF {
            return Ok(None);
        }
        if !skip(r, len + 4)? {
            return Ok(None);
        }
        pos += 12 + len;
        if &ch[4..] == b"IEND" {
            return Ok(Some((Kind::Png, pos)));
        }
    }
}

/// Skips `n` bytes; false if the input ends first.
fn skip(r: &mut dyn Read, mut n: u64) -> Result<bool> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let k = (n as usize).min(buf.len());
        if !read_exact_or(r, &mut buf[..k])? {
            return Ok(false);
        }
        n -= k as u64;
    }
    Ok(true)
}

/// JPEG after SOI: segments, entropy-coded scans, up to EOI.
fn jpeg_end(r: &mut dyn Read) -> Result<Option<u64>> {
    let mut pos = 2u64;
    let mut byte = [0u8; 1];
    let mut next = |r: &mut dyn Read, pos: &mut u64| -> Result<Option<u8>> {
        if !read_exact_or(r, &mut byte)? {
            return Ok(None);
        }
        *pos += 1;
        Ok(Some(byte[0]))
    };
    // `pending`: a marker found while scanning entropy-coded data.
    let mut pending: Option<u8> = None;
    loop {
        let marker = match pending.take() {
            Some(m) => m,
            None => {
                let Some(b) = next(r, &mut pos)? else { return Ok(None) };
                if b != 0xFF {
                    return Ok(None);
                }
                let mut m = 0xFF;
                while m == 0xFF {
                    let Some(b) = next(r, &mut pos)? else { return Ok(None) };
                    m = b;
                }
                m
            }
        };
        match marker {
            0xD9 => return Ok(Some(pos)),
            0x01 | 0xD0..=0xD7 => continue,
            _ => {}
        }
        let (Some(hi), Some(lo)) = (next(r, &mut pos)?, next(r, &mut pos)?) else { return Ok(None) };
        let len = u16::from_be_bytes([hi, lo]) as u64;
        if len < 2 {
            return Ok(None);
        }
        if !skip(r, len - 2)? {
            return Ok(None);
        }
        pos += len - 2;
        if marker == 0xDA {
            // Scan data: 0xFF is followed by 0x00 (stuffing) or a restart marker inside it.
            loop {
                let Some(b) = next(r, &mut pos)? else { return Ok(None) };
                if b != 0xFF {
                    continue;
                }
                let mut m = 0xFF;
                while m == 0xFF {
                    let Some(b) = next(r, &mut pos)? else { return Ok(None) };
                    m = b;
                }
                if m == 0x00 || (0xD0..=0xD7).contains(&m) {
                    continue;
                }
                pending = Some(m);
                break;
            }
        }
    }
}

fn derive(backend: &dyn Backend, password: &[u8], salt: &[u8]) -> Result<crate::util::Secret> {
    let mut key = crate::util::Secret::new(32);
    backend.argon2id(password, salt, MEMORY_KIB, PASSES, LANES, &mut key)?;
    Ok(key)
}

fn nonce(salt: &[u8], index: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(&salt[..16]);
    n[16..].copy_from_slice(&index.to_le_bytes());
    n
}

fn aad(index: u64, last: bool) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[..8].copy_from_slice(&index.to_le_bytes());
    a[8] = last as u8;
    a
}

fn fill(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        let n = r.read(&mut buf[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

/// Writes `cover` (up to the end of its picture) followed by `payload`
/// sealed with `password`. Returns the kind of picture.
pub fn wrap(
    backend: &dyn Backend,
    cover: &[u8],
    payload: &mut dyn Read,
    payload_len: u64,
    out: &mut dyn Write,
    password: &[u8],
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<Kind> {
    if password.is_empty() {
        return Err(Error::invalid("a password is required"));
    }
    let (kind, end) = image_end(&mut &cover[..])?.ok_or_else(|| Error::invalid("the cover must be a JPEG or PNG picture"))?;
    out.write_all(&cover[..end as usize])?;
    let mut salt = [0u8; SALT];
    backend.fill_random(&mut salt)?;
    out.write_all(&salt)?;
    let key = derive(backend, password, &salt)?;
    let key: &[u8; 32] = key[..32].try_into().unwrap();
    // Read one chunk ahead to know which chunk is the last.
    let mut cur = vec![0u8; CHUNK];
    let mut nxt = vec![0u8; CHUNK];
    let mut n = fill(payload, &mut cur)?;
    let mut index = 0u64;
    let mut done = 0u64;
    loop {
        let m = if n == CHUNK { fill(payload, &mut nxt)? } else { 0 };
        let last = m == 0;
        let tag = backend.xchacha_seal(key, &nonce(&salt, index), &aad(index, last), &mut cur[..n])?;
        out.write_all(&cur[..n])?;
        out.write_all(&tag)?;
        done += n as u64;
        if !progress(done, payload_len) {
            return Err(Error::Cancelled);
        }
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut nxt);
        n = m;
        index += 1;
    }
    crate::util::wipe(&mut cur);
    crate::util::wipe(&mut nxt);
    out.flush()?;
    Ok(kind)
}

/// Kind of picture, where it ends, and how many bytes follow it.
pub fn probe(input: &mut (impl Read + Seek)) -> Result<Option<(Kind, u64, u64)>> {
    let len = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;
    let mut r = std::io::BufReader::new(&mut *input);
    Ok(image_end(&mut r)?.map(|(k, end)| (k, end, len.saturating_sub(end))))
}

/// Recovers the payload hidden after the picture. `WrongPassword` when
/// there is nothing hidden with this password.
pub fn unwrap(
    backend: &dyn Backend,
    input: &mut (impl Read + Seek),
    out: &mut dyn Write,
    password: &[u8],
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<u64> {
    let (_, end, trailing) = probe(input)?.ok_or(Error::WrongPassword)?;
    if trailing < (SALT + TAG) as u64 {
        return Err(Error::WrongPassword);
    }
    input.seek(SeekFrom::Start(end))?;
    let mut r = std::io::BufReader::with_capacity(1 << 20, &mut *input);
    let mut salt = [0u8; SALT];
    if !read_exact_or(&mut r, &mut salt)? {
        return Err(Error::WrongPassword);
    }
    let key = derive(backend, password, &salt)?;
    let key: &[u8; 32] = key[..32].try_into().unwrap();
    let total = trailing - SALT as u64;
    let mut consumed = 0u64;
    let mut written = 0u64;
    let mut buf = vec![0u8; CHUNK + TAG];
    let mut index = 0u64;
    loop {
        let left = total - consumed;
        let take = left.min((CHUNK + TAG) as u64) as usize;
        if take < TAG {
            return Err(if index == 0 { Error::WrongPassword } else { Error::Tampered });
        }
        if !read_exact_or(&mut r, &mut buf[..take])? {
            return Err(Error::Tampered);
        }
        consumed += take as u64;
        let last = consumed == total;
        let (data, tag) = buf[..take].split_at_mut(take - TAG);
        let tag: [u8; 16] = tag.try_into().unwrap();
        if backend.xchacha_open(key, &nonce(&salt, index), &aad(index, last), data, &tag).is_err() {
            return Err(if index == 0 { Error::WrongPassword } else { Error::Tampered });
        }
        out.write_all(data)?;
        written += data.len() as u64;
        if !progress(consumed, total) {
            return Err(Error::Cancelled);
        }
        if last {
            break;
        }
        index += 1;
    }
    crate::util::wipe(&mut buf);
    out.flush()?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;
    use std::io::Cursor;

    fn tiny_jpeg() -> Vec<u8> {
        // SOI, APP0 (with an 0xFFD9 inside, which must not end the picture), SOS with stuffed bytes and a restart, EOI.
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x08, b'J', b'F', 0xFF, 0xD9, 0x00, 0x00];
        j.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x01, 0x02, 0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD3, 0x33, 0xFF, 0xD9]);
        j
    }

    fn tiny_png() -> Vec<u8> {
        let mut p = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        for (ty, data) in [(&b"IHDR"[..], &[0u8; 13][..]), (&b"IDAT"[..], &[1, 2, 3][..]), (&b"IEND"[..], &[][..])] {
            p.extend_from_slice(&(data.len() as u32).to_be_bytes());
            p.extend_from_slice(ty);
            p.extend_from_slice(data);
            p.extend_from_slice(&[0, 0, 0, 0]);
        }
        p
    }

    #[test]
    fn finds_the_end_of_pictures() {
        let j = tiny_jpeg();
        assert_eq!(image_end(&mut &j[..]).unwrap(), Some((Kind::Jpeg, j.len() as u64)));
        let mut with_tail = j.clone();
        with_tail.extend_from_slice(b"camera extras");
        assert_eq!(image_end(&mut &with_tail[..]).unwrap(), Some((Kind::Jpeg, j.len() as u64)));
        let p = tiny_png();
        assert_eq!(image_end(&mut &p[..]).unwrap(), Some((Kind::Png, p.len() as u64)));
        assert_eq!(image_end(&mut &b"GIF89a..."[..]).unwrap(), None);
        assert_eq!(image_end(&mut &j[..10]).unwrap(), None, "truncated");
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let b = RefBackend::with_fakes();
        for cover in [tiny_jpeg(), tiny_png()] {
            for size in [0usize, 5, CHUNK, CHUNK + 1, 2 * CHUNK + 77] {
                let payload: Vec<u8> = (0..size as u32).map(|i| (i * 7 + 1) as u8).collect();
                let mut out = Vec::new();
                // The cover's own trailing bytes are dropped.
                let mut c = cover.clone();
                c.extend_from_slice(b"old trailer");
                wrap(&b, &c, &mut &payload[..], size as u64, &mut out, b"pw", &mut |_, _| true).unwrap();
                assert_eq!(&out[..cover.len()], &cover[..], "the picture is untouched");
                assert!(!out.windows(8).any(|w| w == b"QSCRYPT\0"));
                let mut back = Vec::new();
                let n = unwrap(&b, &mut Cursor::new(&out), &mut back, b"pw", &mut |_, _| true).unwrap();
                assert_eq!(n as usize, size);
                assert_eq!(back, payload);
                assert!(matches!(unwrap(&b, &mut Cursor::new(&out), &mut Vec::new(), b"no", &mut |_, _| true), Err(Error::WrongPassword)));
                if size > 10 {
                    let mut bad = out.clone();
                    let at = bad.len() - 20;
                    bad[at] ^= 1;
                    assert!(unwrap(&b, &mut Cursor::new(&bad), &mut Vec::new(), b"pw", &mut |_, _| true).is_err());
                    // Cutting the last chunk off is detected too.
                    let cut = &out[..out.len() - 40];
                    assert!(unwrap(&b, &mut Cursor::new(cut), &mut Vec::new(), b"pw", &mut |_, _| true).is_err());
                }
            }
        }
        // A plain picture holds nothing.
        assert!(matches!(unwrap(&b, &mut Cursor::new(tiny_jpeg()), &mut Vec::new(), b"pw", &mut |_, _| true), Err(Error::WrongPassword)));
        assert!(wrap(&b, b"not a picture", &mut &b"x"[..], 1, &mut Vec::new(), b"pw", &mut |_, _| true).is_err());
    }
}
