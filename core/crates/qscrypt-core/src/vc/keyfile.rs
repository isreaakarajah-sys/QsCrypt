//! VeraCrypt / TrueCrypt keyfiles (VeraCrypt `Common/Keyfiles.c`).
//!
//! Each keyfile (its first 1 MiB) is run through a CRC-32 register; after
//! every byte the four register bytes are added into a pool. The pool is 64
//! bytes when the password is at most 64 bytes long, 128 otherwise. Pools of
//! several keyfiles add up, so their order does not matter. The pool is then
//! added byte-wise onto the password, which is extended to the pool size.

use crate::error::{Error, Result};
use crate::util::{crc32_update, Secret};

/// Bytes of a keyfile that are used.
pub const MAX_READ: usize = 1 << 20;
const LEGACY_POOL: usize = 64;
const POOL: usize = 128;
/// VeraCrypt's password limit (UTF-8 bytes).
pub const MAX_PASSWORD: usize = 128;

pub struct KeyfilePool {
    pool: [u8; POOL],
    size: usize,
    count: usize,
}

impl KeyfilePool {
    pub fn new(password_len: usize) -> KeyfilePool {
        KeyfilePool { pool: [0; POOL], size: if password_len <= LEGACY_POOL { LEGACY_POOL } else { POOL }, count: 0 }
    }

    /// Adds one keyfile; only its first `MAX_READ` bytes matter.
    pub fn add(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(Error::invalid("empty keyfile"));
        }
        let mut crc = 0xFFFF_FFFFu32;
        let mut pos = 0usize;
        for &b in data.iter().take(MAX_READ) {
            crc = crc32_update(crc, b);
            for byte in crc.to_be_bytes() {
                self.pool[pos] = self.pool[pos].wrapping_add(byte);
                pos += 1;
            }
            if pos >= self.size {
                pos = 0;
            }
        }
        self.count += 1;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The password as VeraCrypt hands it to PBKDF2.
    pub fn apply(&self, password: &[u8]) -> Secret {
        let len = password.len().max(self.size);
        let mut out = Secret::new(len);
        out[..password.len()].copy_from_slice(password);
        for i in 0..self.size {
            out[i] = out[i].wrapping_add(self.pool[i]);
        }
        out
    }
}

impl Drop for KeyfilePool {
    fn drop(&mut self) {
        crate::util::wipe(&mut self.pool);
    }
}

/// Combines a password with keyfiles. No keyfiles: the password unchanged.
pub fn apply_keyfiles(password: &[u8], keyfiles: &[&[u8]]) -> Result<Secret> {
    if keyfiles.is_empty() {
        return Ok(Secret::from_slice(password));
    }
    if password.len() > MAX_PASSWORD {
        return Err(Error::invalid("password longer than 128 bytes"));
    }
    let mut pool = KeyfilePool::new(password.len());
    for k in keyfiles {
        pool.add(k)?;
    }
    Ok(pool.apply(password))
}

/// Parses keyfiles packed as `[u32 little-endian length][bytes]...`, the
/// form the apps pass them in.
pub fn unpack(packed: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < packed.len() {
        if pos + 4 > packed.len() {
            return Err(Error::invalid("truncated keyfile list"));
        }
        let n = u32::from_le_bytes(packed[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + n > packed.len() {
            return Err(Error::invalid("truncated keyfile list"));
        }
        out.push(&packed[pos..pos + n]);
        pos += n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_implementation() {
        // Computed by an independent Python port of cryptsetup's tcrypt.c.
        let kf1: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 256) as u8).collect();
        let kf2 = b"second keyfile".to_vec();
        let out = apply_keyfiles(b"pw", &[&kf1, &kf2]).unwrap();
        assert_eq!(out.len(), 64);
        let swapped = apply_keyfiles(b"pw", &[&kf2, &kf1]).unwrap();
        assert_eq!(&out[..], &swapped[..], "order does not matter");
        assert_eq!(crate::util::crc32(&out), 0xC235_4FFC);
        assert_eq!(&out[..4], &[0x00, 0x14, 0x2B, 0xFD]);
    }

    #[test]
    fn pool_sizes_and_limits() {
        let kf = [7u8; 10];
        assert_eq!(apply_keyfiles(b"", &[&kf]).unwrap().len(), 64);
        assert_eq!(apply_keyfiles(&[b'a'; 64], &[&kf]).unwrap().len(), 64);
        assert_eq!(apply_keyfiles(&[b'a'; 65], &[&kf]).unwrap().len(), 128);
        assert_eq!(apply_keyfiles(&[b'a'; 100], &[&kf]).unwrap().len(), 128);
        assert!(apply_keyfiles(b"pw", &[&[]]).is_err());
        assert_eq!(&apply_keyfiles(b"pw", &[]).unwrap()[..], b"pw");
        // Only the first MiB counts.
        let mut big = vec![1u8; MAX_READ + 5];
        let a = apply_keyfiles(b"x", &[&big]).unwrap();
        big[MAX_READ + 1] = 9;
        assert_eq!(&a[..], &apply_keyfiles(b"x", &[&big]).unwrap()[..]);
    }

    #[test]
    fn unpacks() {
        let mut packed = Vec::new();
        for k in [&b"abc"[..], &b""[..], &b"z"[..]] {
            packed.extend((k.len() as u32).to_le_bytes());
            packed.extend(k);
        }
        let v = unpack(&packed).unwrap();
        assert_eq!(v, vec![&b"abc"[..], &b""[..], &b"z"[..]]);
        assert!(unpack(&packed[..5]).is_err());
    }
}
