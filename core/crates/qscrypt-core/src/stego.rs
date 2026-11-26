//! Hiding an (already encrypted) QsCrypt file inside the pixels of an image.
//!
//! One bit goes in the lowest bit of each red, green and blue value, at
//! positions spread over the whole image by a permutation derived from the
//! password (so the bits are not bunched at the top of the picture). Bits
//! are written by LSB matching (the value moves by ±1 at random rather than
//! having its last bit forced), which defeats the classic pair and
//! chi-square tests for LSB replacement. The stream itself is XORed with a
//! keystream, so even its length is not visible.
//!
//! The image must then be saved losslessly (PNG). Messaging apps recompress
//! photos and destroy hidden data: send the PNG as a document.

use crate::crypto::{ctr_xor, Backend, CipherKind};
use crate::error::{Error, Result};
use crate::util::{crc32, Secret};

const MAGIC: [u8; 4] = *b"QSST";
const OVERHEAD: usize = 4 + 4 + 4;
const SALT: &[u8] = b"QsCrypt stego v1 salt";

/// Payload bytes an image of `w` x `h` pixels can carry.
pub fn capacity(w: usize, h: usize) -> usize {
    (w * h * 3 / 8).saturating_sub(OVERHEAD)
}

struct Walk {
    n: u64,
    a: u64,
    b: u64,
    cipher: Box<dyn crate::crypto::BlockCipher>,
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

impl Walk {
    fn new(backend: &dyn Backend, password: &[u8], slots: u64) -> Result<Walk> {
        if slots < 64 {
            return Err(Error::invalid("image too small"));
        }
        let mut k = Secret::new(64);
        backend.argon2id(password, SALT, 32 * 1024, 2, 1, &mut k)?;
        let cipher = backend.cipher(CipherKind::Aes, k[..32].try_into().unwrap())?;
        let mut a = u64::from_le_bytes(k[32..40].try_into().unwrap()) % slots;
        let b = u64::from_le_bytes(k[40..48].try_into().unwrap()) % slots;
        // A multiplier coprime with the slot count makes i -> a·i + b a permutation.
        loop {
            if a == 0 {
                a = 1;
            }
            if gcd(a, slots) == 1 {
                break;
            }
            a = (a + 1) % slots;
        }
        Ok(Walk { n: slots, a, b, cipher })
    }

    fn slot(&self, i: u64) -> usize {
        ((self.a as u128 * i as u128 + self.b as u128) % self.n as u128) as usize
    }

    fn keystream(&self, data: &mut [u8]) {
        ctr_xor(self.cipher.as_ref(), b"QsStego!", 0, data);
    }
}

fn get_bit(px: &[u32], slot: usize) -> u8 {
    let p = px[slot / 3];
    let shift = 16 - 8 * (slot % 3) as u32;
    ((p >> shift) & 1) as u8
}

fn set_bit(px: &mut [u32], slot: usize, bit: u8, coin: bool) {
    let i = slot / 3;
    let shift = 16 - 8 * (slot % 3) as u32;
    let v = ((px[i] >> shift) & 0xFF) as i32;
    if (v & 1) as u8 == bit {
        return;
    }
    // LSB matching: step up or down by one, staying in range.
    let nv = if v == 0 {
        1
    } else if v == 255 {
        254
    } else if coin {
        v + 1
    } else {
        v - 1
    };
    px[i] = (px[i] & !(0xFF << shift)) | ((nv as u32) << shift);
}

/// Hides `payload` in `pixels` (ARGB, one u32 per pixel). Alpha is set to
/// opaque everywhere so the PNG encoder keeps every value exact.
pub fn hide(backend: &dyn Backend, pixels: &mut [u32], password: &[u8], payload: &[u8]) -> Result<()> {
    let slots = pixels.len() as u64 * 3;
    if payload.len() > capacity(pixels.len(), 1) {
        return Err(Error::NoSpace);
    }
    let walk = Walk::new(backend, password, slots)?;
    let mut stream = Vec::with_capacity(OVERHEAD + payload.len());
    stream.extend_from_slice(&MAGIC);
    stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(payload);
    stream.extend_from_slice(&crc32(payload).to_le_bytes());
    walk.keystream(&mut stream);
    for p in pixels.iter_mut() {
        *p |= 0xFF00_0000;
    }
    let mut coins = vec![0u8; stream.len()];
    backend.fill_random(&mut coins)?;
    for (byte_i, &byte) in stream.iter().enumerate() {
        for bit_i in 0..8 {
            let bit = (byte >> (7 - bit_i)) & 1;
            let coin = (coins[byte_i] >> bit_i) & 1 == 1;
            set_bit(pixels, walk.slot((byte_i * 8 + bit_i) as u64), bit, coin);
        }
    }
    Ok(())
}

fn read_bytes(pixels: &[u32], walk: &Walk, from: usize, n: usize) -> Vec<u8> {
    (from..from + n)
        .map(|byte_i| (0..8).fold(0u8, |acc, bit_i| (acc << 1) | get_bit(pixels, walk.slot((byte_i * 8 + bit_i) as u64))))
        .collect()
}

/// Extracts what `hide` put there; `WrongPassword` if nothing (or not with
/// this password).
pub fn reveal(backend: &dyn Backend, pixels: &[u32], password: &[u8]) -> Result<Vec<u8>> {
    let slots = pixels.len() as u64 * 3;
    let walk = Walk::new(backend, password, slots)?;
    let mut head = read_bytes(pixels, &walk, 0, 8);
    let mut ks = vec![0u8; 8];
    walk.keystream(&mut ks);
    for (h, k) in head.iter_mut().zip(&ks) {
        *h ^= k;
    }
    if head[..4] != MAGIC {
        return Err(Error::WrongPassword);
    }
    let len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
    if len > capacity(pixels.len(), 1) {
        return Err(Error::WrongPassword);
    }
    let mut stream = read_bytes(pixels, &walk, 0, OVERHEAD + len);
    walk.keystream(&mut stream);
    let payload = stream[8..8 + len].to_vec();
    if crc32(&payload).to_le_bytes() != stream[8 + len..] {
        return Err(Error::Tampered);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;

    fn picture(w: usize, h: usize) -> Vec<u32> {
        (0..w * h).map(|i| 0xFF00_0000 | ((i * 37 % 256) << 16 | (i * 11 % 256) << 8 | (i * 5 % 256)) as u32).collect()
    }

    #[test]
    fn hides_and_reveals() {
        let b = RefBackend::with_fakes();
        let orig = picture(200, 150);
        let mut px = orig.clone();
        let payload: Vec<u8> = (0..9000u32).map(|i| (i * 7 % 256) as u8).collect();
        assert!(capacity(200, 150) >= payload.len());
        hide(&b, &mut px, b"stego pw", &payload).unwrap();
        // Every value moved by at most one.
        for (a, c) in orig.iter().zip(&px) {
            for s in [0, 8, 16] {
                let d = (((a >> s) & 0xFF) as i32 - ((c >> s) & 0xFF) as i32).abs();
                assert!(d <= 1);
            }
        }
        assert_eq!(reveal(&b, &px, b"stego pw").unwrap(), payload);
        assert!(reveal(&b, &px, b"other").is_err());
        assert!(reveal(&b, &orig, b"stego pw").is_err());
        let mut small = picture(20, 20);
        assert!(matches!(hide(&b, &mut small, b"pw", &payload), Err(Error::NoSpace)));
    }
}
