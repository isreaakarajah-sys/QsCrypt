//! XTS mode (IEEE 1619) over any 128-bit block cipher.
//!
//! Matches VeraCrypt's `EncryptBufferXTS`: the tweak of a data unit is the
//! unit number as a 128-bit little-endian integer encrypted with the second
//! key, multiplied by alpha for each following 16-byte block. Buffers are
//! always whole blocks, so ciphertext stealing is never needed.

use crate::crypto::BlockCipher;

pub struct Xts {
    data: Box<dyn BlockCipher>,
    tweak: Box<dyn BlockCipher>,
}

#[inline]
fn mul_alpha(t: &mut [u8; 16]) {
    let carry = t[15] >> 7;
    for i in (1..16).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
    }
    t[0] <<= 1;
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

impl Xts {
    pub fn new(data: Box<dyn BlockCipher>, tweak: Box<dyn BlockCipher>) -> Xts {
        Xts { data, tweak }
    }

    /// Encrypts `buf`, made of consecutive data units of `unit_size` bytes
    /// (the last one may be shorter), the first of which is `first_unit`.
    pub fn encrypt(&self, buf: &mut [u8], unit_size: usize, first_unit: u64) {
        self.process(buf, unit_size, first_unit, true);
    }

    pub fn decrypt(&self, buf: &mut [u8], unit_size: usize, first_unit: u64) {
        self.process(buf, unit_size, first_unit, false);
    }

    fn process(&self, buf: &mut [u8], unit_size: usize, first_unit: u64, encrypt: bool) {
        assert!(buf.len() % 16 == 0, "XTS buffers must be whole blocks");
        assert!(unit_size % 16 == 0 && unit_size > 0);
        if buf.is_empty() {
            return;
        }
        let units = buf.len().div_ceil(unit_size);
        let mut seeds = vec![0u8; units * 16];
        for (u, seed) in seeds.chunks_exact_mut(16).enumerate() {
            seed[..8].copy_from_slice(&(first_unit + u as u64).to_le_bytes());
        }
        self.tweak.encrypt_blocks(&mut seeds);

        let mut mask = vec![0u8; buf.len()];
        for u in 0..units {
            let mut t: [u8; 16] = seeds[u * 16..u * 16 + 16].try_into().unwrap();
            let start = u * unit_size;
            let end = (start + unit_size).min(buf.len());
            for blk in mask[start..end].chunks_exact_mut(16) {
                blk.copy_from_slice(&t);
                mul_alpha(&mut t);
            }
        }
        crate::util::xor_into(buf, &mask);
        if encrypt {
            self.data.encrypt_blocks(buf);
        } else {
            self.data.decrypt_blocks(buf);
        }
        crate::util::xor_into(buf, &mask);
        crate::util::wipe(&mut mask);
    }
}
