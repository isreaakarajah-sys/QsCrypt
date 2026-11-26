//! Byte-oriented AES-128/256 (FIPS 197). Slow and not constant-time:
//! reference and test use only, never production.

use crate::crypto::BlockCipher;
use std::sync::OnceLock;

struct Tables {
    sbox: [u8; 256],
    inv: [u8; 256],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut sbox = [0u8; 256];
        let (mut p, mut q) = (1u8, 1u8);
        loop {
            // p *= 3 in GF(2^8)
            p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };
            // q /= 3
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            if q & 0x80 != 0 {
                q ^= 0x09;
            }
            let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
            sbox[p as usize] = x ^ 0x63;
            if p == 1 {
                break;
            }
        }
        sbox[0] = 0x63;
        let mut inv = [0u8; 256];
        for (i, &s) in sbox.iter().enumerate() {
            inv[s as usize] = i as u8;
        }
        Tables { sbox, inv }
    })
}

fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1B } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

pub struct Aes256 {
    rk: [[u8; 16]; 15],
    nr: usize,
}

/// The same implementation keyed with 128 bits (10 rounds).
pub type Aes128 = Aes256;

impl Aes256 {
    pub fn new128(key: &[u8; 16]) -> Aes256 {
        let t = tables();
        let mut w = [[0u8; 4]; 44];
        for (i, word) in w.iter_mut().take(4).enumerate() {
            word.copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                temp = [t.sbox[temp[1] as usize] ^ rcon, t.sbox[temp[2] as usize], t.sbox[temp[3] as usize], t.sbox[temp[0] as usize]];
                rcon = xtime(rcon);
            }
            for k in 0..4 {
                w[i][k] = w[i - 4][k] ^ temp[k];
            }
        }
        let mut rk = [[0u8; 16]; 15];
        for (r, key) in rk.iter_mut().take(11).enumerate() {
            for c in 0..4 {
                key[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Aes256 { rk, nr: 10 }
    }

    pub fn new(key: &[u8; 32]) -> Aes256 {
        let t = tables();
        let mut w = [[0u8; 4]; 60];
        for (i, word) in w.iter_mut().take(8).enumerate() {
            word.copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = [t.sbox[temp[1] as usize] ^ rcon, t.sbox[temp[2] as usize], t.sbox[temp[3] as usize], t.sbox[temp[0] as usize]];
                rcon = xtime(rcon);
            } else if i % 8 == 4 {
                temp = temp.map(|b| t.sbox[b as usize]);
            }
            for k in 0..4 {
                w[i][k] = w[i - 8][k] ^ temp[k];
            }
        }
        let mut rk = [[0u8; 16]; 15];
        for (r, key) in rk.iter_mut().enumerate() {
            for c in 0..4 {
                key[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Aes256 { rk, nr: 14 }
    }

    fn add(s: &mut [u8; 16], k: &[u8; 16]) {
        for i in 0..16 {
            s[i] ^= k[i];
        }
    }

    pub fn encrypt_block(&self, s: &mut [u8; 16]) {
        let t = tables();
        let nr = self.nr;
        Self::add(s, &self.rk[0]);
        for round in 1..=nr {
            for b in s.iter_mut() {
                *b = t.sbox[*b as usize];
            }
            let o = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * c + r] = o[4 * ((c + r) % 4) + r];
                }
            }
            if round != nr {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    s[4 * c] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
                    s[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
                    s[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
                    s[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
                }
            }
            Self::add(s, &self.rk[round]);
        }
    }

    pub fn decrypt_block(&self, s: &mut [u8; 16]) {
        let t = tables();
        Self::add(s, &self.rk[self.nr]);
        for round in (0..self.nr).rev() {
            let o = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * ((c + r) % 4) + r] = o[4 * c + r];
                }
            }
            for b in s.iter_mut() {
                *b = t.inv[*b as usize];
            }
            Self::add(s, &self.rk[round]);
            if round != 0 {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    s[4 * c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
                    s[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
                    s[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
                    s[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
                }
            }
        }
    }
}

impl BlockCipher for Aes256 {
    fn encrypt_blocks(&self, data: &mut [u8]) {
        for blk in data.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = blk.try_into().unwrap();
            self.encrypt_block(b);
        }
    }

    fn decrypt_blocks(&self, data: &mut [u8]) {
        for blk in data.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = blk.try_into().unwrap();
            self.decrypt_block(b);
        }
    }
}
