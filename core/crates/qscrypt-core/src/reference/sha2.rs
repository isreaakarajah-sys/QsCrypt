//! Straightforward SHA-512 and SHA-256 (FIPS 180-4). Reference use only.

use super::sha_consts::{H256, H512, K256, K512};

pub trait Hash: Clone {
    const BLOCK: usize;
    const OUT: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>;

    fn digest(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = Self::new();
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }
}

#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; 128],
    len: usize,
    total: u128,
}

impl Sha512 {
    fn compress(h: &mut [u64; 8], block: &[u8]) {
        let mut w = [0u64; 80];
        for (t, word) in w.iter_mut().take(16).enumerate() {
            *word = u64::from_be_bytes(block[t * 8..t * 8 + 8].try_into().unwrap());
        }
        for t in 16..80 {
            let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
            let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
            w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for t in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[t]).wrapping_add(w[t]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
}

impl Hash for Sha512 {
    const BLOCK: usize = 128;
    const OUT: usize = 64;

    fn new() -> Self {
        Sha512 { h: H512, buf: [0; 128], len: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u128;
        while !data.is_empty() {
            let n = (128 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 128 {
                let block = self.buf;
                Self::compress(&mut self.h, &block);
                self.len = 0;
            }
        }
    }

    fn finalize(mut self) -> Vec<u8> {
        let bits = self.total * 8;
        let mut pad = vec![0x80u8];
        let rem = (self.len + 1) % 128;
        let zeros = if rem <= 112 { 112 - rem } else { 240 - rem };
        pad.extend(std::iter::repeat(0).take(zeros));
        pad.extend_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        self.h.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    len: usize,
    total: u64,
}

impl Sha256 {
    fn compress(h: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for (t, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(block[t * 4..t * 4 + 4].try_into().unwrap());
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[t]).wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
}

impl Hash for Sha256 {
    const BLOCK: usize = 64;
    const OUT: usize = 32;

    fn new() -> Self {
        Sha256 { h: H256, buf: [0; 64], len: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let n = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 64 {
                let block = self.buf;
                Self::compress(&mut self.h, &block);
                self.len = 0;
            }
        }
    }

    fn finalize(mut self) -> Vec<u8> {
        let bits = self.total * 8;
        let mut pad = vec![0x80u8];
        let rem = (self.len + 1) % 64;
        let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
        pad.extend(std::iter::repeat(0).take(zeros));
        pad.extend_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        self.h.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

/// HMAC with precomputed inner/outer states.
#[derive(Clone)]
pub struct Hmac<H: Hash> {
    inner: H,
    outer: H,
}

impl<H: Hash> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = vec![0u8; H::BLOCK];
        if key.len() > H::BLOCK {
            let d = H::digest(&[key]);
            k[..d.len()].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = H::new();
        inner.update(&ipad);
        let mut outer = H::new();
        outer.update(&opad);
        Hmac { inner, outer }
    }

    pub fn mac(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut i = self.inner.clone();
        for p in parts {
            i.update(p);
        }
        let ih = i.finalize();
        let mut o = self.outer.clone();
        o.update(&ih);
        o.finalize()
    }
}
