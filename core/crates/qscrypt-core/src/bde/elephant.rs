//! The Elephant diffuser (Ferguson 2006) used by BitLocker's AES-CBC
//! "with diffuser" methods (Vista / Windows 7). Words are little-endian.

const RA: [u32; 4] = [9, 0, 13, 0];
const RB: [u32; 4] = [0, 10, 0, 25];

fn words(sector: &[u8]) -> Vec<u32> {
    sector.chunks_exact(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect()
}

fn store(sector: &mut [u8], d: &[u32]) {
    for (c, w) in sector.chunks_exact_mut(4).zip(d) {
        c.copy_from_slice(&w.to_le_bytes());
    }
}

pub fn a_decrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..5 {
        for i in 0..n {
            d[i] = d[i].wrapping_add(d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(RA[i % 4]));
        }
    }
}

pub fn a_encrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..5 {
        for i in (0..n).rev() {
            d[i] = d[i].wrapping_sub(d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(RA[i % 4]));
        }
    }
}

pub fn b_decrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..3 {
        for i in 0..n {
            d[i] = d[i].wrapping_add(d[(i + 2) % n] ^ d[(i + 5) % n].rotate_left(RB[i % 4]));
        }
    }
}

pub fn b_encrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..3 {
        for i in (0..n).rev() {
            d[i] = d[i].wrapping_sub(d[(i + 2) % n] ^ d[(i + 5) % n].rotate_left(RB[i % 4]));
        }
    }
}

/// After AES-CBC decryption of one sector: diffuser B, diffuser A, sector key.
pub fn undo(sector: &mut [u8], sector_key: &[u8; 32]) {
    let mut d = words(sector);
    b_decrypt(&mut d);
    a_decrypt(&mut d);
    store(sector, &d);
    for (i, b) in sector.iter_mut().enumerate() {
        *b ^= sector_key[i % 32];
    }
}

/// Before AES-CBC encryption of one sector: sector key, diffuser A, diffuser B.
pub fn apply(sector: &mut [u8], sector_key: &[u8; 32]) {
    for (i, b) in sector.iter_mut().enumerate() {
        *b ^= sector_key[i % 32];
    }
    let mut d = words(sector);
    a_encrypt(&mut d);
    b_encrypt(&mut d);
    store(sector, &d);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffusers_invert() {
        let orig: Vec<u8> = (0..512u32).map(|i| (i * 89 % 256) as u8).collect();
        let key = [0x5Au8; 32];
        let mut s = orig.clone();
        apply(&mut s, &key);
        assert_ne!(s, orig);
        undo(&mut s, &key);
        assert_eq!(s, orig);
        // One flipped bit spreads over the whole sector.
        let mut a = orig.clone();
        let mut b = orig.clone();
        b[100] ^= 1;
        let mut da = words(&a);
        let mut db = words(&b);
        a_decrypt(&mut da);
        a_decrypt(&mut db);
        b_decrypt(&mut da);
        b_decrypt(&mut db);
        store(&mut a, &da);
        store(&mut b, &db);
        let differing = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        assert!(differing > 400, "{differing}");
    }
}
