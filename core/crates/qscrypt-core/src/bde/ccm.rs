//! AES-CCM (NIST SP 800-38C / RFC 3610), as BitLocker uses it for keys:
//! 12-byte nonce, 16-byte tag, no associated data, the encrypted tag
//! stored before the ciphertext.

use crate::crypto::BlockCipher;
use crate::error::{Error, Result};
use crate::util::ct_eq;

fn cbc_mac(c: &dyn BlockCipher, nonce: &[u8], aad: &[u8], data: &[u8], tag_len: usize) -> [u8; 16] {
    let l = 15 - nonce.len();
    let mut b0 = [0u8; 16];
    b0[0] = (if aad.is_empty() { 0 } else { 0x40 }) | (((tag_len as u8 - 2) / 2) << 3) | (l as u8 - 1);
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let mut len = data.len() as u64;
    for i in (16 - l..16).rev() {
        b0[i] = len as u8;
        len >>= 8;
    }
    let mut x = b0;
    c.encrypt_blocks(&mut x);
    let absorb = |bytes: &[u8], x: &mut [u8; 16]| {
        for chunk in bytes.chunks(16) {
            for (i, b) in chunk.iter().enumerate() {
                x[i] ^= b;
            }
            c.encrypt_blocks(x);
        }
    };
    if !aad.is_empty() {
        let mut a = Vec::with_capacity(aad.len() + 2);
        a.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        a.extend_from_slice(aad);
        absorb(&a, &mut x);
    }
    absorb(data, &mut x);
    x
}

fn ctr(c: &dyn BlockCipher, nonce: &[u8], data: &mut [u8]) -> [u8; 16] {
    let l = 15 - nonce.len();
    let block = |i: u64| {
        let mut a = [0u8; 16];
        a[0] = l as u8 - 1;
        a[1..1 + nonce.len()].copy_from_slice(nonce);
        let mut n = i;
        for k in (16 - l..16).rev() {
            a[k] = n as u8;
            n >>= 8;
        }
        a
    };
    let mut s0 = block(0);
    c.encrypt_blocks(&mut s0);
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let mut s = block(i as u64 + 1);
        c.encrypt_blocks(&mut s);
        for (b, k) in chunk.iter_mut().zip(s.iter()) {
            *b ^= k;
        }
    }
    s0
}

/// Encrypts `data` in place; returns the encrypted tag (`tag_len` bytes).
pub fn seal(c: &dyn BlockCipher, nonce: &[u8], aad: &[u8], data: &mut [u8], tag_len: usize) -> Vec<u8> {
    debug_assert!((7..=13).contains(&nonce.len()) && (4..=16).contains(&tag_len) && tag_len % 2 == 0);
    let t = cbc_mac(c, nonce, aad, data, tag_len);
    let s0 = ctr(c, nonce, data);
    (0..tag_len).map(|i| t[i] ^ s0[i]).collect()
}

/// Decrypts `data` in place and checks the tag; `Tampered` on mismatch
/// (the buffer is then wiped).
pub fn open(c: &dyn BlockCipher, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Result<()> {
    let s0 = ctr(c, nonce, data);
    let t = cbc_mac(c, nonce, aad, data, tag.len());
    let expect: Vec<u8> = (0..tag.len()).map(|i| t[i] ^ s0[i]).collect();
    if !ct_eq(&expect, tag) {
        crate::util::wipe(data);
        return Err(Error::Tampered);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::aes::Aes256;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn nist_sp800_38c_example_3() {
        let c = Aes256::new128(&h("404142434445464748494a4b4c4d4e4f").try_into().unwrap());
        let nonce = h("101112131415161718191a1b");
        let aad = h("000102030405060708090a0b0c0d0e0f10111213");
        let mut p = h("202122232425262728292a2b2c2d2e2f3031323334353637");
        let tag = seal(&c, &nonce, &aad, &mut p, 8);
        assert_eq!(p, h("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5"));
        assert_eq!(tag, h("484392fbc1b09951"));
        open(&c, &nonce, &aad, &mut p, &tag).unwrap();
        assert_eq!(p, h("202122232425262728292a2b2c2d2e2f3031323334353637"));
        let mut bad = p.clone();
        let t2 = seal(&c, &nonce, &aad, &mut bad, 8);
        bad[0] ^= 1;
        assert!(matches!(open(&c, &nonce, &aad, &mut bad, &t2), Err(Error::Tampered)));
    }

    #[test]
    fn aes128_fips197() {
        let c = Aes256::new128(&h("000102030405060708090a0b0c0d0e0f").try_into().unwrap());
        let mut b: [u8; 16] = h("00112233445566778899aabbccddeeff").try_into().unwrap();
        c.encrypt_block(&mut b);
        assert_eq!(b.to_vec(), h("69c4e0d86a7b0430d8cdb78070b4c55a"));
        c.decrypt_block(&mut b);
        assert_eq!(b.to_vec(), h("00112233445566778899aabbccddeeff"));
    }
}
