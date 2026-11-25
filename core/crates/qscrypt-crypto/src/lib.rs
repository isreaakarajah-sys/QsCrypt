//! The production `Backend`: audited RustCrypto implementations, with the
//! hardware AES instructions (ARMv8 Crypto Extensions, AES-NI) picked at
//! run time by the `aes` crate.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use qscrypt_core::crypto::{Backend, BlockCipher, CipherKind, Prf};
use qscrypt_core::{Error, Result};
use sha2::{Digest, Sha256, Sha512};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct RustCrypto;

impl RustCrypto {
    pub fn new() -> RustCrypto {
        RustCrypto
    }
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps any 128-bit RustCrypto block cipher.
struct Rc<C>(C);

fn as_blocks(data: &mut [u8]) -> &mut [GenericArray<u8, U16>] {
    assert!(data.len() % 16 == 0, "whole blocks only");
    // SAFETY: GenericArray<u8, U16> has the size (16) and alignment (1) of
    // [u8; 16]; the slice covers exactly data.len() / 16 such blocks.
    unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut GenericArray<u8, U16>, data.len() / 16) }
}

impl<C> BlockCipher for Rc<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + Send + Sync,
{
    fn encrypt_blocks(&self, data: &mut [u8]) {
        self.0.encrypt_blocks(as_blocks(data));
    }

    fn decrypt_blocks(&self, data: &mut [u8]) {
        self.0.decrypt_blocks(as_blocks(data));
    }
}

fn pbkdf2_block<M>(password: &[u8], salt: &[u8], iterations: u32, index: u32, out: &mut [u8], cancel: &AtomicBool) -> Result<()>
where
    M: Mac + KeyInit + Clone,
{
    let prf = <M as Mac>::new_from_slice(password).map_err(|_| Error::Crypto("HMAC key".into()))?;
    let mut mac = prf.clone();
    Mac::update(&mut mac, salt);
    Mac::update(&mut mac, &index.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut t = u.clone();
    for k in 1..iterations {
        let mut mac = prf.clone();
        Mac::update(&mut mac, &u);
        u = mac.finalize().into_bytes();
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
        if k % 4096 == 0 && cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
    }
    let n = out.len().min(t.len());
    out[..n].copy_from_slice(&t[..n]);
    for b in t.iter_mut().chain(u.iter_mut()) {
        // SAFETY: valid exclusive reference; volatile keeps the wipe.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    Ok(())
}

impl Backend for RustCrypto {
    fn name(&self) -> &'static str {
        "rustcrypto"
    }

    fn has_prf(&self, _prf: Prf) -> bool {
        true
    }

    fn has_cipher(&self, _cipher: CipherKind) -> bool {
        true
    }

    fn pbkdf2_block(
        &self,
        prf: Prf,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        index: u32,
        out: &mut [u8],
        cancel: &AtomicBool,
    ) -> Result<()> {
        match prf {
            Prf::Sha512 => pbkdf2_block::<Hmac<Sha512>>(password, salt, iterations, index, out, cancel),
            Prf::Sha256 => pbkdf2_block::<Hmac<Sha256>>(password, salt, iterations, index, out, cancel),
            Prf::Whirlpool => pbkdf2_block::<Hmac<whirlpool::Whirlpool>>(password, salt, iterations, index, out, cancel),
            Prf::Ripemd160 => pbkdf2_block::<Hmac<ripemd::Ripemd160>>(password, salt, iterations, index, out, cancel),
        }
    }

    fn hmac_sha512(&self, key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
        for p in parts {
            Mac::update(&mut mac, p);
        }
        let out = mac.finalize().into_bytes();
        let mut r = [0u8; 64];
        r.copy_from_slice(&out);
        r
    }

    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            Digest::update(&mut h, p);
        }
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        r
    }

    fn cipher(&self, kind: CipherKind, key: &[u8; 32]) -> Result<Box<dyn BlockCipher>> {
        let bad = |_| Error::Crypto(format!("{} key", kind.name()));
        Ok(match kind {
            CipherKind::Aes => Box::new(Rc(aes::Aes256::new_from_slice(key).map_err(bad)?)),
            CipherKind::Serpent => Box::new(Rc(serpent::Serpent::new_from_slice(key).map_err(bad)?)),
            CipherKind::Twofish => Box::new(Rc(twofish::Twofish::new_from_slice(key).map_err(bad)?)),
        })
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<()> {
        getrandom::getrandom(out).map_err(|e| Error::Crypto(format!("system RNG: {e}")))
    }

    fn argon2id(&self, password: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, lanes: u32, out: &mut [u8]) -> Result<()> {
        let params = argon2::Params::new(memory_kib, iterations, lanes, Some(out.len())).map_err(|e| Error::Crypto(format!("Argon2 parameters: {e}")))?;
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(password, salt, out)
            .map_err(|e| Error::Crypto(format!("Argon2: {e}")))
    }

    fn xchacha_seal(&self, key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16]> {
        let c = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        let tag = c.encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf).map_err(|_| Error::Crypto("XChaCha20-Poly1305 seal".into()))?;
        let mut t = [0u8; 16];
        t.copy_from_slice(&tag);
        Ok(t)
    }

    fn xchacha_open(&self, key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> Result<()> {
        let c = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        c.decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf, Tag::from_slice(tag)).map_err(|_| Error::Tampered)
    }
}
