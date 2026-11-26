//! Pure-Rust reference backend for tests and cross-checks.
//!
//! Real primitives: SHA-512, SHA-256, HMAC, PBKDF2, AES-256.
//! `RefBackend::with_fakes()` additionally stands in Twofish, Serpent,
//! Argon2id and XChaCha20-Poly1305 with AES/HMAC-based substitutes so the
//! format logic can be exercised offline. The fakes are NOT those
//! algorithms; only the production backend implements them.

pub mod aes;
mod sha_consts;
pub mod sha2;

use crate::crypto::{ctr_xor, Backend, BlockCipher, CipherKind, Prf};
use crate::error::{Error, Result};
use sha2::{Hash, Hmac, Sha256, Sha512};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct RefBackend {
    fakes: bool,
}

const X25519_BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

impl RefBackend {
    pub fn new() -> RefBackend {
        RefBackend { fakes: false }
    }

    pub fn with_fakes() -> RefBackend {
        RefBackend { fakes: true }
    }
}

impl Default for RefBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn pbkdf2_block_generic<H: Hash>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    index: u32,
    out: &mut [u8],
    cancel: &AtomicBool,
) -> Result<()> {
    let mac = Hmac::<H>::new(password);
    let mut u = mac.mac(&[salt, &index.to_be_bytes()]);
    let mut t = u.clone();
    for k in 1..iterations {
        u = mac.mac(&[&u]);
        crate::util::xor_into(&mut t, &u);
        if k % 2048 == 0 && cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
    }
    let n = out.len().min(t.len());
    out[..n].copy_from_slice(&t[..n]);
    Ok(())
}

fn derive_fake_key(kind: CipherKind, key: &[u8; 32]) -> [u8; 32] {
    let d = Sha256::digest(&[kind.name().as_bytes(), key]);
    d.try_into().unwrap()
}

impl Backend for RefBackend {
    fn name(&self) -> &'static str {
        if self.fakes {
            "reference+fakes"
        } else {
            "reference"
        }
    }

    fn has_prf(&self, prf: Prf) -> bool {
        matches!(prf, Prf::Sha512 | Prf::Sha256)
    }

    fn has_cipher(&self, cipher: CipherKind) -> bool {
        cipher == CipherKind::Aes || self.fakes
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
            Prf::Sha512 => pbkdf2_block_generic::<Sha512>(password, salt, iterations, index, out, cancel),
            Prf::Sha256 => pbkdf2_block_generic::<Sha256>(password, salt, iterations, index, out, cancel),
            other => Err(Error::unsupported(other.name())),
        }
    }

    fn hmac_sha512(&self, key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        Hmac::<Sha512>::new(key).mac(parts).try_into().unwrap()
    }

    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        Sha256::digest(parts).try_into().unwrap()
    }

    fn cipher(&self, kind: CipherKind, key: &[u8; 32]) -> Result<Box<dyn BlockCipher>> {
        match kind {
            CipherKind::Aes => Ok(Box::new(aes::Aes256::new(key))),
            _ if self.fakes => Ok(Box::new(aes::Aes256::new(&derive_fake_key(kind, key)))),
            other => Err(Error::unsupported(other.name())),
        }
    }

    fn aes128(&self, key: &[u8; 16]) -> Result<Box<dyn BlockCipher>> {
        Ok(Box::new(aes::Aes256::new128(key)))
    }

    fn sha512(&self, parts: &[&[u8]]) -> [u8; 64] {
        Sha512::digest(parts).try_into().unwrap()
    }

    // The fakes below have the algebraic shape the formats rely on (shared
    // secrets agree, signatures verify) and nothing else. Never secure.

    fn x25519(&self, scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32]> {
        if !self.fakes {
            return Err(Error::unsupported("X25519"));
        }
        // "public key" = the scalar itself; DH = hash of the unordered pair.
        if *point == X25519_BASE {
            return Ok(*scalar);
        }
        let (a, b) = if scalar <= point { (scalar, point) } else { (point, scalar) };
        Ok(Sha256::digest(&[b"fake x25519", a, b]).try_into().unwrap())
    }

    fn mlkem768_keygen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.fakes {
            return Err(Error::unsupported("ML-KEM-768"));
        }
        let mut seed = vec![0u8; 1184];
        self.fill_random(&mut seed)?;
        let mut dk = vec![0u8; 2400];
        dk[..1184].copy_from_slice(&seed);
        Ok((dk, seed))
    }

    fn mlkem768_encapsulate(&self, ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        if !self.fakes || ek.len() != 1184 {
            return Err(Error::unsupported("ML-KEM-768"));
        }
        let mut ct = vec![0u8; 1088];
        self.fill_random(&mut ct)?;
        let ss = Sha256::digest(&[b"fake mlkem", ek, &ct]).try_into().unwrap();
        Ok((ct, ss))
    }

    fn mlkem768_decapsulate(&self, dk: &[u8], ct: &[u8]) -> Result<[u8; 32]> {
        if !self.fakes || dk.len() != 2400 || ct.len() != 1088 {
            return Err(Error::unsupported("ML-KEM-768"));
        }
        Ok(Sha256::digest(&[b"fake mlkem", &dk[..1184], ct]).try_into().unwrap())
    }

    fn ed25519_public(&self, seed: &[u8; 32]) -> Result<[u8; 32]> {
        if !self.fakes {
            return Err(Error::unsupported("Ed25519"));
        }
        Ok(*seed)
    }

    fn ed25519_sign(&self, seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64]> {
        if !self.fakes {
            return Err(Error::unsupported("Ed25519"));
        }
        Ok(self.hmac_sha512(seed, &[msg]))
    }

    fn ed25519_verify(&self, public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        self.fakes && crate::util::ct_eq(&self.hmac_sha512(public, &[msg]), sig)
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<()> {
        std::fs::File::open("/dev/urandom")?.read_exact(out)?;
        Ok(())
    }

    fn argon2id(&self, password: &[u8], salt: &[u8], m: u32, t: u32, p: u32, out: &mut [u8]) -> Result<()> {
        if !self.fakes {
            return Err(Error::unsupported("Argon2id"));
        }
        let mut s = salt.to_vec();
        s.extend_from_slice(&[m.to_le_bytes(), t.to_le_bytes(), p.to_le_bytes()].concat());
        crate::kdf::pbkdf2(self, Prf::Sha512, password, &s, 2, out, &AtomicBool::new(false))
    }

    fn xchacha_seal(&self, key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16]> {
        if !self.fakes {
            return Err(Error::unsupported("XChaCha20-Poly1305"));
        }
        let c = aes::Aes256::new(key);
        ctr_xor(&c, nonce[16..24].try_into().unwrap(), u64::from_le_bytes(nonce[..8].try_into().unwrap()), buf);
        let tag = self.hmac_sha512(key, &[nonce, aad, &(aad.len() as u64).to_le_bytes(), buf]);
        Ok(tag[..16].try_into().unwrap())
    }

    fn xchacha_open(&self, key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> Result<()> {
        if !self.fakes {
            return Err(Error::unsupported("XChaCha20-Poly1305"));
        }
        let expect = self.hmac_sha512(key, &[nonce, aad, &(aad.len() as u64).to_le_bytes(), buf]);
        if !crate::util::ct_eq(&expect[..16], tag) {
            return Err(Error::Tampered);
        }
        let c = aes::Aes256::new(key);
        ctr_xor(&c, nonce[16..24].try_into().unwrap(), u64::from_le_bytes(nonce[..8].try_into().unwrap()), buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xts::Xts;

    include!("../../../../testdata/vectors.rs");

    #[test]
    fn sha2_vectors() {
        for (i, m) in v::HASH_MSGS.iter().enumerate() {
            assert_eq!(Sha512::digest(&[m]), v::SHA512[i], "sha512 msg {i}");
            assert_eq!(Sha256::digest(&[m]), v::SHA256[i], "sha256 msg {i}");
        }
        // Split updates must agree with one-shot hashing.
        let m = v::HASH_MSGS[3];
        let mut h = Sha512::new();
        for part in m.chunks(37) {
            h.update(part);
        }
        assert_eq!(h.finalize(), v::SHA512[3]);
    }

    #[test]
    fn hmac_vectors() {
        let b = RefBackend::new();
        assert_eq!(b.hmac_sha512(v::HMAC_KEY_SHORT, &[v::HMAC_MSG]).to_vec(), v::HMAC_SHA512_SHORT);
        assert_eq!(b.hmac_sha512(v::HMAC_KEY_LONG, &[v::HMAC_MSG]).to_vec(), v::HMAC_SHA512_LONG);
    }

    #[test]
    fn pbkdf2_vectors() {
        let b = RefBackend::new();
        let none = AtomicBool::new(false);
        for (prf, cases) in [
            (Prf::Sha512, [(1, v::PBKDF2_SHA512_1), (2, v::PBKDF2_SHA512_2), (1000, v::PBKDF2_SHA512_1000)]),
            (Prf::Sha256, [(1, v::PBKDF2_SHA256_1), (2, v::PBKDF2_SHA256_2), (1000, v::PBKDF2_SHA256_1000)]),
        ] {
            for (iters, expect) in cases {
                let mut out = vec![0u8; 192];
                crate::kdf::pbkdf2(&b, prf, v::PBKDF2_PW, v::PBKDF2_SALT, iters, &mut out, &none).unwrap();
                assert_eq!(out, expect, "{prf:?} x{iters}");
                // A truncated request is a prefix of the full output.
                let mut short = vec![0u8; 70];
                crate::kdf::pbkdf2(&b, prf, v::PBKDF2_PW, v::PBKDF2_SALT, iters, &mut short, &none).unwrap();
                assert_eq!(short, expect[..70]);
            }
        }
    }

    #[test]
    fn aes_fips197() {
        let c = aes::Aes256::new(v::AES_KEY.try_into().unwrap());
        let mut b: [u8; 16] = v::AES_PT.try_into().unwrap();
        c.encrypt_block(&mut b);
        assert_eq!(&b, v::AES_CT);
        c.decrypt_block(&mut b);
        assert_eq!(&b, v::AES_PT);
    }

    fn xts() -> Xts {
        Xts::new(
            Box::new(aes::Aes256::new(v::XTS_K1.try_into().unwrap())),
            Box::new(aes::Aes256::new(v::XTS_K2.try_into().unwrap())),
        )
    }

    #[test]
    fn xts_vectors() {
        let x = xts();
        let mut buf = v::XTS_PT.to_vec();
        x.encrypt(&mut buf, 512, 256);
        assert_eq!(buf, v::XTS_CT_UNIT_256);
        x.decrypt(&mut buf, 512, 256);
        assert_eq!(buf, v::XTS_PT);

        let mut hdr = v::XTS_PT[..448].to_vec();
        x.encrypt(&mut hdr, 512, 0);
        assert_eq!(hdr, v::XTS_CT_448_UNIT_0);

        let mut big = v::XTS_PT[..512].to_vec();
        x.encrypt(&mut big, 512, v::XTS_BIG_UNIT);
        assert_eq!(big, v::XTS_CT_BIG_UNIT);
    }

    #[test]
    fn hkdf_vector() {
        let b = RefBackend::new();
        let mut out = vec![0u8; 160];
        crate::kdf::hkdf_sha512(&b, v::HKDF_SALT, v::HKDF_IKM, v::HKDF_INFO, &mut out).unwrap();
        assert_eq!(out, v::HKDF_OUT);
    }

    #[test]
    fn fake_aead_round_trip() {
        let b = RefBackend::with_fakes();
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let mut buf = b"hello world".to_vec();
        let tag = b.xchacha_seal(&key, &nonce, b"aad", &mut buf).unwrap();
        assert_ne!(buf, b"hello world");
        b.xchacha_open(&key, &nonce, b"aad", &mut buf, &tag).unwrap();
        assert_eq!(buf, b"hello world");
        let mut bad = buf.clone();
        let tag2 = b.xchacha_seal(&key, &nonce, b"aad", &mut bad).unwrap();
        bad[0] ^= 1;
        assert!(matches!(b.xchacha_open(&key, &nonce, b"aad", &mut bad, &tag2), Err(Error::Tampered)));
    }
}
