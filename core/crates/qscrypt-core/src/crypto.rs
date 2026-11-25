//! The primitive interface. The engine never implements production crypto
//! itself: a `Backend` supplies hashing, block ciphers, KDFs, the AEAD and
//! randomness. `qscrypt-crypto` provides the RustCrypto-based backend.

use crate::error::Result;
use std::sync::atomic::AtomicBool;

/// A 128-bit block cipher with a fixed key.
pub trait BlockCipher: Send + Sync {
    /// Encrypts consecutive 16-byte blocks in place (`data.len() % 16 == 0`).
    fn encrypt_blocks(&self, data: &mut [u8]);
    /// Decrypts consecutive 16-byte blocks in place (`data.len() % 16 == 0`).
    fn decrypt_blocks(&self, data: &mut [u8]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherKind {
    Aes,
    Serpent,
    Twofish,
}

impl CipherKind {
    pub fn name(self) -> &'static str {
        match self {
            CipherKind::Aes => "AES",
            CipherKind::Serpent => "Serpent",
            CipherKind::Twofish => "Twofish",
        }
    }
}

/// Pseudo-random functions VeraCrypt and TrueCrypt use for PBKDF2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prf {
    Sha512,
    Sha256,
    Whirlpool,
    Ripemd160,
}

impl Prf {
    pub const ALL: [Prf; 4] = [Prf::Sha512, Prf::Sha256, Prf::Whirlpool, Prf::Ripemd160];

    pub fn output_len(self) -> usize {
        match self {
            Prf::Sha512 | Prf::Whirlpool => 64,
            Prf::Sha256 => 32,
            Prf::Ripemd160 => 20,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Prf::Sha512 => "SHA-512",
            Prf::Sha256 => "SHA-256",
            Prf::Whirlpool => "Whirlpool",
            Prf::Ripemd160 => "RIPEMD-160",
        }
    }

    /// Stable numeric id shared with the apps (0 means "auto").
    pub fn id(self) -> u32 {
        match self {
            Prf::Sha512 => 1,
            Prf::Sha256 => 2,
            Prf::Whirlpool => 3,
            Prf::Ripemd160 => 4,
        }
    }

    pub fn from_id(id: u32) -> Option<Prf> {
        Prf::ALL.into_iter().find(|p| p.id() == id)
    }
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;

    fn has_prf(&self, prf: Prf) -> bool;

    fn has_cipher(&self, cipher: CipherKind) -> bool;

    /// Computes PBKDF2 output block `index` (1-based, RFC 8018 `T_i`) and
    /// writes its first `out.len()` bytes (at most the PRF output length).
    /// Must return `Error::Cancelled` soon after `cancel` becomes true.
    #[allow(clippy::too_many_arguments)]
    fn pbkdf2_block(
        &self,
        prf: Prf,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        index: u32,
        out: &mut [u8],
        cancel: &AtomicBool,
    ) -> Result<()>;

    /// HMAC-SHA-512 over the concatenation of `parts`.
    fn hmac_sha512(&self, key: &[u8], parts: &[&[u8]]) -> [u8; 64];

    /// SHA-256 over the concatenation of `parts`.
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32];

    fn cipher(&self, kind: CipherKind, key: &[u8; 32]) -> Result<Box<dyn BlockCipher>>;

    /// Cryptographically secure random bytes from the operating system.
    fn fill_random(&self, out: &mut [u8]) -> Result<()>;

    /// Argon2id (version 0x13).
    fn argon2id(
        &self,
        password: &[u8],
        salt: &[u8],
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
        out: &mut [u8],
    ) -> Result<()>;

    /// XChaCha20-Poly1305 encryption in place; returns the 16-byte tag.
    fn xchacha_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 16]>;

    /// XChaCha20-Poly1305 decryption in place. `Error::Tampered` on a bad tag.
    fn xchacha_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()>;
}

/// CTR keystream over a block cipher: XORs `data` with E(prefix || counter),
/// counter is a big-endian u64 starting at `first_counter`.
pub fn ctr_xor(cipher: &dyn BlockCipher, prefix: &[u8; 8], first_counter: u64, data: &mut [u8]) {
    const BATCH: usize = 4096;
    let mut ks = vec![0u8; BATCH.min(data.len().div_ceil(16) * 16)];
    let mut counter = first_counter;
    for chunk in data.chunks_mut(BATCH) {
        let blocks = chunk.len().div_ceil(16);
        let ks = &mut ks[..blocks * 16];
        for (i, blk) in ks.chunks_exact_mut(16).enumerate() {
            blk[..8].copy_from_slice(prefix);
            blk[8..].copy_from_slice(&(counter + i as u64).to_be_bytes());
        }
        cipher.encrypt_blocks(ks);
        crate::util::xor_into(chunk, ks);
        counter += blocks as u64;
    }
}
