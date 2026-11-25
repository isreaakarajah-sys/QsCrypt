use super::Ea;
use crate::crypto::Backend;
use crate::error::{Error, Result};
use crate::xts::Xts;

/// The XTS layers of an encryption algorithm, keyed from a key buffer laid
/// out as VeraCrypt does: all primary keys, then all secondary keys.
pub struct CipherChain {
    ea: Ea,
    layers: Vec<Xts>,
}

impl CipherChain {
    pub fn new(backend: &dyn Backend, ea: Ea, key: &[u8]) -> Result<CipherChain> {
        let n = ea.ciphers().len();
        if key.len() < 64 * n {
            return Err(Error::invalid("key material too short"));
        }
        let mut layers = Vec::with_capacity(n);
        for (i, &kind) in ea.ciphers().iter().enumerate() {
            let k1: &[u8; 32] = key[32 * i..32 * i + 32].try_into().unwrap();
            let k2: &[u8; 32] = key[32 * (n + i)..32 * (n + i) + 32].try_into().unwrap();
            layers.push(Xts::new(backend.cipher(kind, k1)?, backend.cipher(kind, k2)?));
        }
        Ok(CipherChain { ea, layers })
    }

    pub fn ea(&self) -> Ea {
        self.ea
    }

    pub fn encrypt(&self, buf: &mut [u8], unit_size: usize, first_unit: u64) {
        for layer in &self.layers {
            layer.encrypt(buf, unit_size, first_unit);
        }
    }

    pub fn decrypt(&self, buf: &mut [u8], unit_size: usize, first_unit: u64) {
        for layer in self.layers.iter().rev() {
            layer.decrypt(buf, unit_size, first_unit);
        }
    }
}
