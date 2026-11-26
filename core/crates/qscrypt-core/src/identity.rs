//! QsCrypt identities ("contacts"): an X25519 key and an ML-KEM-768 key to
//! receive files (hybrid: secure as long as either holds, including against
//! a future quantum computer), and an Ed25519 key to sign them.
//!
//! The public half travels as a contact card: `QSID1:` + base45, so a QR
//! code in alphanumeric mode carries it. The secret half never leaves the
//! phone (the app keeps it wrapped by the Android Keystore).

use crate::crypto::Backend;
use crate::error::{Error, Result};
use crate::util::{base45_decode, base45_encode, crc32, Secret};

pub const X25519_LEN: usize = 32;
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_DK_LEN: usize = 2400;
pub const ED25519_LEN: usize = 32;
pub const CARD_PREFIX: &str = "QSID1:";
const MAX_NAME: usize = 64;

pub const X25519_BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub name: String,
    pub x25519: [u8; 32],
    pub mlkem: Vec<u8>,
    pub ed25519: [u8; 32],
}

pub struct SecretIdentity {
    pub public: PublicIdentity,
    x25519: Secret,
    mlkem: Secret,
    ed25519: Secret,
}

fn clamp_name(name: &str) -> String {
    let mut n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    while n.len() > MAX_NAME {
        n.pop();
    }
    n
}

impl PublicIdentity {
    fn body(&self) -> Vec<u8> {
        let name = self.name.as_bytes();
        let mut b = Vec::with_capacity(2 + name.len() + 32 + 32 + MLKEM_EK_LEN + 4);
        b.push(1);
        b.push(name.len() as u8);
        b.extend_from_slice(name);
        b.extend_from_slice(&self.x25519);
        b.extend_from_slice(&self.ed25519);
        b.extend_from_slice(&self.mlkem);
        let c = crc32(&b);
        b.extend_from_slice(&c.to_le_bytes());
        b
    }

    /// The contact card text (what the QR code holds).
    pub fn card(&self) -> String {
        format!("{CARD_PREFIX}{}", base45_encode(&self.body()))
    }

    pub fn parse_card(text: &str) -> Result<PublicIdentity> {
        let t = text.trim();
        let rest = t.strip_prefix(CARD_PREFIX).ok_or_else(|| Error::invalid("not a QsCrypt contact card"))?;
        let b = base45_decode(rest).ok_or_else(|| Error::invalid("damaged contact card"))?;
        PublicIdentity::from_body(&b)
    }

    fn from_body(b: &[u8]) -> Result<PublicIdentity> {
        let bad = || Error::invalid("damaged contact card");
        if b.len() < 6 || b[0] != 1 {
            return Err(bad());
        }
        let n = b[1] as usize;
        let need = 2 + n + 32 + 32 + MLKEM_EK_LEN + 4;
        if b.len() != need || crc32(&b[..need - 4]) != u32::from_le_bytes(b[need - 4..].try_into().unwrap()) {
            return Err(bad());
        }
        let name = String::from_utf8(b[2..2 + n].to_vec()).map_err(|_| bad())?;
        let p = 2 + n;
        Ok(PublicIdentity {
            name,
            x25519: b[p..p + 32].try_into().unwrap(),
            ed25519: b[p + 32..p + 64].try_into().unwrap(),
            mlkem: b[p + 64..p + 64 + MLKEM_EK_LEN].to_vec(),
        })
    }

    /// Identifies the keys (not the name).
    pub fn fingerprint(&self, backend: &dyn Backend) -> [u8; 32] {
        backend.sha256(&[b"QsCrypt identity v1", &self.x25519, &self.mlkem, &self.ed25519])
    }

    /// Thirty digits in six groups, to compare aloud or side by side.
    pub fn safety_number(&self, backend: &dyn Backend) -> String {
        let f = self.fingerprint(backend);
        (0..6)
            .map(|g| {
                let v = u64::from_le_bytes([f[g * 5], f[g * 5 + 1], f[g * 5 + 2], f[g * 5 + 3], f[g * 5 + 4], 0, 0, 0]);
                format!("{:05}", v % 100_000)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl SecretIdentity {
    pub fn generate(backend: &dyn Backend, name: &str) -> Result<SecretIdentity> {
        let mut x = Secret::new(32);
        backend.fill_random(&mut x)?;
        let mut ed = Secret::new(32);
        backend.fill_random(&mut ed)?;
        let (dk, ek) = backend.mlkem768_keygen()?;
        let public = PublicIdentity {
            name: clamp_name(name),
            x25519: backend.x25519(x[..].try_into().unwrap(), &X25519_BASE)?,
            mlkem: ek,
            ed25519: backend.ed25519_public(ed[..].try_into().unwrap())?,
        };
        Ok(SecretIdentity { public, x25519: x, mlkem: Secret::from_slice(&dk), ed25519: ed })
    }

    /// Serialized secret keys (with the public ones): wrap before storing.
    pub fn to_bytes(&self) -> Secret {
        let body = self.public.body();
        let mut out = Secret::new(4 + body.len() + 32 + MLKEM_DK_LEN + 32);
        out[..4].copy_from_slice(b"QSK1");
        let mut p = 4;
        out[p..p + body.len()].copy_from_slice(&body);
        p += body.len();
        out[p..p + 32].copy_from_slice(&self.x25519);
        out[p + 32..p + 32 + MLKEM_DK_LEN].copy_from_slice(&self.mlkem);
        out[p + 32 + MLKEM_DK_LEN..].copy_from_slice(&self.ed25519);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<SecretIdentity> {
        let bad = || Error::corrupt("damaged identity");
        if b.len() < 6 || &b[..4] != b"QSK1" {
            return Err(bad());
        }
        let n = b[5] as usize;
        let body_len = 2 + n + 32 + 32 + MLKEM_EK_LEN + 4;
        if b.len() != 4 + body_len + 32 + MLKEM_DK_LEN + 32 {
            return Err(bad());
        }
        let public = PublicIdentity::from_body(&b[4..4 + body_len]).map_err(|_| bad())?;
        let p = 4 + body_len;
        Ok(SecretIdentity {
            public,
            x25519: Secret::from_slice(&b[p..p + 32]),
            mlkem: Secret::from_slice(&b[p + 32..p + 32 + MLKEM_DK_LEN]),
            ed25519: Secret::from_slice(&b[p + 32 + MLKEM_DK_LEN..]),
        })
    }

    pub fn rename(&mut self, name: &str) {
        self.public.name = clamp_name(name);
    }

    pub(crate) fn x25519_secret(&self) -> &[u8; 32] {
        self.x25519[..].try_into().unwrap()
    }

    pub(crate) fn mlkem_secret(&self) -> &[u8] {
        &self.mlkem
    }

    pub fn sign(&self, backend: &dyn Backend, msg: &[u8]) -> Result<[u8; 64]> {
        backend.ed25519_sign(self.ed25519[..].try_into().unwrap(), msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;

    #[test]
    fn cards_round_trip() {
        let b = RefBackend::with_fakes();
        let id = SecretIdentity::generate(&b, "  أحمد\u{7}  ").unwrap();
        assert_eq!(id.public.name, "أحمد");
        let card = id.public.card();
        assert!(card.starts_with(CARD_PREFIX));
        assert!(card.bytes().all(|c| b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".contains(&c)), "QR alphanumeric only");
        let back = PublicIdentity::parse_card(&card).unwrap();
        assert_eq!(back, id.public);
        assert_eq!(back.safety_number(&b).len(), 35);
        let mut damaged = card.clone().into_bytes();
        let i = damaged.len() - 9;
        damaged[i] = if damaged[i] == b'A' { b'B' } else { b'A' };
        assert!(PublicIdentity::parse_card(std::str::from_utf8(&damaged).unwrap()).is_err());
        let s = id.to_bytes();
        let again = SecretIdentity::from_bytes(&s).unwrap();
        assert_eq!(again.public, id.public);
        assert_eq!(again.sign(&b, b"m").unwrap(), id.sign(&b, b"m").unwrap());
    }
}
