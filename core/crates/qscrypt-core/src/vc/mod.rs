//! VeraCrypt and TrueCrypt volumes.
//!
//! Layout of a file-hosted volume (VeraCrypt "VolumeLayoutV2"):
//!
//! ```text
//! 0        normal volume header (512 bytes, rest of the 64 KiB is random)
//! 65536    hidden volume header (random if there is no hidden volume)
//! 131072   encrypted data area
//! S-131072 backup normal header
//! S-65536  backup hidden header
//! ```

mod chain;
mod create;
mod detect;
mod header;
pub mod keyfile;
mod maintain;
pub mod selftest;
mod volume;

pub use chain::CipherChain;
pub use create::{create_container, create_volume, max_hidden_size, CreateOptions, HiddenOptions, MIN_HIDDEN_SIZE, MIN_SIZE};
pub use detect::{detect, OpenOptions, OpenedHeader};
pub use keyfile::apply_keyfiles;
pub use maintain::{backup_headers, change_password, hidden_range, repair_from_embedded, restore_from_file, Credentials};
pub use header::{PlainHeader, ENC_SIZE, HEADER_SIZE, SALT_SIZE};
pub use volume::EncVolume;

use crate::crypto::{CipherKind, Prf};

pub const HIDDEN_HEADER_OFFSET: u64 = 65_536;
pub const DATA_OFFSET: u64 = 131_072;
pub const HEADER_GROUP: u64 = 131_072;
/// Unit size XTS uses for the data area, regardless of the sector size.
pub const UNIT: u64 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    VeraCrypt,
    TrueCrypt,
}

impl Format {
    pub fn magic(self) -> &'static [u8; 4] {
        match self {
            Format::VeraCrypt => b"VERA",
            Format::TrueCrypt => b"TRUE",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::VeraCrypt => "VeraCrypt",
            Format::TrueCrypt => "TrueCrypt",
        }
    }

    /// PBKDF2 iteration count for a non-system volume.
    pub fn iterations(self, prf: Prf, pim: u32) -> u32 {
        match self {
            Format::VeraCrypt if pim > 0 => 15_000 + pim * 1_000,
            Format::VeraCrypt => match prf {
                Prf::Ripemd160 => 655_331,
                _ => 500_000,
            },
            Format::TrueCrypt => match prf {
                Prf::Ripemd160 => 2_000,
                _ => 1_000,
            },
        }
    }

    pub fn prfs(self) -> &'static [Prf] {
        match self {
            Format::VeraCrypt => &[Prf::Sha512, Prf::Sha256, Prf::Whirlpool, Prf::Ripemd160],
            Format::TrueCrypt => &[Prf::Sha512, Prf::Ripemd160, Prf::Whirlpool],
        }
    }
}

/// Encryption algorithms (single ciphers and cascades) in XTS mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ea {
    Aes,
    Serpent,
    Twofish,
    AesTwofish,
    AesTwofishSerpent,
    SerpentAes,
    SerpentTwofishAes,
    TwofishSerpent,
}

impl Ea {
    pub const ALL: [Ea; 8] = [
        Ea::Aes,
        Ea::Serpent,
        Ea::Twofish,
        Ea::AesTwofish,
        Ea::AesTwofishSerpent,
        Ea::SerpentAes,
        Ea::SerpentTwofishAes,
        Ea::TwofishSerpent,
    ];

    /// Ciphers in VeraCrypt's internal order: keys are assigned in this
    /// order, encryption applies them first to last and decryption last to
    /// first. The display name lists them in reverse ("AES-Twofish" is
    /// Twofish first, then AES).
    pub fn ciphers(self) -> &'static [CipherKind] {
        use CipherKind::*;
        match self {
            Ea::Aes => &[Aes],
            Ea::Serpent => &[Serpent],
            Ea::Twofish => &[Twofish],
            Ea::AesTwofish => &[Twofish, Aes],
            Ea::AesTwofishSerpent => &[Serpent, Twofish, Aes],
            Ea::SerpentAes => &[Aes, Serpent],
            Ea::SerpentTwofishAes => &[Aes, Twofish, Serpent],
            Ea::TwofishSerpent => &[Serpent, Twofish],
        }
    }

    /// Bytes of primary key material (the XTS secondary keys follow).
    pub fn key_size(self) -> usize {
        32 * self.ciphers().len()
    }

    pub fn name(self) -> &'static str {
        match self {
            Ea::Aes => "AES",
            Ea::Serpent => "Serpent",
            Ea::Twofish => "Twofish",
            Ea::AesTwofish => "AES-Twofish",
            Ea::AesTwofishSerpent => "AES-Twofish-Serpent",
            Ea::SerpentAes => "Serpent-AES",
            Ea::SerpentTwofishAes => "Serpent-Twofish-AES",
            Ea::TwofishSerpent => "Twofish-Serpent",
        }
    }

    /// Stable numeric id shared with the apps.
    pub fn id(self) -> u32 {
        Ea::ALL.iter().position(|e| *e == self).unwrap() as u32 + 1
    }

    pub fn from_id(id: u32) -> Option<Ea> {
        Ea::ALL.into_iter().find(|e| e.id() == id)
    }
}

#[cfg(test)]
mod tests;
