//! QsCrypt engine core.
//!
//! Everything in this crate is dependency-free logic:
//! - `vc`: VeraCrypt / TrueCrypt volume headers, detection, creation and
//!   sector-level encryption,
//! - `fs`: FAT12/16/32 (read/write) and exFAT (read) file systems,
//! - `qsc`: the QsCrypt file format,
//! - `crypto`: the trait through which all primitives are supplied.
//!
//! The production backend lives in the `qscrypt-crypto` crate.

pub mod bde;
pub mod crypto;
pub mod disk;
pub mod error;
pub mod fs;
pub mod identity;
pub mod json;
pub mod kdf;
pub mod part;
pub mod stego;
pub mod qsc;
pub mod qsc2;
pub mod qvol;
pub mod usb;
pub mod util;
pub mod vc;
pub mod xts;

#[cfg(any(test, feature = "reference"))]
pub mod reference;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_like() {
        let parts: Vec<&str> = version().split('.').collect();
        assert_eq!(parts.len(), 3, "expected MAJOR.MINOR.PATCH, got {}", version());
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    }
}
