//! Runtime self-test against VeraCrypt's own known answers.
//!
//! Reproduces `TestSectorBufEncryption` from VeraCrypt's src/Common/Tests.c:
//! four 512-byte data units holding the IEEE 1619 vector 10-14 plaintext,
//! first unit 0xFFFFFFFFFF - case, primary keys taken row by row from
//! `key1`, secondary keys from `key2` (bytes 0, 1, 2... with the first 32
//! replaced by the pi key). The CRC-32 of the ciphertext must equal the
//! constants VeraCrypt checks at startup. A match proves the cipher byte
//! order, the XTS tweak handling and the cascade order are compatible.

use super::{CipherChain, Ea};
use crate::crypto::Backend;
use crate::error::Result;
use crate::util::crc32;

pub const KEY_E: [u8; 32] = [
    0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59,
    0x57, 0x49, 0x66, 0x96, 0x76, 0x27,
];
pub const KEY_PI: [u8; 32] = [
    0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37, 0x51, 0x05,
    0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
];

/// VeraCrypt's expected CRC-32 per algorithm and test case.
pub const SECTOR_CRCS: [(Ea, [u32; 4]); 8] = [
    (Ea::Aes, [0x888F_2990, 0xEA28_EA34, 0xE058_F5A2, 0x1047_3DC9]),
    (Ea::Serpent, [0x7EDF_ECB3, 0x357B_AAAA, 0xC7B9_FCA5, 0xB526_3E0C]),
    (Ea::Twofish, [0x9152_5124, 0x2895_CC47, 0x6BEE_346D, 0xB1C4_5759]),
    (Ea::AesTwofish, [0x6CEA_7FA2, 0x6905_2C4C, 0x88DB_8DE5, 0xF16F_D8C5]),
    (Ea::AesTwofishSerpent, [0xA2D7_D82A, 0xDBF7_6412, 0xDF0E_A03E, 0xDADE_DFF7]),
    (Ea::SerpentAes, [0x6DD1_33B3, 0x0E57_17D2, 0x39F8_3CD9, 0x8A79_FA2C]),
    (Ea::SerpentTwofishAes, [0xE536_DAF8, 0x3AE8_9E7F, 0x2CC1_301A, 0xCAC7_BDC7]),
    (Ea::TwofishSerpent, [0x2686_C859, 0x8A20_1780, 0x8DD1_3796, 0xE951_96CB]),
];

/// Third primary key row of the test data (three-cipher cascades only),
/// as found in the TrueCrypt sources VeraCrypt inherited it from.
pub const KEY_ROW3: [u8; 32] = [
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
];

/// Primary key rows used by the test (row 0 is all single ciphers need).
pub fn default_key1() -> [u8; 96] {
    let mut k = [0u8; 96];
    k[..32].copy_from_slice(&KEY_E);
    k[32..64].copy_from_slice(&KEY_PI);
    k[64..].copy_from_slice(&KEY_ROW3);
    k
}

pub fn sector_crc(backend: &dyn Backend, ea: Ea, key1: &[u8; 96], case: u64) -> Result<u32> {
    let n = ea.ciphers().len();
    let mut key2 = [0u8; 96];
    for (i, b) in key2.iter_mut().enumerate() {
        *b = i as u8;
    }
    key2[..32].copy_from_slice(&KEY_PI);
    let mut key = vec![0u8; 64 * n];
    key[..32 * n].copy_from_slice(&key1[..32 * n]);
    key[32 * n..].copy_from_slice(&key2[..32 * n]);
    let chain = CipherChain::new(backend, ea, &key)?;
    let mut buf: Vec<u8> = (0..2048usize).map(|i| (i % 256) as u8).collect();
    chain.encrypt(&mut buf, 512, 0xFF_FFFF_FFFF - case);
    let crc = crc32(&buf);
    // Decryption must restore the plaintext too.
    chain.decrypt(&mut buf, 512, 0xFF_FFFF_FFFF - case);
    if !buf.iter().enumerate().all(|(i, &b)| b == (i % 256) as u8) {
        return Ok(!crc);
    }
    Ok(crc)
}

/// (algorithm name, passed) for every algorithm the backend supports.
pub fn run(backend: &dyn Backend, include_cascades: bool) -> Vec<(&'static str, bool)> {
    let key1 = default_key1();
    SECTOR_CRCS
        .iter()
        .filter(|(ea, _)| ea.ciphers().iter().all(|c| backend.has_cipher(*c)))
        .filter(|(ea, _)| include_cascades || ea.ciphers().len() == 1)
        .map(|(ea, crcs)| {
            let ok = (0..4).all(|case| sector_crc(backend, *ea, &key1, case).is_ok_and(|c| c == crcs[case as usize]));
            (ea.name(), ok)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;

    #[test]
    fn aes_matches_veracrypt() {
        let r = run(&RefBackend::new(), false);
        assert_eq!(r, vec![("AES", true)]);
    }
}
