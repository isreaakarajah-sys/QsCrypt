//! The 512-byte volume header.
//!
//! ```text
//! 0    64  salt (plaintext)
//! 64    4  "VERA" / "TRUE"            -- everything below is encrypted
//! 68    2  header version (BE)
//! 70    2  minimum program version (BE)
//! 72    4  CRC-32 of bytes 256..512
//! 76   16  reserved (TrueCrypt: creation / modification times)
//! 92    8  hidden volume size (0 for a normal volume)
//! 100   8  volume size
//! 108   8  byte offset of the encrypted area
//! 116   8  size of the encrypted area
//! 124   4  flags (bit 0: system encryption)
//! 128   4  sector size
//! 132 120  reserved
//! 252   4  CRC-32 of bytes 64..252
//! 256 256  master keys: primary key(s) then secondary key(s)
//! ```

use super::Format;
use crate::util::{be16, be32, be64, crc32, put_be16, put_be32, put_be64, Secret};

pub const HEADER_SIZE: usize = 512;
pub const SALT_SIZE: usize = 64;
/// Size of the encrypted part (header bytes 64..512).
pub const ENC_SIZE: usize = 448;

// Offsets inside the decrypted 448-byte area.
const MAGIC: usize = 0;
const VERSION: usize = 4;
const REQUIRED: usize = 6;
const KEY_CRC: usize = 8;
const HIDDEN_SIZE: usize = 28;
const VOLUME_SIZE: usize = 36;
const DATA_OFFSET: usize = 44;
const DATA_SIZE: usize = 52;
const FLAGS: usize = 60;
const SECTOR_SIZE: usize = 64;
const HEADER_CRC: usize = 188;
const KEYS: usize = 192;

#[derive(Clone, Debug)]
pub struct PlainHeader {
    pub format: Format,
    pub version: u16,
    pub required_version: u16,
    pub hidden_volume_size: u64,
    pub volume_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
    pub flags: u32,
    pub sector_size: u32,
    /// 256 bytes: primary master key(s), then secondary key(s).
    pub master_keys: Secret,
}

impl PlainHeader {
    /// Parses a decrypted 448-byte area; `None` unless the magic and both
    /// CRCs match (which is how a wrong password is detected).
    pub fn parse(dec: &[u8]) -> Option<PlainHeader> {
        debug_assert_eq!(dec.len(), ENC_SIZE);
        let format = match &dec[MAGIC..MAGIC + 4] {
            b"VERA" => Format::VeraCrypt,
            b"TRUE" => Format::TrueCrypt,
            _ => return None,
        };
        if crc32(&dec[KEYS..ENC_SIZE]) != be32(dec, KEY_CRC) {
            return None;
        }
        let version = be16(dec, VERSION);
        // Header CRC exists since header version 4.
        if version >= 4 && crc32(&dec[..HEADER_CRC]) != be32(dec, HEADER_CRC) {
            return None;
        }
        Some(PlainHeader {
            format,
            version,
            required_version: be16(dec, REQUIRED),
            hidden_volume_size: be64(dec, HIDDEN_SIZE),
            volume_size: be64(dec, VOLUME_SIZE),
            data_offset: be64(dec, DATA_OFFSET),
            data_size: be64(dec, DATA_SIZE),
            flags: be32(dec, FLAGS),
            sector_size: be32(dec, SECTOR_SIZE),
            master_keys: Secret::from_slice(&dec[KEYS..ENC_SIZE]),
        })
    }

    pub fn serialize(&self) -> Secret {
        let mut h = Secret::new(ENC_SIZE);
        h[MAGIC..MAGIC + 4].copy_from_slice(self.format.magic());
        put_be16(&mut h, VERSION, self.version);
        put_be16(&mut h, REQUIRED, self.required_version);
        put_be64(&mut h, HIDDEN_SIZE, self.hidden_volume_size);
        put_be64(&mut h, VOLUME_SIZE, self.volume_size);
        put_be64(&mut h, DATA_OFFSET, self.data_offset);
        put_be64(&mut h, DATA_SIZE, self.data_size);
        put_be32(&mut h, FLAGS, self.flags);
        put_be32(&mut h, SECTOR_SIZE, self.sector_size);
        h[KEYS..ENC_SIZE].copy_from_slice(&self.master_keys[..256]);
        let key_crc = crc32(&h[KEYS..ENC_SIZE]);
        put_be32(&mut h, KEY_CRC, key_crc);
        let header_crc = crc32(&h[..HEADER_CRC]);
        put_be32(&mut h, HEADER_CRC, header_crc);
        h
    }

    pub fn is_system(&self) -> bool {
        self.flags & 1 != 0
    }
}
