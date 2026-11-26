//! BitLocker Drive Encryption (Windows 7 and later, including BitLocker To
//! Go), following the libbde format documentation and cryptsetup's BITLK
//! implementation.
//!
//! A volume keeps three copies of its FVE metadata (each in a 64 KiB area
//! guarded by a CRC-32 and, once the VMK is known, an AES-CCM sealed SHA-256).
//! Key protectors ("VMK" entries) wrap the 256-bit volume master key with
//! AES-CCM under a key stretched from the password or recovery password;
//! the VMK wraps the full volume encryption key (FVEK).
//!
//! The decrypted view, as Windows presents it: the first `header_size`
//! bytes come from an encrypted copy stored at `header_offset`, the
//! metadata areas and that copy read as zeros, everything else is
//! decrypted in place (AES-XTS by sector number, AES-CBC with the IV
//! E(K, byte offset), optionally with the Elephant diffuser).

pub mod ccm;
mod create;
pub mod elephant;

pub use create::{create_bitlocker, generate_recovery_password, BdeCreateOptions};

use crate::crypto::{Backend, BlockCipher};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{crc32, guid_string, le16, le32, le64, Secret};
use crate::xts::Xts;
use std::sync::atomic::{AtomicBool, Ordering};

pub const GUID_BDE: [u8; 16] = [0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01];
pub const GUID_EOW: [u8; 16] = [0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8];
/// Each metadata copy owns a 64 KiB area.
pub const META_AREA: u64 = 65536;
const STRETCH_ROUNDS: u64 = 0x10_0000;
const STATE_NORMAL: u16 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Cbc128Diffuser,
    Cbc256Diffuser,
    Cbc128,
    Cbc256,
    Xts128,
    Xts256,
}

impl Method {
    pub fn from_id(id: u16) -> Option<Method> {
        Some(match id {
            0x8000 => Method::Cbc128Diffuser,
            0x8001 => Method::Cbc256Diffuser,
            0x8002 => Method::Cbc128,
            0x8003 => Method::Cbc256,
            0x8004 => Method::Xts128,
            0x8005 => Method::Xts256,
            _ => return None,
        })
    }

    pub fn id(self) -> u16 {
        match self {
            Method::Cbc128Diffuser => 0x8000,
            Method::Cbc256Diffuser => 0x8001,
            Method::Cbc128 => 0x8002,
            Method::Cbc256 => 0x8003,
            Method::Xts128 => 0x8004,
            Method::Xts256 => 0x8005,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Cbc128Diffuser => "AES-CBC 128 + Elephant",
            Method::Cbc256Diffuser => "AES-CBC 256 + Elephant",
            Method::Cbc128 => "AES-CBC 128",
            Method::Cbc256 => "AES-CBC 256",
            Method::Xts128 => "XTS-AES 128",
            Method::Xts256 => "XTS-AES 256",
        }
    }

    /// Length of the key data in the decrypted FVEK.
    fn key_data_len(self) -> usize {
        match self {
            Method::Cbc128 => 16,
            Method::Cbc256 | Method::Xts128 => 32,
            Method::Cbc128Diffuser | Method::Cbc256Diffuser | Method::Xts256 => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    ClearKey,
    Tpm,
    StartupKey,
    TpmPin,
    Recovery,
    Password,
    SmartCard,
    Other(u16),
}

impl Protection {
    fn from_id(v: u16) -> Protection {
        match v {
            0x0000 => Protection::ClearKey,
            0x0100 => Protection::Tpm,
            0x0200 => Protection::StartupKey,
            0x0500 => Protection::TpmPin,
            0x0800 => Protection::Recovery,
            0x1000 => Protection::SmartCard,
            0x2000 => Protection::Password,
            o => Protection::Other(o),
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Protection::ClearKey => "clear_key",
            Protection::Tpm => "tpm",
            Protection::StartupKey => "startup_key",
            Protection::TpmPin => "tpm_pin",
            Protection::Recovery => "recovery_password",
            Protection::Password => "password",
            Protection::SmartCard => "smart_card",
            Protection::Other(_) => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Sealed {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub data: Vec<u8>,
}

impl Sealed {
    fn parse(value: &[u8]) -> Option<Sealed> {
        if value.len() < 28 {
            return None;
        }
        Some(Sealed { nonce: value[..12].try_into().unwrap(), tag: value[12..28].try_into().unwrap(), data: value[28..].to_vec() })
    }

    /// Decrypts with an AES-256 key; returns the key datum's key data
    /// (after its 12-byte header) once its size field checks out.
    pub fn open_key(&self, backend: &dyn Backend, key: &[u8; 32]) -> Result<Secret> {
        let c = backend.cipher(crate::crypto::CipherKind::Aes, key)?;
        let mut plain = Secret::from_slice(&self.data);
        ccm::open(c.as_ref(), &self.nonce, &[], &mut plain, &self.tag)?;
        if plain.len() < 12 || le16(&plain, 0) as usize != plain.len() {
            return Err(Error::corrupt("BitLocker key datum size"));
        }
        Ok(Secret::from_slice(&plain[12..]))
    }
}

#[derive(Clone, Debug)]
pub struct Protector {
    pub guid: String,
    pub protection: Protection,
    salt: Option<[u8; 16]>,
    vmk: Option<Sealed>,
    clear_key: Option<Secret>,
}

pub struct Info {
    pub togo: bool,
    pub eow: bool,
    pub sector_size: u32,
    pub method: Method,
    pub volume_guid: String,
    pub description: String,
    /// Unix time.
    pub created: i64,
    pub volume_size: u64,
    pub metadata: [u64; 3],
    pub header_offset: u64,
    pub header_size: u64,
    pub state: (u16, u16),
    pub protectors: Vec<Protector>,
    fvek: Sealed,
    validation: Option<Sealed>,
    block_hash: [u8; 32],
}

/// True if this boot sector belongs to a BitLocker volume.
pub fn is_bitlocker(boot: &[u8]) -> bool {
    boot.len() >= 512 && (&boot[3..11] == b"-FVE-FS-" || (&boot[3..11] == b"MSWIN4.1" && boot[424..440] == GUID_BDE))
}

fn filetime_to_unix(ft: u64) -> i64 {
    (ft as i64 - 116_444_736_000_000_000) / 10_000_000
}

fn utf16z(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// (entry type, value type, value bytes) of each entry in `data`.
fn entries(data: &[u8]) -> Vec<(u16, u16, &[u8])> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 8 <= data.len() {
        let size = le16(data, p) as usize;
        if size < 8 || p + size > data.len() {
            break;
        }
        out.push((le16(data, p + 2), le16(data, p + 4), &data[p + 8..p + size]));
        p += size;
    }
    out
}

/// Reads and checks the volume header and the first valid metadata copy.
pub fn read_info(backend: &dyn Backend, disk: &mut dyn Disk) -> Result<Info> {
    let mut boot = [0u8; 512];
    disk.read_at(0, &mut boot)?;
    if !is_bitlocker(&boot) {
        return Err(Error::corrupt("not a BitLocker volume"));
    }
    let togo = &boot[3..11] == b"MSWIN4.1";
    if boot[..3] == [0xEB, 0x52, 0x90] {
        return Err(Error::unsupported("BitLocker from Windows Vista"));
    }
    let sector_size = match le16(&boot, 11) {
        0 => 512,
        s @ (512 | 4096) => s as u32,
        s => return Err(Error::unsupported(format!("BitLocker sector size {s}"))),
    };
    let base = if togo { 424 } else { 160 };
    let guid: [u8; 16] = boot[base..base + 16].try_into().unwrap();
    let eow = guid == GUID_EOW;
    if guid != GUID_BDE && !eow {
        return Err(Error::unsupported("unknown BitLocker variant"));
    }
    let offsets = [le64(&boot, base + 16), le64(&boot, base + 24), le64(&boot, base + 32)];
    let size = disk.len();

    let mut chosen = None;
    for (i, &mo) in offsets.iter().enumerate() {
        if mo == 0 || mo + META_AREA > size {
            continue;
        }
        let mut area = vec![0u8; META_AREA as usize];
        if disk.read_at(mo, &mut area).is_err() {
            continue;
        }
        if &area[..8] != b"-FVE-FS-" || le16(&area, 10) != 2 {
            continue;
        }
        let real = (le16(&area, 8) as usize) << 4;
        if real < 112 || real + 8 > area.len() {
            continue;
        }
        let vsize = le16(&area, real) as usize;
        let vver = le16(&area, real + 2);
        if vsize < 8 || vver > 2 || crc32(&area[..real]) != le32(&area, real + 4) {
            continue;
        }
        if le64(&area, 32 + 8 * i) != mo {
            continue;
        }
        chosen = Some((area, real));
        break;
    }
    let (area, real) = chosen.ok_or_else(|| Error::corrupt("no valid BitLocker metadata copy"))?;
    let block_hash = backend.sha256(&[&area[..real]]);

    let msize = le32(&area, 64) as usize;
    if msize < 48 || 64 + msize > real {
        return Err(Error::corrupt("BitLocker metadata size"));
    }
    let method_id = le16(&area, 100);
    let method = Method::from_id(method_id).ok_or_else(|| Error::unsupported(format!("BitLocker encryption method 0x{method_id:04X}")))?;
    let mut info = Info {
        togo,
        eow,
        sector_size,
        method,
        volume_guid: guid_string(&area[80..96]),
        description: String::new(),
        created: filetime_to_unix(le64(&area, 104)),
        volume_size: le64(&area, 16),
        metadata: [le64(&area, 32), le64(&area, 40), le64(&area, 48)],
        header_offset: le64(&area, 56),
        header_size: le32(&area, 28) as u64 * sector_size as u64,
        state: (le16(&area, 12), le16(&area, 14)),
        protectors: Vec::new(),
        fvek: Sealed { nonce: [0; 12], tag: [0; 16], data: Vec::new() },
        validation: None,
        block_hash,
    };

    // Validation: header, then a nested AES-CCM datum (sealed with the VMK).
    let vsize = le16(&area, real) as usize;
    if vsize >= 88 && real + 88 <= area.len() && le16(&area, real + 8) == 80 && le16(&area, real + 12) == 5 {
        info.validation = Sealed::parse(&area[real + 16..real + 88]);
    }

    let mut have_fvek = false;
    for (ety, vty, value) in entries(&area[112..64 + msize]) {
        match (ety, vty) {
            (0x0002, 0x0008) if value.len() >= 28 => {
                let mut p = Protector { guid: guid_string(&value[..16]), protection: Protection::from_id(le16(value, 26)), salt: None, vmk: None, clear_key: None };
                for (_, pv, pval) in entries(&value[28..]) {
                    match pv {
                        0x0003 if pval.len() >= 20 => p.salt = Some(pval[4..20].try_into().unwrap()),
                        0x0005 => p.vmk = Sealed::parse(pval),
                        0x0001 if pval.len() >= 4 + 32 => p.clear_key = Some(Secret::from_slice(&pval[4..])),
                        _ => {}
                    }
                }
                info.protectors.push(p);
            }
            (0x0003, 0x0005) if !have_fvek => {
                info.fvek = Sealed::parse(value).ok_or_else(|| Error::corrupt("BitLocker FVEK entry"))?;
                have_fvek = true;
            }
            (0x000F, 0x000F) if value.len() >= 16 => {
                info.header_offset = le64(value, 0);
                info.header_size = le64(value, 8);
            }
            (0x0007, 0x0002) if info.description.is_empty() => info.description = utf16z(value),
            _ => {}
        }
    }
    if !have_fvek {
        return Err(Error::corrupt("BitLocker metadata without FVEK"));
    }
    if info.header_size == 0 || info.header_size % sector_size as u64 != 0 || info.header_offset + info.header_size > size {
        return Err(Error::corrupt("BitLocker volume header location"));
    }
    Ok(info)
}

/// What the user typed.
pub enum Credential<'a> {
    Password(&'a str),
    /// 48 digits, with or without dashes; Arabic-Indic digits accepted.
    Recovery(&'a str),
    /// Only a clear key (BitLocker suspended) can open it.
    None,
}

/// The 16-byte key a recovery password stands for, or `None` if it is not
/// a valid recovery password (each group of six divisible by 11 and below
/// 720896).
pub fn parse_recovery(s: &str) -> Option<[u8; 16]> {
    let digits: Vec<u32> = s
        .chars()
        .filter_map(|c| match c {
            '0'..='9' => Some(c as u32 - '0' as u32),
            '\u{0660}'..='\u{0669}' => Some(c as u32 - 0x0660),
            '\u{06F0}'..='\u{06F9}' => Some(c as u32 - 0x06F0),
            '-' | ' ' | '\u{2013}' | '_' => None,
            _ => Some(99),
        })
        .collect();
    if digits.len() != 48 || digits.contains(&99) {
        return None;
    }
    let mut key = [0u8; 16];
    for g in 0..8 {
        let v = digits[g * 6..g * 6 + 6].iter().fold(0u32, |a, d| a * 10 + d);
        if v % 11 != 0 || v >= 720_896 {
            return None;
        }
        key[2 * g..2 * g + 2].copy_from_slice(&((v / 11) as u16).to_le_bytes());
    }
    Some(key)
}

/// BitLocker's key stretching: 2^20 rounds of SHA-256 over
/// (last, initial, salt, counter).
pub fn stretch(backend: &dyn Backend, initial: &[u8; 32], salt: &[u8; 16], cancel: &AtomicBool) -> Result<[u8; 32]> {
    let mut st = [0u8; 88];
    st[32..64].copy_from_slice(initial);
    st[64..80].copy_from_slice(salt);
    for i in 0..STRETCH_ROUNDS {
        st[80..88].copy_from_slice(&i.to_le_bytes());
        let h = backend.sha256(&[&st]);
        st[..32].copy_from_slice(&h);
        if i & 0xFFFF == 0 && cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
    }
    let out: [u8; 32] = st[..32].try_into().unwrap();
    crate::util::wipe(&mut st);
    Ok(out)
}

pub fn password_initial(backend: &dyn Backend, password: &str) -> [u8; 32] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let h = backend.sha256(&[&utf16]);
    backend.sha256(&[&h])
}

pub fn recovery_initial(backend: &dyn Backend, key: &[u8; 16]) -> [u8; 32] {
    backend.sha256(&[key])
}

/// The unlocked keys of a volume.
pub struct Keys {
    pub method: Method,
    pub vmk: Secret,
    pub fvek: Secret,
    /// Which protector opened it.
    pub protection: Protection,
}

/// Unlocks with a clear key if there is one, else with the credential.
pub fn unlock(backend: &dyn Backend, info: &Info, cred: &Credential, cancel: &AtomicBool) -> Result<Keys> {
    let mut found: Option<(Secret, Protection)> = None;
    let mut tried = false;
    for p in &info.protectors {
        let Some(sealed) = &p.vmk else { continue };
        let key: Option<[u8; 32]> = match (p.protection, cred) {
            (Protection::ClearKey, _) => p.clear_key.as_ref().and_then(|k| k[..32].try_into().ok()),
            (Protection::Password, Credential::Password(pw)) => {
                tried = true;
                let Some(salt) = p.salt else { continue };
                Some(stretch(backend, &password_initial(backend, pw), &salt, cancel)?)
            }
            (Protection::Recovery, Credential::Recovery(rp) | Credential::Password(rp)) => {
                let Some(rk) = parse_recovery(rp) else { continue };
                tried = true;
                let Some(salt) = p.salt else { continue };
                Some(stretch(backend, &recovery_initial(backend, &rk), &salt, cancel)?)
            }
            _ => None,
        };
        let Some(key) = key else { continue };
        if let Ok(vmk) = sealed.open_key(backend, &key) {
            if vmk.len() >= 32 {
                found = Some((Secret::from_slice(&vmk[..32]), p.protection));
                break;
            }
        }
    }
    let Some((vmk, protection)) = found else {
        if !tried && !matches!(cred, Credential::None) && info.protectors.iter().all(|p| !matches!(p.protection, Protection::Password | Protection::Recovery)) {
            return Err(Error::unsupported("this BitLocker volume opens only with a TPM, startup key or smart card"));
        }
        return Err(Error::WrongPassword);
    };
    let vmk32: [u8; 32] = vmk[..32].try_into().unwrap();

    if let Some(v) = &info.validation {
        let c = backend.cipher(crate::crypto::CipherKind::Aes, &vmk32)?;
        let mut plain = v.data.clone();
        ccm::open(c.as_ref(), &v.nonce, &[], &mut plain, &v.tag).map_err(|_| Error::corrupt("BitLocker metadata validation"))?;
        if plain.len() < 44 || le16(&plain, 2) != 0 || le16(&plain, 4) != 1 || le16(&plain, 8) != 0x2005 || plain[12..44] != info.block_hash {
            return Err(Error::Tampered);
        }
    }

    let key = info.fvek.open_key(backend, &vmk32)?;
    if key.len() < info.method.key_data_len() {
        return Err(Error::corrupt("BitLocker FVEK length"));
    }
    Ok(Keys { method: info.method, vmk, fvek: Secret::from_slice(&key[..info.method.key_data_len()]), protection })
}

enum Engine {
    Xts(Xts),
    Cbc { fvek: Box<dyn BlockCipher>, tweak: Option<Box<dyn BlockCipher>> },
}

fn aes(backend: &dyn Backend, key: &[u8]) -> Result<Box<dyn BlockCipher>> {
    match key.len() {
        16 => backend.aes128(key.try_into().unwrap()),
        32 => backend.cipher(crate::crypto::CipherKind::Aes, key.try_into().unwrap()),
        _ => Err(Error::corrupt("AES key length")),
    }
}

impl Engine {
    fn new(backend: &dyn Backend, method: Method, key: &[u8]) -> Result<Engine> {
        Ok(match method {
            Method::Xts128 => Engine::Xts(Xts::new(aes(backend, &key[..16])?, aes(backend, &key[16..32])?)),
            Method::Xts256 => Engine::Xts(Xts::new(aes(backend, &key[..32])?, aes(backend, &key[32..64])?)),
            Method::Cbc128 => Engine::Cbc { fvek: aes(backend, &key[..16])?, tweak: None },
            Method::Cbc256 => Engine::Cbc { fvek: aes(backend, &key[..32])?, tweak: None },
            Method::Cbc128Diffuser => Engine::Cbc { fvek: aes(backend, &key[..16])?, tweak: Some(aes(backend, &key[32..48])?) },
            Method::Cbc256Diffuser => Engine::Cbc { fvek: aes(backend, &key[..32])?, tweak: Some(aes(backend, &key[32..64])?) },
        })
    }

    fn offset_block(offset: u64) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&offset.to_le_bytes());
        b
    }

    fn sector_key(tweak: &dyn BlockCipher, offset: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&Self::offset_block(offset));
        k[16..].copy_from_slice(&Self::offset_block(offset));
        k[31] = 0x80;
        tweak.encrypt_blocks(&mut k);
        k
    }

    /// `buf` holds whole sectors starting at physical byte `offset`.
    fn decrypt(&self, buf: &mut [u8], ss: usize, offset: u64) {
        match self {
            Engine::Xts(x) => x.decrypt(buf, ss, offset / ss as u64),
            Engine::Cbc { fvek, tweak } => {
                for (i, sector) in buf.chunks_exact_mut(ss).enumerate() {
                    let off = offset + (i * ss) as u64;
                    let mut iv = Self::offset_block(off);
                    fvek.encrypt_blocks(&mut iv);
                    let mut prev = iv;
                    for blk in sector.chunks_exact_mut(16) {
                        let c: [u8; 16] = blk.try_into().unwrap();
                        fvek.decrypt_blocks(blk);
                        for k in 0..16 {
                            blk[k] ^= prev[k];
                        }
                        prev = c;
                    }
                    if let Some(t) = tweak {
                        elephant::undo(sector, &Self::sector_key(t.as_ref(), off));
                    }
                }
            }
        }
    }

    fn encrypt(&self, buf: &mut [u8], ss: usize, offset: u64) {
        match self {
            Engine::Xts(x) => x.encrypt(buf, ss, offset / ss as u64),
            Engine::Cbc { fvek, tweak } => {
                for (i, sector) in buf.chunks_exact_mut(ss).enumerate() {
                    let off = offset + (i * ss) as u64;
                    if let Some(t) = tweak {
                        elephant::apply(sector, &Self::sector_key(t.as_ref(), off));
                    }
                    let mut iv = Self::offset_block(off);
                    fvek.encrypt_blocks(&mut iv);
                    let mut prev = iv;
                    for blk in sector.chunks_exact_mut(16) {
                        for k in 0..16 {
                            blk[k] ^= prev[k];
                        }
                        fvek.encrypt_blocks(blk);
                        prev.copy_from_slice(blk);
                    }
                }
            }
        }
    }
}

/// The decrypted volume as a `Disk`.
pub struct BdeVolume {
    disk: Box<dyn Disk>,
    engine: Engine,
    ss: u64,
    size: u64,
    header_offset: u64,
    header_size: u64,
    /// Physical regions shown as zeros: metadata areas, the header copy.
    zero: Vec<(u64, u64)>,
    read_only: bool,
}

const IO: usize = 1 << 20;

impl BdeVolume {
    pub fn new(backend: &dyn Backend, disk: Box<dyn Disk>, info: &Info, keys: &Keys, read_only: bool) -> Result<BdeVolume> {
        if info.state != (STATE_NORMAL, STATE_NORMAL) {
            return Err(Error::unsupported("BitLocker encryption or decryption is in progress; let Windows finish it first"));
        }
        let mut zero: Vec<(u64, u64)> = info.metadata.iter().map(|&m| (m, m + META_AREA)).collect();
        zero.push((info.header_offset, info.header_offset + info.header_size));
        zero.sort();
        let size = disk.len();
        // Encrypt-on-Write volumes track which blocks are encrypted; writing
        // without updating that map would corrupt them, so they open read-only.
        let read_only = read_only || disk.is_read_only() || info.eow;
        Ok(BdeVolume {
            engine: Engine::new(backend, keys.method, &keys.fvek)?,
            ss: info.sector_size as u64,
            size,
            header_offset: info.header_offset,
            header_size: info.header_size,
            zero,
            disk,
            read_only,
        })
    }

    /// Physical regions the file system must never allocate (for `reserve`).
    pub fn reserved_regions(&self) -> Vec<(u64, u64)> {
        self.zero.clone()
    }

    /// Where logical sector-aligned `pos` lives, and how many bytes of the
    /// same kind follow: (physical offset, is zero region, run length).
    fn map(&self, pos: u64) -> (u64, bool, u64) {
        if pos < self.header_size {
            return (self.header_offset + pos, false, self.header_size - pos);
        }
        for &(s, e) in &self.zero {
            if pos >= s && pos < e {
                return (pos, true, e - pos);
            }
        }
        let next = self.zero.iter().map(|z| z.0).filter(|&s| s > pos).min().unwrap_or(self.size);
        (pos, false, next - pos)
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(e) if e <= self.size => Ok(()),
            _ => Err(Error::invalid("access beyond the end of the BitLocker volume")),
        }
    }

    fn read_sectors(&mut self, pos: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let p = pos + done as u64;
            let (phys, zero, run) = self.map(p);
            let n = (run as usize).min(buf.len() - done).min(IO);
            let chunk = &mut buf[done..done + n];
            if zero {
                chunk.fill(0);
            } else {
                self.disk.read_at(phys, chunk)?;
                self.engine.decrypt(chunk, self.ss as usize, phys);
            }
            done += n;
        }
        Ok(())
    }

    fn write_sectors(&mut self, pos: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let p = pos + done as u64;
            let (phys, zero, run) = self.map(p);
            let n = (run as usize).min(buf.len() - done).min(IO);
            if zero {
                if buf[done..done + n].iter().any(|&b| b != 0) {
                    return Err(Error::corrupt("write into BitLocker metadata area refused"));
                }
            } else {
                let chunk = &mut buf[done..done + n];
                self.engine.encrypt(chunk, self.ss as usize, phys);
                self.disk.write_at(phys, chunk)?;
            }
            done += n;
        }
        Ok(())
    }
}

impl Disk for BdeVolume {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        let ss = self.ss;
        let first = offset / ss * ss;
        let end = (offset + buf.len() as u64).div_ceil(ss) * ss;
        if first == offset && end == offset + buf.len() as u64 {
            return self.read_sectors(offset, buf);
        }
        let mut tmp = vec![0u8; (end - first) as usize];
        self.read_sectors(first, &mut tmp)?;
        let s = (offset - first) as usize;
        buf.copy_from_slice(&tmp[s..s + buf.len()]);
        crate::util::wipe(&mut tmp);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check(offset, buf.len())?;
        let ss = self.ss;
        let first = offset / ss * ss;
        let end = (offset + buf.len() as u64).div_ceil(ss) * ss;
        let mut tmp = vec![0u8; (end - first) as usize];
        if first != offset || end != offset + buf.len() as u64 {
            self.read_sectors(first, &mut tmp[..ss as usize])?;
            let last = tmp.len() - ss as usize;
            if last > 0 {
                let mut t = vec![0u8; ss as usize];
                self.read_sectors(end - ss, &mut t)?;
                tmp[last..].copy_from_slice(&t);
            }
        }
        let s = (offset - first) as usize;
        tmp[s..s + buf.len()].copy_from_slice(buf);
        let r = self.write_sectors(first, &mut tmp);
        crate::util::wipe(&mut tmp);
        r
    }

    fn len(&self) -> u64 {
        self.size
    }

    fn flush(&mut self) -> Result<()> {
        self.disk.flush()
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
}

/// Everything needed to open a BitLocker volume in one call.
pub fn open(backend: &dyn Backend, mut disk: Box<dyn Disk>, cred: &Credential, read_only: bool, cancel: &AtomicBool) -> Result<(Info, Keys, BdeVolume)> {
    let info = read_info(backend, disk.as_mut())?;
    let keys = unlock(backend, &info, cred, cancel)?;
    let vol = BdeVolume::new(backend, disk, &info, &keys, read_only)?;
    Ok((info, keys, vol))
}

#[cfg(test)]
mod tests;

/// Research helper for the CI compatibility job: shows what the nested
/// datums of each protector decrypt to, so the creator can mirror Windows.
#[doc(hidden)]
pub mod research {
    use super::*;
    use std::fmt::Write as _;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn try_open(backend: &dyn Backend, key: &[u8; 32], v: &[u8]) -> Option<Vec<u8>> {
        let s = Sealed::parse(v)?;
        let c = backend.cipher(crate::crypto::CipherKind::Aes, key).ok()?;
        let mut p = s.data.clone();
        ccm::open(c.as_ref(), &s.nonce, &[], &mut p, &s.tag).ok()?;
        Some(p)
    }

    pub fn explain(backend: &dyn Backend, disk: &mut dyn Disk, password: &str, recovery: &str) -> Result<String> {
        let info = read_info(backend, disk)?;
        let no = AtomicBool::new(false);
        let keys = unlock(backend, &info, &Credential::Password(password), &no)?;
        let vmk: [u8; 32] = keys.vmk[..32].try_into().unwrap();
        let mut out = String::new();
        writeln!(out, "vmk {}", hex(&vmk)).ok();
        let mut area = vec![0u8; META_AREA as usize];
        disk.read_at(info.metadata[0], &mut area)?;
        let msize = le32(&area, 64) as usize;
        let rk = parse_recovery(recovery);
        for (ety, vty, value) in entries(&area[112..64 + msize]) {
            if (ety, vty) != (2, 8) {
                continue;
            }
            let prot = le16(value, 26);
            writeln!(out, "protector 0x{prot:04x} unknown24=0x{:04x}", le16(value, 24)).ok();
            let mut stretched = None;
            for (pe, pv, pval) in entries(&value[28..]) {
                if pv == 3 {
                    let salt: [u8; 16] = pval[4..20].try_into().unwrap();
                    let initial = if prot == 0x2000 { password_initial(backend, password) } else { recovery_initial(backend, &rk.unwrap_or([0; 16])) };
                    let st = stretch(backend, &initial, &salt, &no)?;
                    writeln!(out, "  stretch method 0x{:08x} initial {} stretched {}", le32(pval, 0), hex(&initial), hex(&st)).ok();
                    if let Some(k) = rk {
                        writeln!(out, "  recovery key {}", hex(&k)).ok();
                    }
                    for (ne, nv, nval) in entries(&pval[20..]) {
                        writeln!(out, "  nested role 0x{ne:04x} value 0x{nv:04x} len {}", nval.len()).ok();
                        if let Some(p) = try_open(backend, &vmk, nval) {
                            writeln!(out, "    with VMK: {}", hex(&p)).ok();
                        }
                        if let Some(p) = try_open(backend, &st, nval) {
                            writeln!(out, "    with stretched: {}", hex(&p)).ok();
                        }
                    }
                    stretched = Some(st);
                } else if pv == 5 {
                    if let Some(st) = stretched {
                        if let Some(p) = try_open(backend, &st, pval) {
                            writeln!(out, "  role 0x{pe:04x} vmk datum header {}", hex(&p[..12])).ok();
                        }
                    }
                } else {
                    writeln!(out, "  property role 0x{pe:04x} value 0x{pv:04x} {}", hex(pval)).ok();
                }
            }
        }
        // FVEK and validation plaintext headers.
        for (ety, vty, value) in entries(&area[112..64 + msize]) {
            if (ety, vty) == (3, 5) {
                if let Some(p) = try_open(backend, &vmk, value) {
                    writeln!(out, "fvek header {}", hex(&p[..12])).ok();
                }
            }
        }
        if let Some(v) = &info.validation {
            let c = backend.cipher(crate::crypto::CipherKind::Aes, &vmk)?;
            let mut p = v.data.clone();
            if ccm::open(c.as_ref(), &v.nonce, &[], &mut p, &v.tag).is_ok() {
                writeln!(out, "validation {}", hex(&p)).ok();
                writeln!(out, "block hash {}", hex(&info.block_hash)).ok();
            }
        }
        Ok(out)
    }
}
