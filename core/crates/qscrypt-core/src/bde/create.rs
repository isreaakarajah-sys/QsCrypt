//! Creating a BitLocker volume (Windows 7+ "-FVE-FS-" layout) with a
//! password protector and a recovery password protector, an exFAT or FAT32
//! file system inside, and the metadata Windows expects: three metadata
//! copies (CRC-32 + VMK-sealed SHA-256 validation), the relocated boot
//! record, and placeholder files in "System Volume Information" that keep
//! the file system away from those areas (as Windows itself does).

use super::{ccm, Engine, Method, GUID_BDE, META_AREA};
use crate::crypto::Backend;
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::fs::{apply_patches, FileSystem, FsChoice};
use crate::util::{crc32, now_unix, put_le16, put_le32, put_le64, Secret};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct BdeCreateOptions<'a> {
    pub password: &'a str,
    /// The 16-byte key of the recovery password; random when `None`.
    pub recovery_key: Option<[u8; 16]>,
    pub method: Method,
    pub filesystem: FsChoice,
    pub label: &'a str,
    /// Description stored in the metadata ("computer, drive, date" on Windows).
    pub description: &'a str,
    /// Only metadata is written; free space keeps its old (now garbage) content.
    pub quick: bool,
}

const HEADER_COPY: u64 = 8192;
const SVI: &str = "/System Volume Information";
const META_NAME: &str = "FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}";
const BOOT_NAME: &str = "FVE2.{24e6f0ae-6a00-4f73-984b-75ce9942852d}";

/// The 48-digit form of a recovery key.
pub fn recovery_string(key: &[u8; 16]) -> String {
    (0..8).map(|g| format!("{:06}", u16::from_le_bytes([key[2 * g], key[2 * g + 1]]) as u32 * 11)).collect::<Vec<_>>().join("-")
}

pub fn generate_recovery_password(backend: &dyn Backend) -> Result<(String, [u8; 16])> {
    let mut k = [0u8; 16];
    backend.fill_random(&mut k)?;
    Ok((recovery_string(&k), k))
}

fn filetime_now() -> u64 {
    (now_unix() as u64) * 10_000_000 + 116_444_736_000_000_000
}

/// Random version-4 GUID in on-disk (mixed-endian) byte order.
fn new_guid(backend: &dyn Backend) -> Result<[u8; 16]> {
    let mut g = [0u8; 16];
    backend.fill_random(&mut g)?;
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    Ok(g)
}

fn entry(ety: u16, vty: u16, value: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8; 8];
    put_le16(&mut e, 0, (8 + value.len()) as u16);
    put_le16(&mut e, 2, ety);
    put_le16(&mut e, 4, vty);
    put_le16(&mut e, 6, 1);
    e.extend_from_slice(value);
    e
}

/// A key datum (as found inside sealed data): header, method, key bytes.
fn key_datum(method: u16, key: &[u8]) -> Secret {
    let mut d = Secret::new(12 + key.len());
    put_le16(&mut d, 0, (12 + key.len()) as u16);
    put_le16(&mut d, 4, 1);
    put_le16(&mut d, 6, 1);
    put_le16(&mut d, 8, method);
    d[12..].copy_from_slice(key);
    d
}

struct Nonces {
    time: u64,
    counter: u32,
}

impl Nonces {
    fn next(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.time.to_le_bytes());
        n[8..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        n
    }
}

/// AES-CCM datum value: nonce, encrypted tag, ciphertext.
fn sealed(backend: &dyn Backend, key: &[u8; 32], nonce: [u8; 12], plain: &[u8]) -> Result<Vec<u8>> {
    let c = backend.cipher(crate::crypto::CipherKind::Aes, key)?;
    let mut data = plain.to_vec();
    let tag = ccm::seal(c.as_ref(), &nonce, &[], &mut data, 16);
    let mut v = nonce.to_vec();
    v.extend_from_slice(&tag);
    v.extend_from_slice(&data);
    crate::util::wipe(&mut data);
    Ok(v)
}

struct Built {
    area: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn build_metadata(
    backend: &dyn Backend,
    opts: &BdeCreateOptions,
    size: u64,
    offsets: [u64; 3],
    header_offset: u64,
    vmk: &[u8; 32],
    fvek_data: &[u8],
    recovery: &[u8; 16],
    cancel: &AtomicBool,
) -> Result<Vec<Built>> {
    let now = filetime_now();
    let mut nonces = Nonces { time: now, counter: 0 };
    let volume_guid = new_guid(backend)?;

    // Description.
    let mut desc: Vec<u8> = opts.description.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    desc.extend_from_slice(&[0, 0]);
    let mut entries = entry(0x0007, 0x0002, &desc);

    // Password protector.
    {
        let mut salt = [0u8; 16];
        backend.fill_random(&mut salt)?;
        let key = super::stretch(backend, &super::password_initial(backend, opts.password), &salt, cancel)?;
        let mut stretch_value = Vec::new();
        stretch_value.extend_from_slice(&0x1001u32.to_le_bytes());
        stretch_value.extend_from_slice(&salt);
        let inner = sealed(backend, vmk, nonces.next(), &key_datum(0x2003, &key))?;
        stretch_value.extend(entry(0x0000, 0x0005, &inner));
        let mut props = entry(0x0000, 0x0003, &stretch_value);
        props.extend(entry(0x0000, 0x0005, &sealed(backend, &key, nonces.next(), &key_datum(0x2003, vmk))?));
        let mut v = new_guid(backend)?.to_vec();
        v.extend_from_slice(&now.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0x2000u16.to_le_bytes());
        v.extend(props);
        entries.extend(entry(0x0002, 0x0008, &v));
    }

    // Recovery password protector.
    {
        let mut salt = [0u8; 16];
        backend.fill_random(&mut salt)?;
        let key = super::stretch(backend, &super::recovery_initial(backend, recovery), &salt, cancel)?;
        let mut stretch_value = Vec::new();
        stretch_value.extend_from_slice(&0x1000u32.to_le_bytes());
        stretch_value.extend_from_slice(&salt);
        stretch_value.extend(entry(0x0012, 0x0005, &sealed(backend, vmk, nonces.next(), &key_datum(0x1000, recovery))?));
        stretch_value.extend(entry(0x0013, 0x0005, &sealed(backend, vmk, nonces.next(), &key_datum(0x2003, &key))?));
        let mut props = entry(0x0000, 0x0003, &stretch_value);
        props.extend(entry(0x0000, 0x0005, &sealed(backend, &key, nonces.next(), &key_datum(0x2003, vmk))?));
        let mut v = new_guid(backend)?.to_vec();
        v.extend_from_slice(&now.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0x0800u16.to_le_bytes());
        v.extend(props);
        entries.extend(entry(0x0002, 0x0008, &v));
    }

    // FVEK, sealed with the VMK.
    entries.extend(entry(0x0003, 0x0005, &sealed(backend, vmk, nonces.next(), &key_datum(opts.method.id(), fvek_data))?));

    // Where the boot record copy is.
    let mut d = vec![0u8; 16];
    put_le64(&mut d, 0, header_offset);
    put_le64(&mut d, 8, HEADER_COPY);
    entries.extend(entry(0x000F, 0x000F, &d));

    let msize = 48 + entries.len();
    let real = (64 + msize).div_ceil(16) * 16;
    if real + 88 > META_AREA as usize {
        return Err(Error::invalid("BitLocker metadata too large"));
    }
    let validation_nonce = {
        let mut n = nonces.next();
        n[7] |= 0x80;
        n
    };
    let next_nonce = nonces.counter;

    let mut out = Vec::new();
    for _ in &offsets {
        let mut a = vec![0u8; META_AREA as usize];
        a[..8].copy_from_slice(b"-FVE-FS-");
        put_le16(&mut a, 8, (real / 16) as u16);
        put_le16(&mut a, 10, 2);
        put_le16(&mut a, 12, 4);
        put_le16(&mut a, 14, 4);
        put_le64(&mut a, 16, size);
        put_le32(&mut a, 28, (HEADER_COPY / 512) as u32);
        for (i, &o) in offsets.iter().enumerate() {
            put_le64(&mut a, 32 + 8 * i, o);
        }
        put_le64(&mut a, 56, header_offset);
        put_le32(&mut a, 64, msize as u32);
        put_le32(&mut a, 68, 1);
        put_le32(&mut a, 72, 48);
        put_le32(&mut a, 76, msize as u32);
        a[80..96].copy_from_slice(&volume_guid);
        put_le32(&mut a, 96, next_nonce);
        put_le16(&mut a, 100, opts.method.id());
        put_le16(&mut a, 102, opts.method.id());
        put_le64(&mut a, 104, now);
        a[112..112 + entries.len()].copy_from_slice(&entries);

        // Validation: CRC-32 of the block, then the SHA-256 sealed with the VMK.
        let crc = crc32(&a[..real]);
        let hash = backend.sha256(&[&a[..real]]);
        let mut hv = vec![0u8; 44];
        put_le16(&mut hv, 0, 44);
        put_le16(&mut hv, 4, 1);
        put_le16(&mut hv, 6, 1);
        put_le16(&mut hv, 8, 0x2005);
        hv[12..44].copy_from_slice(&hash);
        let nested = sealed(backend, vmk, validation_nonce, &hv)?;
        put_le16(&mut a, real, (META_AREA as usize - real) as u16);
        put_le16(&mut a, real + 2, 2);
        put_le32(&mut a, real + 4, crc);
        put_le16(&mut a, real + 8, 80);
        put_le16(&mut a, real + 10, 0);
        put_le16(&mut a, real + 12, 5);
        put_le16(&mut a, real + 14, 1);
        a[real + 16..real + 16 + nested.len()].copy_from_slice(&nested);
        out.push(Built { area: a });
    }
    Ok(out)
}

/// The "-FVE-FS-" boot sector that replaces the file system's own.
fn volume_header(offsets: [u64; 3], hidden_sectors: u32) -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    b[3..11].copy_from_slice(b"-FVE-FS-");
    put_le16(&mut b, 11, 512);
    b[13] = 8;
    b[21] = 0xF8;
    put_le16(&mut b, 24, 0x3F);
    put_le16(&mut b, 26, 0xFF);
    put_le32(&mut b, 28, hidden_sectors);
    put_le32(&mut b, 36, 0x1FE0);
    put_le16(&mut b, 48, 1);
    put_le16(&mut b, 50, 6);
    b[64] = 0x80;
    b[66] = 0x29;
    b[71..82].copy_from_slice(b"NO NAME    ");
    b[82..90].copy_from_slice(b"FAT32   ");
    // Not bootable: clear interrupts and halt.
    b[90..94].copy_from_slice(&[0xFA, 0xF4, 0xEB, 0xFD]);
    b[160..176].copy_from_slice(&GUID_BDE);
    for (i, o) in offsets.iter().enumerate() {
        put_le64(&mut b, 176 + 8 * i, *o);
    }
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

/// Identity view used while building: encrypts at the same position.
struct RawView {
    disk: crate::part::SharedDisk,
    engine: std::sync::Arc<Engine>,
}

impl Disk for RawView {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let first = offset / 512 * 512;
        let end = (offset + buf.len() as u64).div_ceil(512) * 512;
        let mut tmp = vec![0u8; (end - first) as usize];
        self.disk.lock().map_err(|_| Error::corrupt("lock"))?.read_at(first, &mut tmp)?;
        self.engine.decrypt(&mut tmp, 512, first);
        let s = (offset - first) as usize;
        buf.copy_from_slice(&tmp[s..s + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let first = offset / 512 * 512;
        let end = (offset + buf.len() as u64).div_ceil(512) * 512;
        let mut tmp = vec![0u8; (end - first) as usize];
        if first != offset || end != offset + buf.len() as u64 {
            self.read_at(first, &mut tmp)?;
        }
        let s = (offset - first) as usize;
        tmp[s..s + buf.len()].copy_from_slice(buf);
        self.engine.encrypt(&mut tmp, 512, first);
        self.disk.lock().map_err(|_| Error::corrupt("lock"))?.write_at(first, &tmp)
    }

    fn len(&self) -> u64 {
        self.disk.lock().map(|d| d.len()).unwrap_or(0)
    }
}

/// Builds a BitLocker volume over all of `disk`. Returns the recovery
/// password, which the user must keep.
pub fn create_bitlocker(
    backend: &dyn Backend,
    disk: Box<dyn Disk>,
    opts: &BdeCreateOptions,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<String> {
    if opts.password.encode_utf16().count() < 8 {
        return Err(Error::invalid("BitLocker passwords have at least 8 characters"));
    }
    let size = disk.len() / 512 * 512;
    if size < 64 << 20 {
        return Err(Error::invalid("BitLocker volumes need at least 64 MiB"));
    }
    if matches!(opts.method, Method::Cbc128Diffuser | Method::Cbc256Diffuser) {
        return Err(Error::unsupported("new volumes with the Elephant diffuser (Windows 10 no longer creates them)"));
    }
    let mut vmk = [0u8; 32];
    backend.fill_random(&mut vmk)?;
    let mut fvek = Secret::new(super::Method::key_data_len(opts.method));
    backend.fill_random(&mut fvek)?;
    let recovery = match opts.recovery_key {
        Some(k) => k,
        None => generate_recovery_password(backend)?.1,
    };
    let engine = std::sync::Arc::new(Engine::new(backend, opts.method, &fvek)?);
    let shared: crate::part::SharedDisk = std::sync::Arc::new(std::sync::Mutex::new(disk));
    let total = size;
    let mut report = |done: u64| -> Result<()> {
        if cancel.load(Ordering::Relaxed) || !progress(done, total) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    };

    // 1. File system, encrypted in place (identity layout for now).
    let mut vid = [0u8; 4];
    backend.fill_random(&mut vid)?;
    let plan = opts.filesystem.plan(size, opts.label, u32::from_le_bytes(vid))?;
    let chunk = 1usize << 20;
    let mut buf = vec![0u8; chunk];
    let mut pos = 0u64;
    while pos < size {
        let n = ((size - pos) as usize).min(chunk);
        let has_meta = plan.patches.iter().any(|(o, b)| *o < pos + n as u64 && o + b.len() as u64 > pos);
        if !opts.quick || has_meta {
            let c = &mut buf[..n];
            c.fill(0);
            apply_patches(&plan.patches, pos, c);
            engine.encrypt(c, 512, pos);
            lock(&shared)?.write_at(pos, c)?;
        }
        pos += n as u64;
        report(pos * 9 / 10)?;
    }

    // 2. Placeholder files for the metadata areas and the boot record copy.
    let (meta, header_offset) = {
        let mut fs = crate::fs::mount(Box::new(RawView { disk: shared.clone(), engine: engine.clone() }), false, 0)?;
        fs.mkdir(SVI)?;
        let zeros = vec![0u8; META_AREA as usize];
        let mut meta = [0u64; 3];
        for (i, m) in meta.iter_mut().enumerate() {
            let p = format!("{SVI}/{META_NAME}.{}", i + 1);
            fs.write_file(&p, &mut zeros.as_slice(), META_AREA, false, &mut |_| true)?;
            *m = single_extent(fs.as_mut(), &p, META_AREA)?;
        }
        let p = format!("{SVI}/{BOOT_NAME}");
        fs.write_file(&p, &mut &zeros[..HEADER_COPY as usize], HEADER_COPY, false, &mut |_| true)?;
        let ho = single_extent(fs.as_mut(), &p, HEADER_COPY)?;
        fs.set_hidden_system(SVI)?;
        fs.flush()?;
        (meta, ho)
    };

    // 3. Move the file system's boot record to its copy, re-encrypted for
    //    its new position, and put the BitLocker header in its place.
    let mut d = lock(&shared)?;
    let mut boot = vec![0u8; HEADER_COPY as usize];
    d.read_at(0, &mut boot)?;
    engine.decrypt(&mut boot, 512, 0);
    engine.encrypt(&mut boot, 512, header_offset);
    d.write_at(header_offset, &boot)?;
    crate::util::wipe(&mut boot);
    let mut first = vec![0u8; HEADER_COPY as usize];
    first[..512].copy_from_slice(&volume_header(meta, 0));
    d.write_at(0, &first)?;

    // 4. The three metadata copies.
    let areas = build_metadata(backend, opts, size, meta, header_offset, &vmk, &fvek, &recovery, cancel)?;
    for (b, &mo) in areas.iter().zip(&meta) {
        d.write_at(mo, &b.area)?;
    }
    crate::util::wipe(&mut vmk);
    d.flush()?;
    drop(d);
    report(total)?;
    Ok(recovery_string(&recovery))
}

fn lock(s: &crate::part::SharedDisk) -> Result<std::sync::MutexGuard<'_, Box<dyn Disk>>> {
    s.lock().map_err(|_| Error::corrupt("disk lock poisoned"))
}

fn single_extent(fs: &mut dyn FileSystem, path: &str, len: u64) -> Result<u64> {
    let ext = fs.extents(path)?;
    match ext.as_slice() {
        [(off, l)] if *l >= len && off % 512 == 0 => Ok(*off),
        _ => Err(Error::corrupt("placeholder file is not contiguous")),
    }
}
