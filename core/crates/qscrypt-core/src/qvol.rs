//! QsCrypt containers: a FAT/exFAT volume whose data area is encrypted with
//! the AES-Twofish-Serpent XTS cascade, behind a QsCrypt v2 header (so the
//! same key slots and policies as files: password, duress password,
//! recovery key, contacts, offline-only, expiry, attempts).
//!
//! ```text
//! 0         QsCrypt v2 header (flags: container), padded with random to 64 KiB
//! 65536     encrypted data area (units of 512 bytes, numbered from 0 at 0)
//! S-65536   copy of the header (same bytes)
//! ```

use crate::crypto::Backend;
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::fs::{apply_patches, FsChoice};
use crate::qsc2::{self, Header, Options, Unlock, FLAG_CONTAINER};
use crate::util::now_unix;
use crate::vc::{CipherChain, Ea, EncVolume};
use std::sync::atomic::{AtomicBool, Ordering};

pub const AREA: u64 = 65536;
pub const EXTENSION: &str = "qsv";
const EA: Ea = Ea::AesTwofishSerpent;

/// True if `prefix` starts a QsCrypt container.
pub fn is_container(prefix: &[u8]) -> bool {
    qsc2::is_v2(prefix) && prefix.len() >= 12 && u16::from_le_bytes([prefix[10], prefix[11]]) & FLAG_CONTAINER != 0
}

pub fn create(
    backend: &dyn Backend,
    disk: &mut dyn Disk,
    opts: &Options,
    filesystem: FsChoice,
    label: &str,
    quick: bool,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<()> {
    let size = disk.len() / 512 * 512;
    if size < 2 * AREA + (1 << 20) {
        return Err(Error::invalid("container too small"));
    }
    let data = size - 2 * AREA;
    let (header, fk, file_id) = qsc2::build_header(backend, opts, FLAG_CONTAINER, 0, data, now_unix())?;
    let mut area = vec![0u8; AREA as usize];
    backend.fill_random(&mut area)?;
    area[..header.len()].copy_from_slice(&header);
    disk.write_at(0, &area)?;
    disk.write_at(size - AREA, &area)?;

    let key = qsc2::container_key(backend, &fk, &file_id)?;
    let chain = CipherChain::new(backend, EA, &key)?;
    let mut vid = [0u8; 4];
    backend.fill_random(&mut vid)?;
    let plan = filesystem.plan(data, label, u32::from_le_bytes(vid))?;
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    while pos < data {
        let n = ((data - pos) as usize).min(buf.len());
        let has_meta = plan.patches.iter().any(|(o, b)| *o < pos + n as u64 && o + b.len() as u64 > pos);
        if !quick || has_meta || pos < plan.meta_end {
            let c = &mut buf[..n];
            c.fill(0);
            apply_patches(&plan.patches, pos, c);
            chain.encrypt(c, 512, pos / 512);
            disk.write_at(AREA + pos, c)?;
        }
        pos += n as u64;
        if cancel.load(Ordering::Relaxed) || !progress(pos, data) {
            return Err(Error::Cancelled);
        }
    }
    disk.flush()
}

/// Reads the header (the copy at the end if the first is damaged).
pub fn read_header(disk: &mut dyn Disk) -> Result<Header> {
    let size = disk.len();
    let mut last = Error::corrupt("not a QsCrypt container");
    for at in [0, size.saturating_sub(AREA)] {
        let mut area = vec![0u8; AREA.min(size) as usize];
        if disk.read_at(at, &mut area).is_err() {
            continue;
        }
        if !is_container(&area) {
            continue;
        }
        let len = u32::from_le_bytes(area[12..16].try_into().unwrap()) as usize;
        if len > area.len() {
            continue;
        }
        match qsc2::parse_header(area[..len].to_vec()) {
            Ok(h) => return Ok(h),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub struct Opened {
    pub header: Header,
    pub duress: bool,
    /// None when the duress password was used.
    pub volume: Option<EncVolume>,
    pub file_key: Option<crate::util::Secret>,
}

/// Unlocks and returns the decrypted data area (policies are the caller's
/// to evaluate first, with `header.evaluate`).
pub fn open(backend: &dyn Backend, mut disk: Box<dyn Disk>, header: Header, how: &Unlock, read_only: bool) -> Result<Opened> {
    let u = qsc2::unlock(backend, &header, how)?;
    if u.duress {
        return Ok(Opened { header, duress: true, volume: None, file_key: None });
    }
    let size = disk.len() / 512 * 512;
    let data = header.stream_len();
    if data + 2 * AREA != size {
        // The header copy may be read from a file that was cut or grown.
        let _ = disk.flush();
        return Err(Error::corrupt("container size does not match its header"));
    }
    let key = qsc2::container_key(backend, &u.file_key, &header.file_id)?;
    let chain = CipherChain::new(backend, EA, &key)?;
    // Units are numbered from the start of the data area.
    let vol = EncVolume::with_unit_base(disk, chain, AREA, data, read_only, 0)?;
    Ok(Opened { header, duress: false, volume: Some(vol), file_key: Some(u.file_key) })
}

/// Makes the container unrecoverable: both header copies are overwritten.
pub fn destroy(backend: &dyn Backend, disk: &mut dyn Disk) -> Result<()> {
    let size = disk.len();
    let mut junk = vec![0u8; AREA as usize];
    for at in [0, size.saturating_sub(AREA)] {
        backend.fill_random(&mut junk)?;
        disk.write_at(at, &junk[..AREA.min(size) as usize])?;
    }
    disk.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;
    use crate::identity::SecretIdentity;
    use crate::part::{DiskView, SharedDisk};
    use crate::qsc::Params;
    use crate::qsc2::{Action, Context, Policy, Verdict};
    use crate::reference::RefBackend;
    use std::sync::{Arc, Mutex};

    #[test]
    fn containers_round_trip() {
        let b = RefBackend::with_fakes();
        let bob = SecretIdentity::generate(&b, "Bob").unwrap();
        let recipients = vec![bob.public.clone()];
        let o = Options {
            password: Some(b"vault pw"),
            duress: Some(b"duress"),
            recovery: None,
            recipients: &recipients,
            signer: None,
            policy: Policy { offline_only: Some(Action::Refuse), ..Policy::default() },
            params: Params { memory_kib: 64, iterations: 1, lanes: 1, chunk_size: 4096 },
        };
        let shared: SharedDisk = Arc::new(Mutex::new(Box::new(MemDisk::new(6 << 20))));
        let mut d = DiskView::whole(shared.clone(), false).unwrap();
        create(&b, &mut d, &o, FsChoice::Exfat, "QsVault", false, &mut |_, _| true, &AtomicBool::new(false)).unwrap();
        let view = || Box::new(DiskView::whole(shared.clone(), false).unwrap());

        let h = read_header(view().as_mut()).unwrap();
        assert_eq!(h.evaluate(&Context { now: now_unix(), max_seen: 0, online: true }), Verdict::Refuse("online"));
        let opened = open(&b, view(), h.clone(), &Unlock::Password(b"vault pw"), false).unwrap();
        let mut fs = crate::fs::mount(Box::new(opened.volume.unwrap()), false, 0).unwrap();
        assert_eq!((fs.kind(), fs.label()), ("exFAT", "QsVault".to_string()));
        fs.write_file("/a.txt", &mut &b"inside"[..], 6, false, &mut |_| true).unwrap();
        drop(fs);
        let opened = open(&b, view(), h.clone(), &Unlock::Identity(&bob), true).unwrap();
        let mut fs = crate::fs::mount(Box::new(opened.volume.unwrap()), true, 0).unwrap();
        let mut out = Vec::new();
        fs.read_file("/a.txt", &mut out, &mut |_| true).unwrap();
        assert_eq!(out, b"inside");
        assert!(open(&b, view(), h.clone(), &Unlock::Password(b"duress"), true).unwrap().duress);

        // The first header damaged: the copy at the end still opens it.
        shared.lock().unwrap().write_at(20, &[0xAA; 64]).unwrap();
        let h2 = read_header(view().as_mut()).unwrap();
        assert!(open(&b, view(), h2, &Unlock::Password(b"vault pw"), true).is_ok());
        destroy(&b, view().as_mut()).unwrap();
        assert!(read_header(view().as_mut()).is_err());
    }
}
