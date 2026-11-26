//! Header maintenance: password changes, hidden volume protection ranges,
//! external header backups (VeraCrypt-compatible) and header repair.

use super::create::seal_header;
use super::detect::{detect, OpenOptions, OpenedHeader};
use super::{HEADER_GROUP, HIDDEN_HEADER_OFFSET};
use crate::crypto::{Backend, Prf};
use crate::disk::Disk;
use crate::error::{Error, Result};
use std::sync::atomic::AtomicBool;

pub struct Credentials<'a> {
    /// Already combined with any keyfiles.
    pub password: &'a [u8],
    pub pim: u32,
    pub prf: Prf,
}

fn copy_opts<'a>(o: &OpenOptions<'a>) -> OpenOptions<'a> {
    OpenOptions {
        password: o.password,
        pim: o.pim,
        prf: o.prf,
        format: o.format,
        try_hidden: o.try_hidden,
        use_backup: o.use_backup,
        hidden_only: o.hidden_only,
        backup_only: o.backup_only,
    }
}

fn slots(found: &OpenedHeader, size: u64) -> (u64, u64) {
    if found.hidden {
        (HIDDEN_HEADER_OFFSET, size - HIDDEN_HEADER_OFFSET)
    } else {
        (0, size - HEADER_GROUP)
    }
}

/// Absolute byte range of the hidden volume's data, from its header
/// decrypted with the hidden volume's credentials.
pub fn hidden_range(backend: &dyn Backend, disk: &mut dyn Disk, hidden: &OpenOptions, cancel: &AtomicBool) -> Result<(u64, u64)> {
    let mut o = copy_opts(hidden);
    o.hidden_only = true;
    o.backup_only = false;
    let found = detect(backend, disk, &o, cancel)?;
    let h = &found.header;
    Ok((h.data_offset, h.data_offset + h.data_size))
}

/// Re-encrypts the header that `current` opens (and its embedded backup)
/// under new credentials. The master keys, and so the data, are unchanged.
pub fn change_password(backend: &dyn Backend, disk: &mut dyn Disk, current: &OpenOptions, new: &Credentials, cancel: &AtomicBool) -> Result<OpenedHeader> {
    if new.password.is_empty() {
        return Err(Error::invalid("empty password"));
    }
    let found = detect(backend, disk, current, cancel)?;
    let size = disk.len();
    let (primary, backup) = slots(&found, size);
    let f = found.header.format;
    if f == super::Format::TrueCrypt && new.pim != 0 {
        return Err(Error::invalid("TrueCrypt has no PIM"));
    }
    for at in [primary, backup] {
        let sealed = seal_header(backend, f, new.password, new.pim, new.prf, found.ea, &found.header, cancel)?;
        disk.write_at(at, &sealed)?;
    }
    disk.flush()?;
    Ok(found)
}

/// VeraCrypt-compatible external header backup: 128 KiB with the normal
/// header at 0 and the hidden one at 64 KiB (random when there is none),
/// each re-encrypted with a fresh salt under the same credentials.
pub fn backup_headers(backend: &dyn Backend, disk: &mut dyn Disk, outer: &OpenOptions, hidden: Option<&OpenOptions>, cancel: &AtomicBool) -> Result<Vec<u8>> {
    let mut out = vec![0u8; HEADER_GROUP as usize];
    backend.fill_random(&mut out)?;
    let mut o = copy_opts(outer);
    o.try_hidden = false;
    o.hidden_only = false;
    let n = detect(backend, disk, &o, cancel)?;
    let sealed = seal_header(backend, n.header.format, outer.password, n.pim, n.prf, n.ea, &n.header, cancel)?;
    out[..sealed.len()].copy_from_slice(&sealed);
    if let Some(h) = hidden {
        let mut ho = copy_opts(h);
        ho.hidden_only = true;
        let hf = detect(backend, disk, &ho, cancel)?;
        let sealed = seal_header(backend, hf.header.format, h.password, hf.pim, hf.prf, hf.ea, &hf.header, cancel)?;
        let at = HIDDEN_HEADER_OFFSET as usize;
        out[at..at + sealed.len()].copy_from_slice(&sealed);
    }
    Ok(out)
}

/// A backup file seen as the start of a volume of `size` bytes, so the
/// usual detection (and its range checks) apply.
struct BackupView<'a> {
    data: &'a [u8],
    size: u64,
}

impl Disk for BackupView<'_> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let o = offset as usize;
        if o + buf.len() > self.data.len() {
            return Err(Error::corrupt("outside the header backup"));
        }
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> Result<()> {
        Err(Error::ReadOnly)
    }
    fn len(&self) -> u64 {
        self.size
    }
}

/// Restores the header that `opts` opens in an external backup file, to
/// both its primary and embedded backup slots.
pub fn restore_from_file(backend: &dyn Backend, disk: &mut dyn Disk, backup: &[u8], opts: &OpenOptions, cancel: &AtomicBool) -> Result<OpenedHeader> {
    if backup.len() != HEADER_GROUP as usize {
        return Err(Error::invalid("not a VeraCrypt header backup (must be 128 KiB)"));
    }
    let size = disk.len();
    let mut view = BackupView { data: backup, size };
    let mut o = copy_opts(opts);
    o.use_backup = false;
    o.backup_only = false;
    let found = detect(backend, &mut view, &o, cancel)?;
    let (primary, embedded) = slots(&found, size);
    for at in [primary, embedded] {
        let sealed = seal_header(backend, found.header.format, opts.password, found.pim, found.prf, found.ea, &found.header, cancel)?;
        disk.write_at(at, &sealed)?;
    }
    disk.flush()?;
    Ok(found)
}

/// Repairs a damaged primary header from the backup embedded at the end
/// of the volume.
pub fn repair_from_embedded(backend: &dyn Backend, disk: &mut dyn Disk, opts: &OpenOptions, cancel: &AtomicBool) -> Result<OpenedHeader> {
    let mut o = copy_opts(opts);
    o.backup_only = true;
    let found = detect(backend, disk, &o, cancel)?;
    let (primary, _) = slots(&found, disk.len());
    let sealed = seal_header(backend, found.header.format, opts.password, found.pim, found.prf, found.ea, &found.header, cancel)?;
    disk.write_at(primary, &sealed)?;
    disk.flush()?;
    Ok(found)
}
