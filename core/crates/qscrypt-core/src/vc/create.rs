//! Creating a new file-hosted volume, formatted with FAT.
//!
//! Everything is written: random header areas, the encrypted FAT, and the
//! data area as encrypted zeros, so the container is indistinguishable from
//! random data and leaks nothing about how much of it is used.

use super::header::{PlainHeader, ENC_SIZE, HEADER_SIZE, SALT_SIZE};
use super::{CipherChain, Ea, Format, DATA_OFFSET, HEADER_GROUP, UNIT};
use crate::crypto::{Backend, Prf};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::Secret;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct CreateOptions<'a> {
    pub format: Format,
    pub password: &'a [u8],
    pub pim: u32,
    pub prf: Prf,
    pub ea: Ea,
    /// Total container size in bytes (multiple of 512).
    pub size: u64,
    pub label: &'a str,
}

/// Smallest container: header groups plus 1 MiB of data.
pub const MIN_SIZE: u64 = 2 * HEADER_GROUP + (1 << 20);

const CHUNK: usize = 1 << 20;

fn encrypted_header(backend: &dyn Backend, opts: &CreateOptions, plain: &PlainHeader, cancel: &AtomicBool) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_SIZE];
    backend.fill_random(&mut salt)?;
    let mut dk = Secret::new(2 * opts.ea.key_size());
    let iterations = opts.format.iterations(opts.prf, opts.pim);
    crate::kdf::pbkdf2(backend, opts.prf, opts.password, &salt, iterations, &mut dk, cancel)?;
    let chain = CipherChain::new(backend, opts.ea, &dk)?;
    let mut enc = plain.serialize();
    chain.encrypt(&mut enc, 512, 0);
    let mut out = Vec::with_capacity(HEADER_SIZE);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&enc);
    debug_assert_eq!(out.len(), SALT_SIZE + ENC_SIZE);
    Ok(out)
}

fn random_fill(backend: &dyn Backend, disk: &mut dyn Disk, from: u64, to: u64) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = from;
    while pos < to {
        let n = ((to - pos) as usize).min(buf.len());
        backend.fill_random(&mut buf[..n])?;
        disk.write_at(pos, &buf[..n])?;
        pos += n as u64;
    }
    Ok(())
}

/// Writes a complete new volume over `disk` (whose length must be `opts.size`).
/// `progress(done, total)` returning false cancels.
pub fn create_container(
    backend: &dyn Backend,
    disk: &mut dyn Disk,
    opts: &CreateOptions,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<()> {
    if opts.size % UNIT != 0 || opts.size < MIN_SIZE {
        return Err(Error::invalid("container size must be a multiple of 512 and at least 1.25 MiB"));
    }
    if disk.len() != opts.size {
        return Err(Error::invalid("target size does not match"));
    }
    if opts.password.is_empty() {
        return Err(Error::invalid("empty password"));
    }
    if opts.format == Format::TrueCrypt && opts.pim != 0 {
        return Err(Error::invalid("TrueCrypt has no PIM"));
    }
    if !opts.format.prfs().contains(&opts.prf) || !backend.has_prf(opts.prf) {
        return Err(Error::unsupported(format!("{} for {}", opts.prf.name(), opts.format.name())));
    }
    if !opts.ea.ciphers().iter().all(|c| backend.has_cipher(*c)) {
        return Err(Error::unsupported(opts.ea.name()));
    }

    let data_size = opts.size - 2 * HEADER_GROUP;
    let mut master = Secret::new(256);
    backend.fill_random(&mut master)?;
    let plain = PlainHeader {
        format: opts.format,
        version: 5,
        required_version: match opts.format {
            Format::VeraCrypt => 0x010B,
            Format::TrueCrypt => 0x0700,
        },
        hidden_volume_size: 0,
        volume_size: data_size,
        data_offset: DATA_OFFSET,
        data_size,
        flags: 0,
        sector_size: 512,
        master_keys: master.clone(),
    };
    let total = opts.size;
    let mut done = 0u64;
    let mut report = |done: u64| -> Result<()> {
        if cancel.load(Ordering::Relaxed) || !progress(done, total) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    };

    // Header group: header, then random filler (incl. the hidden header slot).
    let header = encrypted_header(backend, opts, &plain, cancel)?;
    disk.write_at(0, &header)?;
    random_fill(backend, disk, HEADER_SIZE as u64, HEADER_GROUP)?;
    done += HEADER_GROUP;
    report(done)?;

    // Data area: encrypted zeros with the FAT metadata overlaid.
    let mut vid = [0u8; 4];
    backend.fill_random(&mut vid)?;
    let plan = crate::fs::format_plan(data_size, opts.label, u32::from_le_bytes(vid))?;
    let chain = CipherChain::new(backend, opts.ea, &master)?;
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < data_size {
        let n = ((data_size - pos) as usize).min(CHUNK);
        let chunk = &mut buf[..n];
        chunk.fill(0);
        crate::fs::apply_patches(&plan.patches, pos, chunk);
        chain.encrypt(chunk, UNIT as usize, (DATA_OFFSET + pos) / UNIT);
        disk.write_at(DATA_OFFSET + pos, chunk)?;
        pos += n as u64;
        done += n as u64;
        report(done)?;
    }

    // Backup header group: same keys and fields, fresh salt.
    let backup = encrypted_header(backend, opts, &plain, cancel)?;
    let backup_at = opts.size - HEADER_GROUP;
    disk.write_at(backup_at, &backup)?;
    random_fill(backend, disk, backup_at + HEADER_SIZE as u64, opts.size)?;
    done += HEADER_GROUP;
    report(done)?;
    disk.flush()
}
