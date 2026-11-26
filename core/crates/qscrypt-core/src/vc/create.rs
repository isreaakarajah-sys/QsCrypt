//! Creating a new volume (file container, partition or whole drive),
//! optionally with a hidden volume inside.
//!
//! Everything is written: random header areas, the encrypted file system
//! metadata and the data area as encrypted zeros, so the volume is
//! indistinguishable from random data and leaks nothing about how much of it
//! is used. Quick mode (drives only) writes just the headers and metadata.
//!
//! Hidden volume layout (VeraCrypt's `TCFormatVolume`): the hidden data area
//! ends where the backup header group begins, minus a small reserve the
//! outer file system may touch, and its header sits at 64 KiB:
//!
//! ```text
//! 0        outer header           65536  hidden header
//! 131072   outer data ... | hidden data (D) | reserve (R) |
//! S-131072 outer backup header    S-65536 hidden backup header
//! ```
//! with H = requested size, R = 4 KiB (H < 2 MiB) or 128 KiB, D = H - R and
//! the hidden data at S - 131072 - H.

use super::header::{PlainHeader, ENC_SIZE, HEADER_SIZE, SALT_SIZE};
use super::{CipherChain, Ea, Format, DATA_OFFSET, HEADER_GROUP, HIDDEN_HEADER_OFFSET, UNIT};
use crate::crypto::{Backend, Prf};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::fs::{apply_patches, FatPlan, FsChoice};
use crate::util::Secret;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct HiddenOptions<'a> {
    pub password: &'a [u8],
    pub pim: u32,
    pub prf: Prf,
    pub ea: Ea,
    /// Space taken from the end of the outer volume, in bytes.
    pub size: u64,
    pub filesystem: FsChoice,
    pub label: &'a str,
}

pub struct CreateOptions<'a> {
    pub format: Format,
    /// Already combined with any keyfiles (see `apply_keyfiles`).
    pub password: &'a [u8],
    pub pim: u32,
    pub prf: Prf,
    pub ea: Ea,
    /// Total size in bytes (multiple of 512): the file, partition or drive.
    pub size: u64,
    pub label: &'a str,
    pub filesystem: FsChoice,
    /// Only headers and file system metadata are written (drives only).
    pub quick: bool,
    pub hidden: Option<HiddenOptions<'a>>,
}

impl<'a> CreateOptions<'a> {
    pub fn new(format: Format, password: &'a [u8], ea: Ea, prf: Prf, size: u64) -> CreateOptions<'a> {
        CreateOptions { format, password, pim: 0, prf, ea, size, label: "", filesystem: FsChoice::Fat, quick: false, hidden: None }
    }
}

/// Smallest volume: header groups plus 1 MiB of data.
pub const MIN_SIZE: u64 = 2 * HEADER_GROUP + (1 << 20);
/// Smallest hidden volume.
pub const MIN_HIDDEN_SIZE: u64 = (1 << 20) + HEADER_GROUP;

const CHUNK: usize = 1 << 20;
const SMALL_HIDDEN: u64 = 2 << 20;

fn reserve_for(hidden_size: u64) -> u64 {
    if hidden_size < SMALL_HIDDEN {
        4096
    } else {
        HEADER_GROUP
    }
}

struct HeaderParams<'a> {
    format: Format,
    password: &'a [u8],
    pim: u32,
    prf: Prf,
    ea: Ea,
}

fn encrypted_header(backend: &dyn Backend, p: &HeaderParams, plain: &PlainHeader, cancel: &AtomicBool) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_SIZE];
    backend.fill_random(&mut salt)?;
    let mut dk = Secret::new(2 * p.ea.key_size());
    let iterations = p.format.iterations(p.prf, p.pim);
    crate::kdf::pbkdf2(backend, p.prf, p.password, &salt, iterations, &mut dk, cancel)?;
    let chain = CipherChain::new(backend, p.ea, &dk)?;
    let mut enc = plain.serialize();
    chain.encrypt(&mut enc, 512, 0);
    let mut out = Vec::with_capacity(HEADER_SIZE);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&enc);
    debug_assert_eq!(out.len(), SALT_SIZE + ENC_SIZE);
    Ok(out)
}

/// Re-encrypts `plain` under new credentials (new salt). Used by password
/// changes and header backups.
pub(crate) fn seal_header(
    backend: &dyn Backend,
    format: Format,
    password: &[u8],
    pim: u32,
    prf: Prf,
    ea: Ea,
    plain: &PlainHeader,
    cancel: &AtomicBool,
) -> Result<Vec<u8>> {
    encrypted_header(backend, &HeaderParams { format, password, pim, prf, ea }, plain, cancel)
}

pub(crate) fn random_fill(backend: &dyn Backend, disk: &mut dyn Disk, from: u64, to: u64) -> Result<()> {
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

fn check_params(backend: &dyn Backend, format: Format, password: &[u8], pim: u32, prf: Prf, ea: Ea) -> Result<()> {
    if password.is_empty() {
        return Err(Error::invalid("empty password"));
    }
    if format == Format::TrueCrypt && pim != 0 {
        return Err(Error::invalid("TrueCrypt has no PIM"));
    }
    if !format.prfs().contains(&prf) || !backend.has_prf(prf) {
        return Err(Error::unsupported(format!("{} for {}", prf.name(), format.name())));
    }
    if !ea.ciphers().iter().all(|c| backend.has_cipher(*c)) {
        return Err(Error::unsupported(ea.name()));
    }
    Ok(())
}

fn plain_header(format: Format, master: &Secret, hidden_size: u64, data_offset: u64, data_size: u64) -> PlainHeader {
    PlainHeader {
        format,
        version: 5,
        required_version: match format {
            Format::VeraCrypt => 0x010B,
            Format::TrueCrypt => 0x0700,
        },
        hidden_volume_size: hidden_size,
        volume_size: data_size,
        data_offset,
        data_size,
        flags: 0,
        sector_size: 512,
        master_keys: master.clone(),
    }
}

/// Where the outer file system's metadata ends, rounded to whole clusters
/// (relative to the start of the outer data area).
fn metadata_end(plan: &FatPlan) -> u64 {
    let end = plan.patches.iter().map(|(o, b)| o + b.len() as u64).max().unwrap_or(0);
    end.div_ceil(plan.cluster_size as u64) * plan.cluster_size as u64
}

/// Largest hidden volume that fits in a fresh outer volume of `size` bytes.
pub fn max_hidden_size(size: u64, outer_fs: FsChoice) -> Result<u64> {
    if size < MIN_SIZE {
        return Err(Error::invalid("volume too small"));
    }
    let data_size = size - 2 * HEADER_GROUP;
    let plan = outer_fs.plan(data_size, "", 0)?;
    // Keep one cluster of the outer file system free after its metadata.
    let free = data_size.saturating_sub(metadata_end(&plan) + plan.cluster_size as u64);
    let max = free / 4096 * 4096;
    if max < MIN_HIDDEN_SIZE {
        return Err(Error::invalid("volume too small for a hidden volume"));
    }
    Ok(max)
}

struct Area {
    start: u64,
    end: u64,
    chain: CipherChain,
    plan: FatPlan,
}

/// Writes a complete new volume over `disk` (whose length must be `opts.size`).
/// `progress(done, total)` returning false cancels.
pub fn create_volume(
    backend: &dyn Backend,
    disk: &mut dyn Disk,
    opts: &CreateOptions,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<()> {
    if opts.size % UNIT != 0 || opts.size < MIN_SIZE {
        return Err(Error::invalid("volume size must be a multiple of 512 and at least 1.25 MiB"));
    }
    if disk.len() != opts.size {
        return Err(Error::invalid("target size does not match"));
    }
    check_params(backend, opts.format, opts.password, opts.pim, opts.prf, opts.ea)?;
    if let Some(h) = &opts.hidden {
        check_params(backend, opts.format, h.password, h.pim, h.prf, h.ea)?;
        if opts.quick {
            return Err(Error::invalid("a hidden volume needs a full format of the outer volume"));
        }
        if h.password == opts.password {
            return Err(Error::invalid("the hidden volume password must differ from the outer one"));
        }
    }

    let size = opts.size;
    let data_size = size - 2 * HEADER_GROUP;
    let outer_params = HeaderParams { format: opts.format, password: opts.password, pim: opts.pim, prf: opts.prf, ea: opts.ea };
    let mut master = Secret::new(256);
    backend.fill_random(&mut master)?;
    let outer_plain = plain_header(opts.format, &master, 0, DATA_OFFSET, data_size);
    let mut vid = [0u8; 8];
    backend.fill_random(&mut vid)?;
    let outer_plan = opts.filesystem.plan(data_size, opts.label, u32::from_le_bytes(vid[..4].try_into().unwrap()))?;

    let mut areas = vec![Area {
        start: DATA_OFFSET,
        end: DATA_OFFSET + data_size,
        chain: CipherChain::new(backend, opts.ea, &master)?,
        plan: outer_plan,
    }];

    let mut hidden_header = None;
    if let Some(h) = &opts.hidden {
        let hsize = h.size / 4096 * 4096;
        let max = max_hidden_size(size, opts.filesystem)?;
        if hsize < MIN_HIDDEN_SIZE || hsize > max {
            return Err(Error::invalid(format!("hidden volume size must be between {MIN_HIDDEN_SIZE} and {max} bytes")));
        }
        let hdata = hsize - reserve_for(hsize);
        let hoffset = size - HEADER_GROUP - hsize;
        let mut hmaster = Secret::new(256);
        backend.fill_random(&mut hmaster)?;
        let plain = plain_header(opts.format, &hmaster, hdata, hoffset, hdata);
        let params = HeaderParams { format: opts.format, password: h.password, pim: h.pim, prf: h.prf, ea: h.ea };
        let plan = h.filesystem.plan(hdata, h.label, u32::from_le_bytes(vid[4..].try_into().unwrap()))?;
        // The hidden area replaces part of the outer one.
        areas[0].end = hoffset;
        areas.push(Area { start: hoffset, end: hoffset + hdata, chain: CipherChain::new(backend, h.ea, &hmaster)?, plan });
        // The reserve after it is free space of the outer file system.
        let outer_tail = Area {
            start: hoffset + hdata,
            end: DATA_OFFSET + data_size,
            chain: CipherChain::new(backend, opts.ea, &master)?,
            plan: FatPlan { fat_type: "", cluster_size: 512, patches: Vec::new() },
        };
        areas.push(outer_tail);
        hidden_header = Some((params, plain));
    }

    let total = size;
    let mut done = 0u64;
    let mut report = |done: u64| -> Result<()> {
        if cancel.load(Ordering::Relaxed) || !progress(done, total) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    };

    // Header group: header, random filler, the hidden header if any.
    let header = encrypted_header(backend, &outer_params, &outer_plain, cancel)?;
    disk.write_at(0, &header)?;
    random_fill(backend, disk, HEADER_SIZE as u64, HEADER_GROUP)?;
    if let Some((p, plain)) = &hidden_header {
        let hh = encrypted_header(backend, p, plain, cancel)?;
        disk.write_at(HIDDEN_HEADER_OFFSET, &hh)?;
    }
    done += HEADER_GROUP;
    report(done)?;

    // Data areas: encrypted zeros with the file system metadata overlaid.
    let mut buf = vec![0u8; CHUNK];
    for area in &areas {
        let mut pos = area.start;
        while pos < area.end {
            let n = ((area.end - pos) as usize).min(CHUNK - (pos % CHUNK as u64) as usize);
            let rel = pos - area.start;
            let has_meta = area.plan.patches.iter().any(|(o, b)| *o < rel + n as u64 && o + b.len() as u64 > rel);
            if !opts.quick || has_meta {
                let chunk = &mut buf[..n];
                chunk.fill(0);
                apply_patches(&area.plan.patches, rel, chunk);
                area.chain.encrypt(chunk, UNIT as usize, pos / UNIT);
                disk.write_at(pos, chunk)?;
            }
            pos += n as u64;
            done += n as u64;
            report(done)?;
        }
    }
    crate::util::wipe(&mut buf);

    // Backup header group: same keys and fields, fresh salts.
    let backup_at = size - HEADER_GROUP;
    let backup = encrypted_header(backend, &outer_params, &outer_plain, cancel)?;
    disk.write_at(backup_at, &backup)?;
    random_fill(backend, disk, backup_at + HEADER_SIZE as u64, size)?;
    if let Some((p, plain)) = &hidden_header {
        let hh = encrypted_header(backend, p, plain, cancel)?;
        disk.write_at(size - HIDDEN_HEADER_OFFSET, &hh)?;
    }
    done += HEADER_GROUP;
    report(done)?;
    disk.flush()
}

/// Kept for callers of the first API: a full-format file container.
pub fn create_container(
    backend: &dyn Backend,
    disk: &mut dyn Disk,
    opts: &CreateOptions,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<()> {
    create_volume(backend, disk, opts, progress, cancel)
}
