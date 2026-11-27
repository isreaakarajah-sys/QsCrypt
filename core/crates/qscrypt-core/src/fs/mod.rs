//! File systems inside a decrypted volume.
//!
//! - FAT12/16/32: read and write, long file names.
//! - exFAT: read and write.
//! - NTFS: read and write (writing only when Windows closed it cleanly).
//! - ReFS: recognized and reported as unsupported.

pub mod exfat;
mod exfat_format;
pub mod fat;
mod fat_format;
pub mod ntfs;

pub use exfat_format::exfat_format_plan;
pub use fat_format::{apply_patches, format_plan, FatPlan};

/// File system for a new volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsChoice {
    /// FAT12/16/32 by size; files up to 4 GiB - 1.
    Fat,
    /// No practical file size limit; Windows 7+, macOS, Linux 5.4+.
    Exfat,
}

impl FsChoice {
    pub fn from_id(id: u32) -> Option<FsChoice> {
        match id {
            0 | 1 => Some(FsChoice::Fat),
            2 => Some(FsChoice::Exfat),
            _ => None,
        }
    }

    /// Sparse formatting plan for a volume of `size` bytes.
    pub fn plan(self, size: u64, label: &str, volume_id: u32) -> Result<FatPlan> {
        match self {
            FsChoice::Fat => format_plan(size, label, volume_id),
            FsChoice::Exfat => exfat_format_plan(size, label, volume_id),
        }
    }
}

use crate::disk::Disk;
use crate::error::{Error, Result};
use std::io::{Read, Write};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Seconds since the Unix epoch (UTC); 0 when unknown.
    pub modified: i64,
}

/// Reports bytes processed so far; returning `false` cancels.
pub type Progress<'a> = &'a mut dyn FnMut(u64) -> bool;

/// What a file system check found (and, with repair, fixed).
#[derive(Clone, Debug, Default)]
pub struct CheckReport {
    pub files: u64,
    pub dirs: u64,
    pub used_bytes: u64,
    /// Allocated clusters nothing refers to.
    pub lost_clusters: u64,
    /// Clusters claimed by two files or directories.
    pub cross_linked: u64,
    /// Chains that leave the volume, loop, or end early.
    pub bad_chains: u64,
    /// Files whose size and allocation disagree.
    pub size_mismatches: u64,
    /// exFAT: clusters in use but marked free in the bitmap.
    pub bitmap_errors: u64,
    /// exFAT: entry sets whose checksum fails (they are invisible).
    pub checksum_errors: u64,
    /// The stored count of free clusters is wrong.
    pub free_count_wrong: bool,
    /// Fixes applied (with repair).
    pub repaired: u64,
    /// The first few problems, with paths.
    pub issues: Vec<String>,
}

impl CheckReport {
    pub fn clean(&self) -> bool {
        self.lost_clusters == 0
            && self.cross_linked == 0
            && self.bad_chains == 0
            && self.size_mismatches == 0
            && self.bitmap_errors == 0
            && self.checksum_errors == 0
            && !self.free_count_wrong
    }

    pub(crate) fn issue(&mut self, text: String) {
        if self.issues.len() < 50 {
            self.issues.push(text);
        }
    }
}

pub trait FileSystem: Send {
    /// "FAT12", "FAT16", "FAT32", "exFAT".
    fn kind(&self) -> &'static str;
    fn label(&self) -> String;
    fn read_only(&self) -> bool;
    /// Why a volume asked to be writable was opened read-only anyway.
    fn read_only_reason(&self) -> Option<String> {
        None
    }
    fn total_bytes(&self) -> u64;
    fn free_bytes(&mut self) -> Result<u64>;
    /// Largest file the file system can store.
    fn max_file_size(&self) -> u64;

    fn list(&mut self, path: &str) -> Result<Vec<DirEntry>>;
    fn stat(&mut self, path: &str) -> Result<DirEntry>;
    /// Streams a whole file to `out`; returns the number of bytes written.
    fn read_file(&mut self, path: &str, out: &mut dyn Write, progress: Progress) -> Result<u64>;
    /// Random access read; returns bytes read (short at end of file).
    fn read_range(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize>;

    fn write_file(&mut self, path: &str, src: &mut dyn Read, size: u64, overwrite: bool, progress: Progress) -> Result<()>;
    fn mkdir(&mut self, path: &str) -> Result<()>;
    /// Removes a file, or a directory with everything in it.
    fn remove(&mut self, path: &str) -> Result<()>;
    /// Renames within the same directory.
    fn rename(&mut self, path: &str, new_name: &str) -> Result<()>;
    fn flush(&mut self) -> Result<()>;

    /// Keeps the allocator away from `[start, end)` (bytes from the start
    /// of the volume): hidden volume protection. Free space shrinks
    /// accordingly. Default: nothing to do (read-only file systems).
    fn reserve(&mut self, _start: u64, _end: u64) {}

    /// Byte ranges (from the start of the volume) a file occupies, in order.
    fn extents(&mut self, _path: &str) -> Result<Vec<(u64, u64)>> {
        Err(Error::unsupported("file extents on this file system"))
    }

    /// The device under the file system. A container stored as a file in it
    /// (a VeraCrypt volume on a USB stick's FAT, exFAT or NTFS partition) is
    /// read and written in place through it, at the file's [extents]: only
    /// the file's own clusters change, never the file system's records.
    fn raw_disk(&mut self) -> Option<&mut (dyn Disk + 'static)> {
        None
    }

    /// Marks a file or directory hidden + system (as Windows does for
    /// "System Volume Information").
    fn set_hidden_system(&mut self, _path: &str) -> Result<()> {
        Err(Error::unsupported("attributes on this file system"))
    }

    /// Writes zeros over free clusters from byte `cursor` of the volume, at
    /// most about `max` bytes per call; returns where to continue and
    /// whether the end was reached. Through an encrypted volume the zeros
    /// become ciphertext that looks random: this completes a quick format
    /// in the background (resumable from the cursor), and erases the traces
    /// of deleted files. Clusters in use, or reserved, are never touched.
    fn zero_free(&mut self, _cursor: u64, _max: u64) -> Result<(u64, bool)> {
        Err(Error::unsupported("filling free space on this file system"))
    }

    /// Moves a file or directory into another directory of the same volume
    /// without copying its data.
    fn move_item(&mut self, _path: &str, _dest_dir: &str) -> Result<()> {
        Err(Error::unsupported("moving on this file system"))
    }

    /// Checks the structures; with `repair`, fixes what is safe to fix
    /// (lost clusters, extra clusters, free counts, the exFAT bitmap).
    fn check(&mut self, _repair: bool) -> Result<CheckReport> {
        Err(Error::unsupported("checking this file system"))
    }
}

/// Refuses to move a directory into itself or below it.
pub(crate) fn check_move(path: &str, dest_dir: &str) -> Result<()> {
    let p = path.trim_end_matches('/');
    let d = dest_dir.trim_end_matches('/');
    if p.is_empty() {
        return Err(Error::invalid("cannot move the root"));
    }
    if d == p || d.starts_with(&format!("{p}/")) {
        return Err(Error::invalid("cannot move a folder into itself"));
    }
    Ok(())
}


/// Merges consecutive clusters into byte ranges.
pub(crate) fn runs(clusters: &[u32], base: u64, cluster_size: u64, len: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut left = len;
    for &c in clusters {
        if left == 0 {
            break;
        }
        let off = base + (c as u64 - 2) * cluster_size;
        let n = cluster_size.min(left);
        match out.last_mut() {
            Some((o, l)) if *o + *l == off => *l += n,
            _ => out.push((off, n)),
        }
        left -= n;
    }
    out
}

/// Identifies the file system in a decrypted volume and mounts it.
pub fn mount(mut disk: Box<dyn Disk>, read_only: bool, tz_offset_min: i32) -> Result<Box<dyn FileSystem>> {
    if disk.len() < 512 {
        return Err(Error::corrupt("volume too small"));
    }
    let mut boot = [0u8; 512];
    disk.read_at(0, &mut boot)?;
    match &boot[3..11] {
        b"EXFAT   " => return Ok(Box::new(exfat::Exfat::mount(disk, read_only, tz_offset_min)?)),
        b"NTFS    " => return Ok(Box::new(ntfs::Ntfs::mount(disk, read_only)?)),
        _ => {}
    }
    if &boot[3..7] == b"ReFS" {
        return Err(Error::unsupported("ReFS"));
    }
    if fat::looks_like_fat(&boot) {
        return Ok(Box::new(fat::Fat::mount(disk, read_only, tz_offset_min)?));
    }
    if boot.iter().all(|&b| b == 0) {
        return Err(Error::corrupt("the volume is not formatted"));
    }
    Err(Error::corrupt("no recognizable file system"))
}

/// Path components of "/a/b/c" (also accepts "a/b", "" and "/").
pub fn components(path: &str) -> Result<Vec<&str>> {
    path.split('/')
        .filter(|c| !c.is_empty())
        .map(|c| if c == "." || c == ".." { Err(Error::InvalidName) } else { Ok(c) })
        .collect()
}

/// (parent components, leaf name) of a non-root path.
pub fn split_parent(path: &str) -> Result<(Vec<&str>, &str)> {
    let mut comps = components(path)?;
    let leaf = comps.pop().ok_or(Error::invalid("the root has no parent"))?;
    Ok((comps, leaf))
}

/// Names Windows accepts: no control characters, none of `"*/:<>?\|`, no
/// trailing dot or space, 1..=255 UTF-16 units.
pub fn validate_name(name: &str) -> Result<()> {
    let units = name.encode_utf16().count();
    if units == 0 || units > 255 || name == "." || name == ".." {
        return Err(Error::InvalidName);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(Error::InvalidName);
    }
    if name.chars().any(|c| (c as u32) < 0x20 || "\"*/:<>?\\|".contains(c)) {
        return Err(Error::InvalidName);
    }
    Ok(())
}

pub fn same_name(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

#[cfg(test)]
mod tests;
