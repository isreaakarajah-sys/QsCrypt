//! File systems inside a decrypted volume.
//!
//! - FAT12/16/32: read and write, long file names.
//! - exFAT: read-only for now.
//! - NTFS / ReFS: recognized and reported as unsupported.

pub mod exfat;
pub mod fat;
mod fat_format;

pub use fat_format::{apply_patches, format_plan, FatPlan};

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

pub trait FileSystem: Send {
    /// "FAT12", "FAT16", "FAT32", "exFAT".
    fn kind(&self) -> &'static str;
    fn label(&self) -> String;
    fn read_only(&self) -> bool;
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
}

/// Identifies the file system in a decrypted volume and mounts it.
pub fn mount(mut disk: Box<dyn Disk>, read_only: bool, tz_offset_min: i32) -> Result<Box<dyn FileSystem>> {
    if disk.len() < 512 {
        return Err(Error::corrupt("volume too small"));
    }
    let mut boot = [0u8; 512];
    disk.read_at(0, &mut boot)?;
    match &boot[3..11] {
        b"EXFAT   " => return Ok(Box::new(exfat::Exfat::mount(disk, tz_offset_min)?)),
        b"NTFS    " => return Err(Error::unsupported("NTFS")),
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
