//! Fixed VHD disk images: a raw disk followed by a 512-byte footer.
//!
//! Windows mounts a `.vhd` file natively (double-click in Explorer, or
//! Disk Management), so a BitLocker volume inside one opens on any Windows
//! PC with nothing installed: QsCrypt writes a partition table, the
//! BitLocker volume in its single partition, and the footer.

use crate::bde::{self, BdeCreateOptions};
use crate::crypto::Backend;
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::part::{self, DiskView, SharedDisk};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Size of the footer at the end of the file.
pub const FOOTER: u64 = 512;

const COOKIE: &[u8; 8] = b"conectix";
const DISK_FIXED: u32 = 2;
/// 2000-01-01 00:00:00 UTC, the VHD epoch.
const EPOCH: i64 = 946_684_800;

/// Cylinders, heads and sectors per track as the VHD specification computes them.
pub fn geometry(size: u64) -> (u16, u8, u8) {
    let mut total = size / 512;
    if total > 65535 * 16 * 255 {
        total = 65535 * 16 * 255;
    }
    let (spt, heads, cth);
    if total >= 65535 * 16 * 63 {
        spt = 255;
        heads = 16;
        cth = total / spt;
    } else {
        let mut s = 17;
        let mut c = total / s;
        let mut h = (c + 1023) / 1024;
        if h < 4 {
            h = 4;
        }
        if c >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            c = total / s;
        }
        if c >= h * 1024 {
            s = 63;
            h = 16;
            c = total / s;
        }
        spt = s;
        heads = h;
        cth = c;
    }
    ((cth / heads) as u16, heads as u8, spt as u8)
}

fn checksum(f: &[u8; 512]) -> u32 {
    let sum: u32 = f.iter().enumerate().filter(|(i, _)| !(64..68).contains(i)).fold(0u32, |a, (_, &b)| a.wrapping_add(b as u32));
    !sum
}

/// The footer of a fixed disk of `size` bytes (the file is `size + 512`).
pub fn footer(size: u64, unique_id: [u8; 16], now_unix: i64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(COOKIE);
    f[8..12].copy_from_slice(&2u32.to_be_bytes()); // features: reserved bit
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // format version 1.0
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes()); // no dynamic header
    f[24..28].copy_from_slice(&((now_unix - EPOCH).max(0) as u32).to_be_bytes());
    f[28..32].copy_from_slice(b"qscr");
    f[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    f[36..40].copy_from_slice(b"Wi2k");
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    let (c, h, s) = geometry(size);
    f[56..58].copy_from_slice(&c.to_be_bytes());
    f[58] = h;
    f[59] = s;
    f[60..64].copy_from_slice(&DISK_FIXED.to_be_bytes());
    f[68..84].copy_from_slice(&unique_id);
    let sum = checksum(&f);
    f[64..68].copy_from_slice(&sum.to_be_bytes());
    f
}

/// True if `f` is a valid fixed-disk footer for a disk of `size` bytes.
pub fn is_fixed_footer(f: &[u8; 512], size: u64) -> bool {
    f[0..8] == COOKIE[..]
        && u32::from_be_bytes(f[60..64].try_into().unwrap()) == DISK_FIXED
        && u64::from_be_bytes(f[48..56].try_into().unwrap()) == size
        && u32::from_be_bytes(f[64..68].try_into().unwrap()) == checksum(f)
}

/// True if the disk is a fixed VHD (its last 512 bytes are a footer).
pub fn is_vhd(disk: &mut dyn Disk) -> bool {
    let len = disk.len();
    if len < 2 * FOOTER || len % 512 != 0 {
        return false;
    }
    let mut f = [0u8; 512];
    disk.read_at(len - FOOTER, &mut f).is_ok() && is_fixed_footer(&f, len - FOOTER)
}

/// Writes the footer of a disk image whose disk part is `size` bytes.
pub fn write_footer(disk: &mut dyn Disk, size: u64, unique_id: [u8; 16], now_unix: i64) -> Result<()> {
    disk.write_at(size, &footer(size, unique_id, now_unix))?;
    disk.flush()
}

/// Size of a VHD file for a requested size: whole MiB of disk plus the footer.
pub fn image_size(requested: u64) -> u64 {
    (requested.saturating_sub(FOOTER) >> 20 << 20) + FOOTER
}

/// Writes a fixed VHD that Windows mounts natively: an MBR with a single
/// partition from 1 MiB holding a new BitLocker volume, then the footer.
/// `disk` must already have its final length (see [`image_size`]).
/// Returns the recovery password.
pub fn create_bitlocker_vhd(
    backend: &dyn Backend,
    disk: Box<dyn Disk>,
    opts: &BdeCreateOptions,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    cancel: &AtomicBool,
) -> Result<String> {
    let total = disk.len();
    if total < (65 << 20) + FOOTER || (total - FOOTER) % (1 << 20) != 0 {
        return Err(Error::invalid("BitLocker volumes need at least 64 MiB"));
    }
    let size = total - FOOTER;
    let shared: SharedDisk = Arc::new(Mutex::new(disk));
    let p = {
        let mut whole = DiskView::new(shared.clone(), 0, size, false)?;
        part::write_single_partition_mbr(&mut whole, 512, 0x07)?
    };
    let o = BdeCreateOptions { hidden_sectors: (p.start / 512) as u32, ..*opts };
    let view = DiskView::new(shared.clone(), p.start, p.size, false)?;
    let recovery = bde::create_bitlocker(backend, Box::new(view), &o, progress, cancel)?;
    let mut id = [0u8; 16];
    backend.fill_random(&mut id)?;
    let mut d = shared.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?;
    write_footer(&mut **d, size, id, crate::util::now_unix())?;
    Ok(recovery)
}

/// The volume inside a fixed VHD: its first partition. Other disks are
/// returned unchanged.
pub fn unwrap(mut disk: Box<dyn Disk>, read_only: bool) -> Result<Box<dyn Disk>> {
    if !is_vhd(disk.as_mut()) {
        return Ok(disk);
    }
    let limit = disk.len() - FOOTER;
    let parts = part::read_table(disk.as_mut(), 512).unwrap_or_default();
    let Some(p) = parts.into_iter().find(|p| p.size > 0 && p.start + p.size <= limit) else {
        return Ok(disk);
    };
    let shared: SharedDisk = Arc::new(Mutex::new(disk));
    Ok(Box::new(DiskView::new(shared, p.start, p.size, read_only)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;

    #[test]
    fn footer_round_trip() {
        let size = 64u64 << 20;
        let f = footer(size, [7; 16], 1_764_000_000);
        assert!(is_fixed_footer(&f, size));
        assert!(!is_fixed_footer(&f, size + 512));
        let mut bad = f;
        bad[100] ^= 1;
        assert!(!is_fixed_footer(&bad, size));
        let mut d = MemDisk::new((size + FOOTER) as usize);
        assert!(!is_vhd(&mut d));
        write_footer(&mut d, size, [7; 16], 1_764_000_000).unwrap();
        assert!(is_vhd(&mut d));
    }

    #[test]
    fn bitlocker_inside_a_vhd() {
        use crate::bde::{Credential, Method};
        use crate::fs::FsChoice;
        use crate::reference::RefBackend;
        let b = RefBackend::new();
        let no = AtomicBool::new(false);
        let total = image_size(70 << 20);
        assert_eq!(total, (70 << 20) - (1 << 20) + FOOTER);
        let shared: SharedDisk = Arc::new(Mutex::new(Box::new(MemDisk::new(total as usize))));
        let opts = BdeCreateOptions { password: "Vhd password 1", recovery_key: None, method: Method::Xts128, filesystem: FsChoice::Fat, label: "QSVHD", description: "QsCrypt", quick: true, hidden_sectors: 0 };
        let whole = Box::new(DiskView::whole(shared.clone(), false).unwrap());
        create_bitlocker_vhd(&b, whole, &opts, &mut |_, _| true, &no).unwrap();
        let mut d: Box<dyn Disk> = Box::new(DiskView::whole(shared.clone(), true).unwrap());
        assert!(is_vhd(d.as_mut()));
        let t = part::read_table(d.as_mut(), 512).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].start, 1 << 20);
        assert_eq!(t[0].start + t[0].size, total - FOOTER);
        let mut inner = unwrap(d, true).unwrap();
        let mut boot = [0u8; 512];
        inner.read_at(0, &mut boot).unwrap();
        assert!(bde::is_bitlocker(&boot));
        assert_eq!(u32::from_le_bytes(boot[28..32].try_into().unwrap()), 2048);
        let (_, _, vol) = bde::open(&b, inner, &Credential::Password("Vhd password 1"), true, &no).unwrap();
        let fs = crate::fs::mount(Box::new(vol), true, 0).unwrap();
        assert_eq!(fs.label(), "QSVHD");
        // Too small, or not sized for an image.
        let small = Box::new(MemDisk::new(image_size(40 << 20) as usize));
        assert!(create_bitlocker_vhd(&b, small, &opts, &mut |_, _| true, &no).is_err());
        let odd = Box::new(MemDisk::new((80 << 20) as usize));
        assert!(create_bitlocker_vhd(&b, odd, &opts, &mut |_, _| true, &no).is_err());
    }

    #[test]
    fn geometry_matches_the_specification() {
        // 64 MiB: 131072 sectors -> 17 spt gives 7710 c*h, heads 8, cylinders 963.
        assert_eq!(geometry(64 << 20), (963, 8, 17));
        // 2 GiB: falls through to 63 spt with 16 heads.
        let (c, h, s) = geometry(2 << 30);
        assert_eq!((h, s), (16, 63));
        assert_eq!(c as u64, (2u64 << 30) / 512 / 63 / 16);
        // Very large disks are capped at 65535 cylinders.
        assert_eq!(geometry(4 << 40), (65535, 16, 255));
    }
}
