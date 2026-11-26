//! Partition tables (MBR with extended partitions, GPT) and views of a
//! byte range of a disk.

use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{le16, le32, le64};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// 1-based, in table order (logical partitions after the primaries).
    pub index: u32,
    pub start: u64,
    pub size: u64,
    pub scheme: &'static str,
    /// "0x07" for MBR, the type GUID for GPT.
    pub type_id: String,
    /// GPT partition name, or a description of the MBR type.
    pub name: String,
}

use crate::util::guid_string as guid;

fn mbr_type_name(t: u8) -> &'static str {
    match t {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x0B | 0x0C => "FAT32",
        0x07 => "NTFS / exFAT",
        0x27 => "Windows recovery",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0xAF => "macOS",
        _ => "",
    }
}

fn gpt_type_name(g: &str) -> &'static str {
    match g {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Basic data",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux",
        "48465300-0000-11AA-AA11-00306543ECAC" => "HFS+",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "APFS",
        _ => "",
    }
}

/// A file system boot sector at LBA 0 means a "superfloppy": no table.
fn looks_like_boot_sector(s: &[u8]) -> bool {
    let jump = (s[0] == 0xEB && s[2] == 0x90) || s[0] == 0xE9;
    jump && (matches!(&s[3..11], b"NTFS    " | b"EXFAT   " | b"-FVE-FS-" | b"MSWIN4.1" | b"MSDOS5.0" | b"mkfs.fat" | b"MSWIN4.0") || &s[82..87] == b"FAT32" || &s[54..59] == b"FAT16" || &s[54..59] == b"FAT12")
}

/// Reads the partition table. An empty list means the disk has none (a
/// whole-disk volume, or random data such as a whole-disk VeraCrypt volume).
pub fn read_table(disk: &mut dyn Disk, sector: u32) -> Result<Vec<Partition>> {
    let ss = sector as u64;
    let size = disk.len();
    if size < 2 * ss.max(512) {
        return Ok(Vec::new());
    }
    let mut s0 = vec![0u8; ss.max(512) as usize];
    disk.read_at(0, &mut s0)?;
    if s0[510] != 0x55 || s0[511] != 0xAA || looks_like_boot_sector(&s0) {
        return Ok(Vec::new());
    }
    let entries: Vec<&[u8]> = (0..4).map(|i| &s0[446 + 16 * i..462 + 16 * i]).collect();
    if entries.iter().any(|e| e[0] != 0 && e[0] != 0x80) {
        return Ok(Vec::new());
    }
    if entries.iter().any(|e| e[4] == 0xEE) {
        if let Some(gpt) = read_gpt(disk, ss)? {
            return Ok(gpt);
        }
    }
    let mut out = Vec::new();
    let mut index = 1u32;
    let mut extended = Vec::new();
    for e in &entries {
        let ty = e[4];
        let start = le32(e, 8) as u64 * ss;
        let len = le32(e, 12) as u64 * ss;
        if ty == 0 || len == 0 {
            continue;
        }
        if start + len > size || start == 0 {
            return Ok(Vec::new()); // not a real table
        }
        if matches!(ty, 0x05 | 0x0F | 0x85) {
            extended.push(start);
            continue;
        }
        out.push(Partition { index, start, size: len, scheme: "MBR", type_id: format!("0x{ty:02X}"), name: mbr_type_name(ty).into() });
        index += 1;
    }
    for ext in extended {
        let mut ebr = ext;
        for _ in 0..128 {
            let mut b = vec![0u8; ss.max(512) as usize];
            disk.read_at(ebr, &mut b)?;
            if b[510] != 0x55 || b[511] != 0xAA {
                break;
            }
            let (e1, e2) = (&b[446..462], &b[462..478]);
            let (ty, start, len) = (e1[4], ebr + le32(e1, 8) as u64 * ss, le32(e1, 12) as u64 * ss);
            if ty != 0 && len != 0 && start + len <= size {
                out.push(Partition { index, start, size: len, scheme: "MBR", type_id: format!("0x{ty:02X}"), name: mbr_type_name(ty).into() });
                index += 1;
            }
            let next = le32(e2, 8) as u64 * ss;
            if e2[4] == 0 || next == 0 {
                break;
            }
            ebr = ext + next;
            if ebr >= size {
                break;
            }
        }
    }
    let mut sorted = out.clone();
    sorted.sort_by_key(|p| p.start);
    if sorted.windows(2).any(|w| w[0].start + w[0].size > w[1].start) {
        return Ok(Vec::new());
    }
    Ok(out)
}

fn read_gpt(disk: &mut dyn Disk, ss: u64) -> Result<Option<Vec<Partition>>> {
    let mut h = vec![0u8; ss as usize];
    disk.read_at(ss, &mut h)?;
    if &h[..8] != b"EFI PART" {
        return Ok(None);
    }
    let size = disk.len();
    let entries_lba = le64(&h, 72);
    let count = le32(&h, 80).min(1024) as u64;
    let esize = le32(&h, 84) as u64;
    if !(128..=4096).contains(&esize) || entries_lba * ss + count * esize > size {
        return Ok(None);
    }
    let mut table = vec![0u8; (count * esize) as usize];
    disk.read_at(entries_lba * ss, &mut table)?;
    let mut out = Vec::new();
    for (i, e) in table.chunks_exact(esize as usize).enumerate() {
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = le64(e, 32);
        let last = le64(e, 40);
        if last < first || (last + 1) * ss > size {
            continue;
        }
        let ty = guid(&e[..16]);
        let units: Vec<u16> = (0..36).map(|k| le16(e, 56 + 2 * k)).take_while(|&u| u != 0).collect();
        let mut name = String::from_utf16_lossy(&units);
        if name.is_empty() {
            name = gpt_type_name(&ty).into();
        }
        out.push(Partition { index: i as u32 + 1, start: first * ss, size: (last - first + 1) * ss, scheme: "GPT", type_id: ty, name });
    }
    Ok(Some(out))
}

/// A disk shared by several views (a drive and its partitions).
pub type SharedDisk = Arc<Mutex<Box<dyn Disk>>>;

/// Bytes `[start, start + size)` of a shared disk.
pub struct DiskView {
    inner: SharedDisk,
    start: u64,
    size: u64,
    read_only: bool,
}

impl DiskView {
    pub fn new(inner: SharedDisk, start: u64, size: u64, read_only: bool) -> Result<DiskView> {
        let total = inner.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?.len();
        if start.checked_add(size).is_none_or(|e| e > total) {
            return Err(Error::invalid("partition outside the disk"));
        }
        Ok(DiskView { inner, start, size, read_only })
    }

    pub fn whole(inner: SharedDisk, read_only: bool) -> Result<DiskView> {
        let total = inner.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?.len();
        DiskView::new(inner, 0, total, read_only)
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(e) if e <= self.size => Ok(()),
            _ => Err(Error::invalid("access beyond the end of the partition")),
        }
    }
}

impl Disk for DiskView {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        self.inner.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?.read_at(self.start + offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check(offset, buf.len())?;
        self.inner.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?.write_at(self.start + offset, buf)
    }

    fn len(&self) -> u64 {
        self.size
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::corrupt("disk lock poisoned"))?.flush()
    }

    fn is_read_only(&self) -> bool {
        self.read_only || self.inner.lock().map(|d| d.is_read_only()).unwrap_or(true)
    }
}

/// Writes a fresh MBR with one partition spanning the disk from 1 MiB, of
/// the given type (0x07 for NTFS/exFAT/encrypted, 0x0C for FAT32).
pub fn write_single_partition_mbr(disk: &mut dyn Disk, sector: u32, ty: u8) -> Result<Partition> {
    let ss = sector as u64;
    let total = disk.len() / ss;
    let start = (1 << 20) / ss;
    if total <= start + 2048 || total > u32::MAX as u64 {
        return Err(Error::invalid("disk size not suitable for an MBR"));
    }
    let len = total - start;
    let mut mbr = vec![0u8; ss.max(512) as usize];
    let e = &mut mbr[446..462];
    e[0] = 0x00;
    // CHS fields: "beyond 8 GB" markers, as Windows writes for LBA-only use.
    e[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[4] = ty;
    e[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&(start as u32).to_le_bytes());
    e[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    let mut sig = [0u8; 4];
    sig.copy_from_slice(&(crate::util::now_unix() as u32 ^ 0x5153_4352).to_le_bytes());
    mbr[440..444].copy_from_slice(&sig);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    disk.write_at(0, &mbr)?;
    // Clear anything that could be mistaken for a GPT.
    disk.write_at(ss, &vec![0u8; ss as usize])?;
    disk.flush()?;
    Ok(Partition { index: 1, start: start * ss, size: len * ss, scheme: "MBR", type_id: format!("0x{ty:02X}"), name: mbr_type_name(ty).into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;

    #[test]
    fn mbr_round_trip_and_views() {
        let mut d = MemDisk::new(64 << 20);
        let p = write_single_partition_mbr(&mut d, 512, 0x07).unwrap();
        assert_eq!(p.start, 1 << 20);
        let t = read_table(&mut d, 512).unwrap();
        assert_eq!(t, vec![p.clone()]);
        let shared: SharedDisk = Arc::new(Mutex::new(Box::new(d)));
        let mut v = DiskView::new(shared.clone(), p.start, p.size, false).unwrap();
        v.write_at(0, b"inside").unwrap();
        let mut buf = [0u8; 6];
        shared.lock().unwrap().read_at(1 << 20, &mut buf).unwrap();
        assert_eq!(&buf, b"inside");
        assert!(v.write_at(p.size - 2, b"abc").is_err());
    }

    #[test]
    fn random_and_boot_sectors_are_not_tables() {
        let mut d = MemDisk::new(4 << 20);
        for (i, b) in d.data.iter_mut().enumerate().take(512) {
            *b = (i * 37 % 251) as u8;
        }
        d.data[510] = 0x55;
        d.data[511] = 0xAA;
        assert!(read_table(&mut d, 512).unwrap().is_empty());
        let mut f = MemDisk::new(4 << 20);
        let plan = crate::fs::format_plan(4 << 20, "X", 1).unwrap();
        crate::fs::apply_patches(&plan.patches, 0, &mut f.data);
        assert!(read_table(&mut f, 512).unwrap().is_empty());
    }

    #[test]
    fn gpt_entries() {
        let mut d = MemDisk::new(8 << 20);
        d.data[446 + 4] = 0xEE;
        d.data[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        d.data[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        d.data[510] = 0x55;
        d.data[511] = 0xAA;
        let h = &mut d.data[512..1024];
        h[..8].copy_from_slice(b"EFI PART");
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        let e = &mut d.data[1024..1152];
        // Basic data GUID EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, mixed endian.
        e[..16].copy_from_slice(&[0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
        e[32..40].copy_from_slice(&2048u64.to_le_bytes());
        e[40..48].copy_from_slice(&10_000u64.to_le_bytes());
        for (k, u) in "Data".encode_utf16().enumerate() {
            e[56 + 2 * k..58 + 2 * k].copy_from_slice(&u.to_le_bytes());
        }
        let t = read_table(&mut d, 512).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].scheme, t[0].start, t[0].size, t[0].name.as_str()), ("GPT", 2048 * 512, 7953 * 512, "Data"));
        assert_eq!(t[0].type_id, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }
}
