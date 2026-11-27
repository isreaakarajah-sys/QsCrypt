//! FAT12/16/32 with VFAT long file names (Microsoft "fatgen103").
//!
//! The first FAT is kept in memory and written back to every copy on
//! flush. Writes go data first, then the FAT, then the directory entry, so
//! an interruption can only leak clusters, never corrupt existing files.

use super::{components, same_name, split_parent, validate_name, CheckReport, DirEntry, FileSystem, Progress};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{civil_from_unix, le16, le32, now_unix, put_le16, put_le32, unix_from_civil, Civil};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const ENTRY: usize = 32;
const MAX_DIR_ENTRIES: usize = 65_536;
const IO_CHUNK: usize = 1 << 20;
/// Offsets of the 13 UTF-16 characters inside a long-name entry.
const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

pub fn looks_like_fat(boot: &[u8]) -> bool {
    let bps = le16(boot, 11);
    let spc = boot[13];
    let fats = boot[16];
    matches!(boot[0], 0xEB | 0xE9)
        && matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc != 0
        && spc.is_power_of_two()
        && le16(boot, 14) != 0
        && (1..=4).contains(&fats)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirLoc {
    /// The fixed root directory region of FAT12/16.
    FixedRoot,
    /// A directory stored in a cluster chain (always for FAT32).
    Chain(u32),
}

struct RawDir {
    loc: DirLoc,
    data: Vec<u8>,
    clusters: Vec<u32>,
}

#[derive(Clone, Debug)]
struct Item {
    name: String,
    short: [u8; 11],
    attr: u8,
    first_cluster: u32,
    size: u32,
    /// Index of the first entry of the set (a long-name entry or the 8.3 entry).
    start: usize,
    /// Index of the 8.3 entry.
    sfn: usize,
    created: (u16, u16),
    modified: (u16, u16),
}

impl Item {
    fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
}

pub struct Fat {
    disk: Box<dyn Disk>,
    ty: FatType,
    bps: u32,
    cluster_size: u32,
    fat_offset: u64,
    fat_bytes: usize,
    num_fats: u32,
    root_offset: u64,
    root_entries: u32,
    data_offset: u64,
    clusters: u32,
    root_cluster: u32,
    fsinfo: Option<u64>,
    fat: Vec<u8>,
    dirty: Vec<bool>,
    free_hint: u32,
    free_count: Option<u32>,
    /// Clusters [lo, hi) the allocator must not use, and how many of them are free.
    reserved: Option<(u32, u32)>,
    reserved_free: u32,
    read_only: bool,
    tz: i32,
    label: String,
}

impl Fat {
    pub fn mount(mut disk: Box<dyn Disk>, read_only: bool, tz_offset_min: i32) -> Result<Fat> {
        let mut b = [0u8; 512];
        disk.read_at(0, &mut b)?;
        if !looks_like_fat(&b) {
            return Err(Error::corrupt("not a FAT boot sector"));
        }
        let bps = le16(&b, 11) as u32;
        let spc = b[13] as u32;
        let reserved = le16(&b, 14) as u32;
        let num_fats = b[16] as u32;
        let root_entries = le16(&b, 17) as u32;
        let tot16 = le16(&b, 19) as u32;
        let fat16_size = le16(&b, 22) as u32;
        let tot32 = le32(&b, 32);
        let fat_size = if fat16_size != 0 { fat16_size } else { le32(&b, 36) };
        let total = if tot16 != 0 { tot16 } else { tot32 };
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let first_data = reserved as u64 + num_fats as u64 * fat_size as u64 + root_sectors as u64;
        if fat_size == 0 || total as u64 <= first_data {
            return Err(Error::corrupt("inconsistent FAT geometry"));
        }
        if total as u64 * bps as u64 > disk.len() {
            return Err(Error::corrupt("file system larger than the volume"));
        }
        let clusters = ((total as u64 - first_data) / spc as u64) as u32;
        let ty = if clusters < 4085 {
            FatType::Fat12
        } else if clusters < 65_525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };
        let fat_bytes = fat_size as usize * bps as usize;
        let needed = match ty {
            FatType::Fat12 => (clusters as usize + 2) * 3 / 2 + 1,
            FatType::Fat16 => (clusters as usize + 2) * 2,
            FatType::Fat32 => (clusters as usize + 2) * 4,
        };
        if needed > fat_bytes {
            return Err(Error::corrupt("FAT too small for the cluster count"));
        }
        if fat_bytes > 256 << 20 {
            return Err(Error::unsupported("FAT larger than 256 MiB"));
        }
        let (root_cluster, fsinfo) = if ty == FatType::Fat32 {
            let fsinfo_sector = le16(&b, 48) as u64;
            let fsinfo = (fsinfo_sector != 0 && fsinfo_sector != 0xFFFF && fsinfo_sector < reserved as u64)
                .then_some(fsinfo_sector * bps as u64);
            (le32(&b, 44), fsinfo)
        } else {
            (0, None)
        };
        let fat_offset = reserved as u64 * bps as u64;
        let mut fat = vec![0u8; fat_bytes];
        disk.read_at(fat_offset, &mut fat)?;
        let label_off = if ty == FatType::Fat32 { 71 } else { 43 };
        let boot_sig = if ty == FatType::Fat32 { b[66] } else { b[38] };
        let mut label = if boot_sig == 0x29 { decode_short_part(&b[label_off..label_off + 11], false) } else { String::new() };
        if label == "NO NAME" {
            label.clear();
        }
        let read_only = read_only || disk.is_read_only();
        let mut fs = Fat {
            disk,
            ty,
            bps,
            cluster_size: spc * bps,
            fat_offset,
            fat_bytes,
            num_fats,
            root_offset: fat_offset + num_fats as u64 * fat_bytes as u64,
            root_entries,
            data_offset: first_data * bps as u64,
            clusters,
            root_cluster,
            fsinfo,
            fat,
            dirty: vec![false; fat_size as usize],
            free_hint: 2,
            reserved: None,
            reserved_free: 0,
            free_count: None,
            read_only,
            tz: tz_offset_min,
            label,
        };
        if ty == FatType::Fat32 && !fs.valid_cluster(root_cluster) {
            return Err(Error::corrupt("bad FAT32 root cluster"));
        }
        if let Some(l) = fs.root_label()? {
            fs.label = l;
        }
        Ok(fs)
    }

    pub fn fat_type(&self) -> FatType {
        self.ty
    }

    // ------------------------------------------------------------ FAT table

    fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    fn entry(&self, c: u32) -> u32 {
        let c = c as usize;
        match self.ty {
            FatType::Fat12 => {
                let o = c + c / 2;
                let v = le16(&self.fat, o) as u32;
                if c & 1 == 1 {
                    v >> 4
                } else {
                    v & 0xFFF
                }
            }
            FatType::Fat16 => le16(&self.fat, c * 2) as u32,
            FatType::Fat32 => le32(&self.fat, c * 4) & 0x0FFF_FFFF,
        }
    }

    fn set_entry(&mut self, c: u32, v: u32) {
        let c = c as usize;
        let (o, len) = match self.ty {
            FatType::Fat12 => {
                let o = c + c / 2;
                let mut w = le16(&self.fat, o);
                if c & 1 == 1 {
                    w = (w & 0x000F) | ((v as u16) << 4);
                } else {
                    w = (w & 0xF000) | (v as u16 & 0x0FFF);
                }
                put_le16(&mut self.fat, o, w);
                (o, 2)
            }
            FatType::Fat16 => {
                put_le16(&mut self.fat, c * 2, v as u16);
                (c * 2, 2)
            }
            FatType::Fat32 => {
                let old = le32(&self.fat, c * 4);
                put_le32(&mut self.fat, c * 4, (old & 0xF000_0000) | (v & 0x0FFF_FFFF));
                (c * 4, 4)
            }
        };
        let bps = self.bps as usize;
        self.dirty[o / bps] = true;
        self.dirty[(o + len - 1) / bps] = true;
    }

    fn eoc(&self) -> u32 {
        match self.ty {
            FatType::Fat12 => 0xFFF,
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }

    fn is_eoc(&self, v: u32) -> bool {
        match self.ty {
            FatType::Fat12 => v >= 0xFF8,
            FatType::Fat16 => v >= 0xFFF8,
            FatType::Fat32 => v >= 0x0FFF_FFF8,
        }
    }

    fn chain(&self, first: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        if first == 0 {
            return Ok(out);
        }
        let mut c = first;
        loop {
            if !self.valid_cluster(c) {
                return Err(Error::corrupt(format!("cluster chain points to {c}")));
            }
            out.push(c);
            if out.len() > self.clusters as usize {
                return Err(Error::corrupt("cluster chain loops"));
            }
            let next = self.entry(c);
            if self.is_eoc(next) {
                return Ok(out);
            }
            c = next;
        }
    }

    fn free_clusters(&mut self) -> u32 {
        if let Some(n) = self.free_count {
            return n;
        }
        let n = (2..self.clusters + 2).filter(|&c| self.entry(c) == 0).count() as u32;
        self.free_count = Some(n);
        n
    }

    fn is_reserved(&self, c: u32) -> bool {
        self.reserved.is_some_and(|(lo, hi)| c >= lo && c < hi)
    }

    /// Free clusters the allocator may use.
    fn available(&mut self) -> u32 {
        self.free_clusters().saturating_sub(self.reserved_free)
    }

    /// Allocates `n` clusters linked as one chain ending in EOC.
    fn alloc(&mut self, n: u32) -> Result<Vec<u32>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.available() < n {
            return Err(Error::NoSpace);
        }
        let mut got = Vec::with_capacity(n as usize);
        let mut c = if self.valid_cluster(self.free_hint) { self.free_hint } else { 2 };
        let mut scanned = 0u32;
        while got.len() < n as usize {
            if c >= self.clusters + 2 {
                c = 2;
            }
            if self.entry(c) == 0 && !self.is_reserved(c) {
                got.push(c);
            }
            c += 1;
            scanned += 1;
            if scanned > self.clusters + 2 {
                return Err(Error::NoSpace);
            }
        }
        for w in got.windows(2) {
            self.set_entry(w[0], w[1]);
        }
        let last = *got.last().unwrap();
        let eoc = self.eoc();
        self.set_entry(last, eoc);
        self.free_hint = last + 1;
        self.free_count = Some(self.free_clusters() - n);
        Ok(got)
    }

    fn release(&mut self, clusters: &[u32]) {
        for &c in clusters {
            self.set_entry(c, 0);
        }
        if let Some(n) = self.free_count {
            self.free_count = Some(n + clusters.len() as u32);
        }
        if let Some(&first) = clusters.first() {
            self.free_hint = self.free_hint.min(first);
        }
    }

    fn flush_fat(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let bps = self.bps as usize;
        let mut s = 0;
        while s < self.dirty.len() {
            if !self.dirty[s] {
                s += 1;
                continue;
            }
            let mut e = s;
            while e < self.dirty.len() && self.dirty[e] {
                e += 1;
            }
            for f in 0..self.num_fats as u64 {
                let off = self.fat_offset + f * self.fat_bytes as u64 + (s * bps) as u64;
                self.disk.write_at(off, &self.fat[s * bps..e * bps])?;
            }
            for d in &mut self.dirty[s..e] {
                *d = false;
            }
            s = e;
        }
        if let (Some(off), Some(free)) = (self.fsinfo, self.free_count) {
            let mut sec = vec![0u8; 512];
            self.disk.read_at(off, &mut sec)?;
            if le32(&sec, 0) == 0x4161_5252 && le32(&sec, 484) == 0x6141_7272 {
                put_le32(&mut sec, 488, free);
                put_le32(&mut sec, 492, self.free_hint);
                self.disk.write_at(off, &sec)?;
            }
        }
        Ok(())
    }

    fn cluster_offset(&self, c: u32) -> u64 {
        self.data_offset + (c as u64 - 2) * self.cluster_size as u64
    }

    // ------------------------------------------------------------ directories

    fn read_dir(&mut self, loc: DirLoc) -> Result<RawDir> {
        match loc {
            DirLoc::FixedRoot => {
                let mut data = vec![0u8; self.root_entries as usize * ENTRY];
                self.disk.read_at(self.root_offset, &mut data)?;
                Ok(RawDir { loc, data, clusters: Vec::new() })
            }
            DirLoc::Chain(first) => {
                let clusters = self.chain(first)?;
                let cs = self.cluster_size as usize;
                if clusters.len() * cs > MAX_DIR_ENTRIES * ENTRY {
                    return Err(Error::corrupt("directory too large"));
                }
                let mut data = vec![0u8; clusters.len() * cs];
                for (i, &c) in clusters.iter().enumerate() {
                    let off = self.cluster_offset(c);
                    self.disk.read_at(off, &mut data[i * cs..(i + 1) * cs])?;
                }
                Ok(RawDir { loc, data, clusters })
            }
        }
    }

    fn entry_offset(&self, dir: &RawDir, index: usize) -> u64 {
        match dir.loc {
            DirLoc::FixedRoot => self.root_offset + (index * ENTRY) as u64,
            DirLoc::Chain(_) => {
                let pos = index * ENTRY;
                let cs = self.cluster_size as usize;
                self.cluster_offset(dir.clusters[pos / cs]) + (pos % cs) as u64
            }
        }
    }

    fn write_entries(&mut self, dir: &RawDir, from: usize, count: usize) -> Result<()> {
        for i in from..from + count {
            let off = self.entry_offset(dir, i);
            self.disk.write_at(off, &dir.data[i * ENTRY..(i + 1) * ENTRY])?;
        }
        Ok(())
    }

    fn root_loc(&self) -> DirLoc {
        if self.ty == FatType::Fat32 {
            DirLoc::Chain(self.root_cluster)
        } else {
            DirLoc::FixedRoot
        }
    }

    fn root_label(&mut self) -> Result<Option<String>> {
        let dir = self.read_dir(self.root_loc())?;
        for e in dir.data.chunks_exact(ENTRY) {
            if e[0] == 0 {
                break;
            }
            if e[0] != 0xE5 && e[11] & (ATTR_LFN | ATTR_DIRECTORY) == ATTR_VOLUME_ID {
                return Ok(Some(decode_short_part(&e[..11], false)));
            }
        }
        Ok(None)
    }

    fn parse(&self, dir: &RawDir) -> Vec<Item> {
        let mut items = Vec::new();
        let mut parts: Vec<Option<[u16; 13]>> = Vec::new();
        let mut expect = 0u8;
        let mut checksum = 0u8;
        let mut set_start = 0usize;
        for (i, e) in dir.data.chunks_exact(ENTRY).enumerate() {
            if e[0] == 0x00 {
                break;
            }
            if e[0] == 0xE5 {
                expect = 0;
                continue;
            }
            let attr = e[11];
            if attr & 0x3F == ATTR_LFN {
                let ord = e[0];
                let seq = ord & 0x1F;
                if ord & 0x40 != 0 {
                    if seq == 0 || seq > 20 {
                        expect = 0;
                        continue;
                    }
                    parts = vec![None; seq as usize];
                    checksum = e[13];
                    set_start = i;
                } else if expect == 0 || seq != expect - 1 || e[13] != checksum {
                    expect = 0;
                    continue;
                }
                let mut chars = [0u16; 13];
                for (k, &o) in LFN_OFFSETS.iter().enumerate() {
                    chars[k] = le16(e, o);
                }
                parts[seq as usize - 1] = Some(chars);
                expect = seq;
                continue;
            }
            let short: [u8; 11] = e[..11].try_into().unwrap();
            let long_ok = expect == 1 && sfn_checksum(&short) == checksum && parts.iter().all(|p| p.is_some());
            let long = long_ok.then(|| {
                let units: Vec<u16> = parts.iter().flat_map(|p| p.unwrap()).take_while(|&u| u != 0).collect();
                String::from_utf16_lossy(&units)
            });
            let start = if long_ok { set_start } else { i };
            expect = 0;
            if attr & ATTR_VOLUME_ID != 0 {
                continue;
            }
            if &short == b".          " || &short == b"..         " {
                continue;
            }
            let name = long.unwrap_or_else(|| decode_short(&short, e[12]));
            let hi = if self.ty == FatType::Fat32 { (le16(e, 20) as u32) << 16 } else { 0 };
            items.push(Item {
                name,
                short,
                attr,
                first_cluster: hi | le16(e, 26) as u32,
                size: le32(e, 28),
                start,
                sfn: i,
                created: (le16(e, 16), le16(e, 14)),
                modified: (le16(e, 24), le16(e, 22)),
            });
        }
        items
    }

    fn find(&self, items: &[Item], name: &str) -> Option<Item> {
        items.iter().find(|it| same_name(&it.name, name) || same_name(&decode_short(&it.short, 0), name)).cloned()
    }

    fn resolve_dir(&mut self, comps: &[&str]) -> Result<DirLoc> {
        let mut loc = self.root_loc();
        for comp in comps {
            let dir = self.read_dir(loc)?;
            let items = self.parse(&dir);
            let it = self.find(&items, comp).ok_or(Error::NotFound)?;
            if !it.is_dir() {
                return Err(Error::NotADirectory);
            }
            loc = if it.first_cluster == 0 { self.root_loc() } else { DirLoc::Chain(it.first_cluster) };
        }
        Ok(loc)
    }

    /// (parent directory, the item) for a non-root path.
    fn resolve_item(&mut self, path: &str) -> Result<(RawDir, Item)> {
        let (parent, leaf) = split_parent(path)?;
        let loc = self.resolve_dir(&parent)?;
        let dir = self.read_dir(loc)?;
        let items = self.parse(&dir);
        let it = self.find(&items, leaf).ok_or(Error::NotFound)?;
        Ok((dir, it))
    }

    /// Index of `n` consecutive free entries, growing the directory if needed.
    fn free_slots(&mut self, dir: &mut RawDir, n: usize) -> Result<usize> {
        loop {
            let total = dir.data.len() / ENTRY;
            let mut run = 0;
            for i in 0..total {
                let first = dir.data[i * ENTRY];
                if first == 0x00 {
                    // Everything from an end marker on is free.
                    if total - i >= n {
                        return Ok(i);
                    }
                    break;
                }
                if first == 0xE5 {
                    run += 1;
                    if run == n {
                        return Ok(i + 1 - n);
                    }
                } else {
                    run = 0;
                }
            }
            let DirLoc::Chain(first) = dir.loc else {
                return Err(Error::NoSpace);
            };
            if total + self.cluster_size as usize / ENTRY > MAX_DIR_ENTRIES {
                return Err(Error::NoSpace);
            }
            // Append a zeroed cluster. A trailing 0x00 region now runs on into
            // it, so the next scan finds room starting at the old end marker.
            let new = self.alloc(1)?[0];
            let zeros = vec![0u8; self.cluster_size as usize];
            self.disk.write_at(self.cluster_offset(new), &zeros)?;
            let last = *dir.clusters.last().unwrap_or(&first);
            self.set_entry(last, new);
            dir.clusters.push(new);
            dir.data.extend_from_slice(&zeros);
        }
    }

    fn short_names(&self, dir: &RawDir) -> Vec<[u8; 11]> {
        dir.data
            .chunks_exact(ENTRY)
            .take_while(|e| e[0] != 0)
            .filter(|e| e[0] != 0xE5 && e[11] & 0x3F != ATTR_LFN)
            .map(|e| e[..11].try_into().unwrap())
            .collect()
    }

    fn fat_time(&self, unix: i64) -> (u16, u16) {
        let c = civil_from_unix(unix + self.tz as i64 * 60);
        if c.year < 1980 {
            return ((1 << 5) | 1, 0);
        }
        let year = c.year.min(2107) as u16;
        let date = ((year - 1980) << 9) | ((c.month as u16) << 5) | c.day as u16;
        let time = ((c.hour as u16) << 11) | ((c.minute as u16) << 5) | (c.second as u16 / 2);
        (date, time)
    }

    fn unix_time(&self, (date, time): (u16, u16)) -> i64 {
        if date == 0 {
            return 0;
        }
        let civil = Civil {
            year: 1980 + (date >> 9) as i64,
            month: ((date >> 5) & 0xF).clamp(1, 12) as u32,
            day: (date & 0x1F).clamp(1, 31) as u32,
            hour: (time >> 11).min(23) as u32,
            minute: ((time >> 5) & 0x3F).min(59) as u32,
            second: ((time & 0x1F) * 2).min(59) as u32,
        };
        unix_from_civil(&civil) - self.tz as i64 * 60
    }

    fn to_entry(&self, it: &Item) -> DirEntry {
        DirEntry { name: it.name.clone(), is_dir: it.is_dir(), size: if it.is_dir() { 0 } else { it.size as u64 }, modified: self.unix_time(it.modified) }
    }

    /// Builds the long-name entries plus the 8.3 entry for `name`.
    fn entry_set(&self, name: &str, short: [u8; 11], nt_case: u8, needs_lfn: bool, attr: u8, first: u32, size: u32, created: (u16, u16), modified: (u16, u16)) -> Vec<[u8; ENTRY]> {
        let mut out = Vec::new();
        if needs_lfn {
            let units: Vec<u16> = name.encode_utf16().collect();
            let count = units.len().div_ceil(13);
            let sum = sfn_checksum(&short);
            for seq in (1..=count).rev() {
                let mut e = [0u8; ENTRY];
                e[0] = seq as u8 | if seq == count { 0x40 } else { 0 };
                e[11] = ATTR_LFN;
                e[13] = sum;
                for (k, &o) in LFN_OFFSETS.iter().enumerate() {
                    let idx = (seq - 1) * 13 + k;
                    let u = match idx.cmp(&units.len()) {
                        std::cmp::Ordering::Less => units[idx],
                        std::cmp::Ordering::Equal => 0x0000,
                        std::cmp::Ordering::Greater => 0xFFFF,
                    };
                    put_le16(&mut e, o, u);
                }
                out.push(e);
            }
        }
        let mut e = [0u8; ENTRY];
        e[..11].copy_from_slice(&short);
        e[11] = attr;
        e[12] = nt_case;
        put_le16(&mut e, 14, created.1);
        put_le16(&mut e, 16, created.0);
        put_le16(&mut e, 18, modified.0);
        if self.ty == FatType::Fat32 {
            put_le16(&mut e, 20, (first >> 16) as u16);
        }
        put_le16(&mut e, 22, modified.1);
        put_le16(&mut e, 24, modified.0);
        put_le16(&mut e, 26, first as u16);
        put_le32(&mut e, 28, size);
        out.push(e);
        out
    }

    /// Adds an entry set to `dir` and writes it.
    #[allow(clippy::too_many_arguments)]
    fn add_entry(&mut self, dir: &mut RawDir, name: &str, attr: u8, first: u32, size: u32, created: (u16, u16), modified: (u16, u16)) -> Result<()> {
        let existing = self.short_names(dir);
        let (short, nt_case, needs_lfn) = make_short_name(name, &existing)?;
        let set = self.entry_set(name, short, nt_case, needs_lfn, attr, first, size, created, modified);
        let at = self.free_slots(dir, set.len())?;
        for (k, e) in set.iter().enumerate() {
            dir.data[(at + k) * ENTRY..(at + k + 1) * ENTRY].copy_from_slice(e);
        }
        // The FAT may have changed while growing the directory.
        self.flush_fat()?;
        self.write_entries(dir, at, set.len())
    }

    fn delete_entries(&mut self, dir: &mut RawDir, it: &Item) -> Result<()> {
        for i in it.start..=it.sfn {
            dir.data[i * ENTRY] = 0xE5;
        }
        self.write_entries(dir, it.start, it.sfn - it.start + 1)
    }

    fn remove_item(&mut self, dir: &mut RawDir, it: &Item) -> Result<()> {
        if it.is_dir() && it.first_cluster != 0 {
            let child = DirLoc::Chain(it.first_cluster);
            let mut cdir = self.read_dir(child)?;
            for c in self.parse(&cdir) {
                self.remove_item(&mut cdir, &c)?;
            }
        }
        self.delete_entries(dir, it)?;
        let chain = self.chain(it.first_cluster)?;
        self.release(&chain);
        self.flush_fat()
    }

    fn write_chain(&mut self, clusters: &[u32], src: &mut dyn Read, size: u64, progress: Progress) -> Result<()> {
        let cs = self.cluster_size as u64;
        let mut done = 0u64;
        let mut buf = vec![0u8; IO_CHUNK.max(cs as usize)];
        let mut i = 0;
        while i < clusters.len() && done < size {
            // Longest run of consecutive clusters, capped at one chunk.
            let mut j = i + 1;
            while j < clusters.len() && clusters[j] == clusters[j - 1] + 1 && ((j - i + 1) as u64 * cs) <= buf.len() as u64 {
                j += 1;
            }
            let span = ((j - i) as u64 * cs).min(size - done) as usize;
            src.read_exact(&mut buf[..span])?;
            self.disk.write_at(self.cluster_offset(clusters[i]), &buf[..span])?;
            done += span as u64;
            if !progress(done) {
                return Err(Error::Cancelled);
            }
            i = j;
        }
        crate::util::wipe(&mut buf);
        Ok(())
    }

    fn read_chain(&mut self, it: &Item, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = it.size as u64;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(size - offset) as usize;
        let chain = self.chain(it.first_cluster)?;
        let cs = self.cluster_size as u64;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let idx = (pos / cs) as usize;
            let within = pos % cs;
            let &c = chain.get(idx).ok_or_else(|| Error::corrupt("file shorter than its size"))?;
            let n = ((cs - within) as usize).min(want - done);
            self.disk.read_at(self.cluster_offset(c) + within, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(want)
    }
}

impl Fat {
    fn is_bad_marker(&self, v: u32) -> bool {
        match self.ty {
            FatType::Fat12 => v == 0xFF7,
            FatType::Fat16 => v == 0xFFF7,
            FatType::Fat32 => v == 0x0FFF_FFF7,
        }
    }

    fn zero_free_impl(&mut self, cursor: u64, max: u64) -> Result<(u64, bool)> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let cs = self.cluster_size as u64;
        let end = self.clusters + 2;
        let mut c = if cursor <= self.data_offset { 2 } else { 2 + ((cursor - self.data_offset).div_ceil(cs)) as u32 };
        let budget = max.max(cs);
        let mut written = 0u64;
        let zeros = vec![0u8; IO_CHUNK];
        while c < end && written < budget {
            if self.entry(c) != 0 || self.is_reserved(c) {
                c += 1;
                continue;
            }
            let start = c;
            let room = ((budget - written) / cs).max(1) as u32;
            while c < end && c - start < room && self.entry(c) == 0 && !self.is_reserved(c) {
                c += 1;
            }
            let mut off = self.cluster_offset(start);
            let stop = self.cluster_offset(start) + (c - start) as u64 * cs;
            while off < stop {
                let n = ((stop - off) as usize).min(IO_CHUNK);
                self.disk.write_at(off, &zeros[..n])?;
                off += n as u64;
            }
            written += (c - start) as u64 * cs;
        }
        self.disk.flush()?;
        if c >= end {
            Ok((self.data_offset + self.clusters as u64 * cs, true))
        } else {
            Ok((self.cluster_offset(c), false))
        }
    }

    fn move_impl(&mut self, path: &str, dest_dir: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        super::check_move(path, dest_dir)?;
        let (src_dir, it) = self.resolve_item(path)?;
        let comps: Vec<&str> = dest_dir.split('/').filter(|c| !c.is_empty()).collect();
        let dest_loc = self.resolve_dir(&comps)?;
        if dest_loc == src_dir.loc {
            return Ok(());
        }
        let mut dest = self.read_dir(dest_loc)?;
        if self.find(&self.parse(&dest), &it.name).is_some() {
            return Err(Error::AlreadyExists);
        }
        self.add_entry(&mut dest, &it.name, it.attr, it.first_cluster, it.size, it.created, it.modified)?;
        // The source directory may have changed if it was the destination's parent; re-read it.
        let mut src = self.read_dir(src_dir.loc)?;
        let current = self.parse(&src).into_iter().find(|i| i.sfn == it.sfn && i.first_cluster == it.first_cluster).ok_or(Error::NotFound)?;
        self.delete_entries(&mut src, &current)?;
        if it.is_dir() && it.first_cluster != 0 {
            // ".." of the moved directory now names its new parent (0 for the root).
            let parent = match dest_loc {
                DirLoc::Chain(p) if !(self.ty == FatType::Fat32 && p == self.root_cluster) => p,
                _ => 0,
            };
            let off = self.cluster_offset(it.first_cluster) + ENTRY as u64;
            let mut e = [0u8; ENTRY];
            self.disk.read_at(off, &mut e)?;
            if &e[..11] == b"..         " {
                put_le16(&mut e, 20, (parent >> 16) as u16);
                put_le16(&mut e, 26, parent as u16);
                self.disk.write_at(off, &e)?;
            }
        }
        self.disk.flush()
    }

    fn check_impl(&mut self, repair: bool) -> Result<CheckReport> {
        let mut r = CheckReport::default();
        let repair = repair && !self.read_only;
        let cs = self.cluster_size as u64;
        let end = (self.clusters + 2) as usize;
        let mut owner: Vec<bool> = vec![false; end];
        // Directories to visit: (location, path).
        let mut stack: Vec<(DirLoc, String)> = vec![(self.root_loc(), String::new())];
        let mut seen_dirs = std::collections::HashSet::new();
        while let Some((loc, path)) = stack.pop() {
            let dir = match self.read_dir(loc) {
                Ok(d) => d,
                Err(_) => {
                    r.bad_chains += 1;
                    r.issue(format!("{}: unreadable folder", if path.is_empty() { "/" } else { &path }));
                    continue;
                }
            };
            for &c in &dir.clusters {
                if owner[c as usize] {
                    r.cross_linked += 1;
                    r.issue(format!("{path}/: shares a cluster"));
                }
                owner[c as usize] = true;
            }
            r.used_bytes += dir.clusters.len() as u64 * cs;
            for it in self.parse(&dir) {
                let p = format!("{path}/{}", it.name);
                if it.is_dir() {
                    r.dirs += 1;
                    if it.first_cluster == 0 || !self.valid_cluster(it.first_cluster) {
                        r.bad_chains += 1;
                        r.issue(format!("{p}: folder points nowhere"));
                    } else if seen_dirs.insert(it.first_cluster) && stack.len() < 10_000 {
                        stack.push((DirLoc::Chain(it.first_cluster), p));
                    }
                    continue;
                }
                r.files += 1;
                let chain = match self.chain(it.first_cluster) {
                    Ok(c) => c,
                    Err(_) => {
                        r.bad_chains += 1;
                        r.issue(format!("{p}: broken cluster chain"));
                        continue;
                    }
                };
                let need = (it.size as u64).div_ceil(cs) as usize;
                let mut keep = chain.len();
                if chain.len() < need {
                    r.size_mismatches += 1;
                    r.issue(format!("{p}: shorter on disk than its size"));
                } else if chain.len() > need && need > 0 {
                    r.size_mismatches += 1;
                    r.issue(format!("{p}: {} extra clusters", chain.len() - need));
                    keep = need;
                    if repair {
                        let eoc = self.eoc();
                        self.set_entry(chain[need - 1], eoc);
                        for &c in &chain[need..] {
                            self.set_entry(c, 0);
                        }
                        self.free_count = None;
                        r.repaired += 1;
                    }
                }
                for &c in &chain[..keep] {
                    if owner[c as usize] {
                        r.cross_linked += 1;
                        r.issue(format!("{p}: shares a cluster with another file"));
                        break;
                    }
                    owner[c as usize] = true;
                }
                r.used_bytes += keep as u64 * cs;
            }
        }
        let mut lost = Vec::new();
        for c in 2..end as u32 {
            let v = self.entry(c);
            if v != 0 && !self.is_bad_marker(v) && !owner[c as usize] {
                lost.push(c);
            }
        }
        if !lost.is_empty() {
            r.lost_clusters = lost.len() as u64;
            r.issue(format!("{} lost clusters ({} bytes)", lost.len(), lost.len() as u64 * cs));
            if repair {
                for &c in &lost {
                    self.set_entry(c, 0);
                }
                self.free_count = None;
                r.repaired += 1;
            }
        }
        let actual = (2..end as u32).filter(|&c| self.entry(c) == 0).count() as u32;
        if let Some(off) = self.fsinfo {
            let mut sec = vec![0u8; self.bps as usize];
            self.disk.read_at(off, &mut sec)?;
            let stored = le32(&sec, 488);
            if stored != 0xFFFF_FFFF && stored != actual && lost.is_empty() {
                r.free_count_wrong = true;
                r.issue(format!("free cluster count says {stored}, actually {actual}"));
                if repair {
                    r.repaired += 1;
                }
            }
        }
        if repair && r.repaired > 0 {
            self.free_count = Some(actual);
            self.flush_fat()?;
            self.disk.flush()?;
        }
        Ok(r)
    }
}

impl FileSystem for Fat {
    fn kind(&self) -> &'static str {
        match self.ty {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        }
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn total_bytes(&self) -> u64 {
        self.clusters as u64 * self.cluster_size as u64
    }

    fn free_bytes(&mut self) -> Result<u64> {
        Ok(self.available() as u64 * self.cluster_size as u64)
    }

    fn max_file_size(&self) -> u64 {
        u32::MAX as u64
    }

    fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let comps = components(path)?;
        let loc = self.resolve_dir(&comps)?;
        let dir = self.read_dir(loc)?;
        Ok(self.parse(&dir).iter().map(|it| self.to_entry(it)).collect())
    }

    fn stat(&mut self, path: &str) -> Result<DirEntry> {
        if components(path)?.is_empty() {
            return Ok(DirEntry { name: String::new(), is_dir: true, size: 0, modified: 0 });
        }
        let (_, it) = self.resolve_item(path)?;
        Ok(self.to_entry(&it))
    }

    fn read_file(&mut self, path: &str, out: &mut dyn Write, progress: Progress) -> Result<u64> {
        let (_, it) = self.resolve_item(path)?;
        if it.is_dir() {
            return Err(Error::IsADirectory);
        }
        let size = it.size as u64;
        let chain = self.chain(it.first_cluster)?;
        let cs = self.cluster_size as u64;
        if (chain.len() as u64) * cs < size {
            return Err(Error::corrupt("file shorter than its size"));
        }
        let mut buf = vec![0u8; IO_CHUNK.max(cs as usize)];
        let mut done = 0u64;
        let mut i = 0;
        while done < size {
            let mut j = i + 1;
            while j < chain.len() && chain[j] == chain[j - 1] + 1 && ((j - i + 1) as u64 * cs) <= buf.len() as u64 {
                j += 1;
            }
            let span = ((j - i) as u64 * cs).min(size - done) as usize;
            self.disk.read_at(self.cluster_offset(chain[i]), &mut buf[..span])?;
            out.write_all(&buf[..span])?;
            done += span as u64;
            if !progress(done) {
                crate::util::wipe(&mut buf);
                return Err(Error::Cancelled);
            }
            i = j;
        }
        crate::util::wipe(&mut buf);
        Ok(size)
    }

    fn read_range(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (_, it) = self.resolve_item(path)?;
        if it.is_dir() {
            return Err(Error::IsADirectory);
        }
        self.read_chain(&it, offset, buf)
    }

    fn write_file(&mut self, path: &str, src: &mut dyn Read, size: u64, overwrite: bool, progress: Progress) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if size > u32::MAX as u64 {
            return Err(Error::unsupported("files over 4 GB on FAT"));
        }
        let (parent, leaf) = split_parent(path)?;
        validate_name(leaf)?;
        let loc = self.resolve_dir(&parent)?;
        let mut dir = self.read_dir(loc)?;
        if let Some(existing) = self.find(&self.parse(&dir), leaf) {
            if existing.is_dir() {
                return Err(Error::IsADirectory);
            }
            if !overwrite {
                return Err(Error::AlreadyExists);
            }
            self.remove_item(&mut dir, &existing)?;
        }
        let n = size.div_ceil(self.cluster_size as u64) as u32;
        let clusters = self.alloc(n)?;
        if let Err(e) = self.write_chain(&clusters, src, size, progress) {
            self.release(&clusters);
            return Err(e);
        }
        let now = self.fat_time(now_unix());
        let first = clusters.first().copied().unwrap_or(0);
        if let Err(e) = self.add_entry(&mut dir, leaf, ATTR_ARCHIVE, first, size as u32, now, now) {
            self.release(&clusters);
            self.flush_fat()?;
            return Err(e);
        }
        self.disk.flush()
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (parent, leaf) = split_parent(path)?;
        validate_name(leaf)?;
        let loc = self.resolve_dir(&parent)?;
        let mut dir = self.read_dir(loc)?;
        if self.find(&self.parse(&dir), leaf).is_some() {
            return Err(Error::AlreadyExists);
        }
        let c = self.alloc(1)?[0];
        let now = self.fat_time(now_unix());
        let parent_cluster = match loc {
            DirLoc::Chain(p) if !(self.ty == FatType::Fat32 && p == self.root_cluster) => p,
            _ => 0,
        };
        let mut data = vec![0u8; self.cluster_size as usize];
        let dot = self.entry_set(".", *b".          ", 0, false, ATTR_DIRECTORY, c, 0, now, now);
        let dotdot = self.entry_set("..", *b"..         ", 0, false, ATTR_DIRECTORY, parent_cluster, 0, now, now);
        data[..ENTRY].copy_from_slice(&dot[0]);
        data[ENTRY..2 * ENTRY].copy_from_slice(&dotdot[0]);
        self.disk.write_at(self.cluster_offset(c), &data)?;
        if let Err(e) = self.add_entry(&mut dir, leaf, ATTR_DIRECTORY, c, 0, now, now) {
            self.release(&[c]);
            self.flush_fat()?;
            return Err(e);
        }
        self.disk.flush()
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (mut dir, it) = self.resolve_item(path)?;
        self.remove_item(&mut dir, &it)?;
        self.disk.flush()
    }

    fn rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        validate_name(new_name)?;
        let (mut dir, it) = self.resolve_item(path)?;
        if let Some(other) = self.find(&self.parse(&dir), new_name) {
            if other.sfn != it.sfn {
                return Err(Error::AlreadyExists);
            }
        }
        // Free the old slots in memory so the new set can reuse them. On
        // failure nothing has been written, so the disk still has the old name.
        for i in it.start..=it.sfn {
            dir.data[i * ENTRY] = 0xE5;
        }
        self.add_entry(&mut dir, new_name, it.attr, it.first_cluster, it.size, it.created, it.modified)?;
        // Old slots the new set did not reuse: write their deletion.
        let mut stale = Vec::new();
        for i in it.start..=it.sfn {
            if dir.data[i * ENTRY] == 0xE5 {
                stale.push(i);
            }
        }
        for i in stale {
            self.write_entries(&dir, i, 1)?;
        }
        self.disk.flush()
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_fat()?;
        self.disk.flush()
    }

    fn raw_disk(&mut self) -> Option<&mut (dyn Disk + 'static)> {
        Some(&mut *self.disk)
    }

    fn extents(&mut self, path: &str) -> Result<Vec<(u64, u64)>> {
        let (_, it) = self.resolve_item(path)?;
        if it.first_cluster == 0 {
            return Ok(Vec::new());
        }
        let chain = self.chain(it.first_cluster)?;
        let len = if it.is_dir() { chain.len() as u64 * self.cluster_size as u64 } else { it.size as u64 };
        Ok(super::runs(&chain, self.data_offset, self.cluster_size as u64, len))
    }

    fn set_hidden_system(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (mut dir, it) = self.resolve_item(path)?;
        dir.data[it.sfn * ENTRY + 11] |= 0x06;
        self.write_entries(&dir, it.sfn, 1)
    }

    fn zero_free(&mut self, cursor: u64, max: u64) -> Result<(u64, bool)> {
        self.zero_free_impl(cursor, max)
    }

    fn move_item(&mut self, path: &str, dest_dir: &str) -> Result<()> {
        self.move_impl(path, dest_dir)
    }

    fn check(&mut self, repair: bool) -> Result<CheckReport> {
        self.check_impl(repair)
    }

    fn reserve(&mut self, start: u64, end: u64) {
        let cs = self.cluster_size as u64;
        if end <= start || end <= self.data_offset {
            return;
        }
        let lo = 2 + (start.saturating_sub(self.data_offset) / cs) as u32;
        let hi = (2 + (end - self.data_offset).div_ceil(cs)).min(self.clusters as u64 + 2) as u32;
        if lo >= hi {
            return;
        }
        self.reserved = Some((lo, hi));
        self.reserved_free = (lo..hi).filter(|&c| self.entry(c) == 0).count() as u32;
    }
}

// ---------------------------------------------------------------- 8.3 names

pub(crate) fn sfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short {
        sum = (if sum & 1 != 0 { 0x80u8 } else { 0 }).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

fn decode_short_part(bytes: &[u8], lower: bool) -> String {
    let s: String = bytes.iter().map(|&b| b as char).collect::<String>().trim_end().to_string();
    if lower {
        s.to_ascii_lowercase()
    } else {
        s
    }
}

fn decode_short(short: &[u8; 11], nt_case: u8) -> String {
    let mut base_bytes = short[..8].to_vec();
    if base_bytes[0] == 0x05 {
        base_bytes[0] = 0xE5;
    }
    let base = decode_short_part(&base_bytes, nt_case & 0x08 != 0);
    let ext = decode_short_part(&short[8..], nt_case & 0x10 != 0);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

fn sfn_char_ok(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || "$%'-_@~`!(){}^#&".contains(c)
}

/// Returns (8.3 name, NT case flags, whether long-name entries are needed).
fn make_short_name(name: &str, existing: &[[u8; 11]]) -> Result<([u8; 11], u8, bool)> {
    validate_name(name)?;
    // Exact 8.3 names (single case per part) need no long-name entries.
    let (base, ext) = match name.rfind('.') {
        Some(p) if p > 0 => (&name[..p], &name[p + 1..]),
        _ => (name, ""),
    };
    let part_ok = |s: &str, max: usize| -> Option<u8> {
        if s.is_empty() && max == 8 || s.len() > max || !s.is_ascii() {
            return None;
        }
        let lower = s.chars().any(|c| c.is_ascii_lowercase());
        let upper = s.chars().any(|c| c.is_ascii_uppercase());
        if lower && upper {
            return None;
        }
        if !s.chars().all(|c| sfn_char_ok(c.to_ascii_uppercase())) {
            return None;
        }
        Some(lower as u8)
    };
    if !base.contains('.') {
        if let (Some(lb), Some(le)) = (part_ok(base, 8), part_ok(ext, 3)) {
            let short = pack_short(&base.to_ascii_uppercase(), &ext.to_ascii_uppercase());
            if !existing.contains(&short) {
                return Ok((short, (lb * 0x08) | (le * 0x10), false));
            }
        }
    }

    // Generated "BASIS~N.EXT" plus long-name entries.
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| *c != ' ' && *c != '.')
            .map(|c| {
                let u = c.to_ascii_uppercase();
                if sfn_char_ok(u) {
                    u
                } else {
                    '_'
                }
            })
            .collect()
    };
    let trimmed = name.trim_start_matches('.');
    let (gbase, gext) = match trimmed.rfind('.') {
        Some(p) => (clean(&trimmed[..p]), clean(&trimmed[p + 1..])),
        None => (clean(trimmed), String::new()),
    };
    let gbase = if gbase.is_empty() { "FILE".to_string() } else { gbase };
    let gext: String = gext.chars().take(3).collect();
    for n in 1..1_000_000u32 {
        let tail = format!("~{n}");
        let keep = 8 - tail.len();
        let b: String = gbase.chars().take(keep).collect();
        let short = pack_short(&format!("{b}{tail}"), &gext);
        if !existing.contains(&short) {
            return Ok((short, 0, true));
        }
    }
    Err(Error::NoSpace)
}

fn pack_short(base: &str, ext: &str) -> [u8; 11] {
    let mut s = [b' '; 11];
    for (i, b) in base.bytes().take(8).enumerate() {
        s[i] = b;
    }
    for (i, b) in ext.bytes().take(3).enumerate() {
        s[8 + i] = b;
    }
    if s[0] == 0xE5 {
        s[0] = 0x05;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names() {
        let (s, case, lfn) = make_short_name("README.TXT", &[]).unwrap();
        assert_eq!(&s, b"README  TXT");
        assert_eq!((case, lfn), (0, false));
        let (s, case, lfn) = make_short_name("notes.txt", &[]).unwrap();
        assert_eq!(&s, b"NOTES   TXT");
        assert_eq!((case, lfn), (0x18, false));
        let (s, _, lfn) = make_short_name("My Document.docx", &[]).unwrap();
        assert_eq!(&s, b"MYDOCU~1DOC");
        assert!(lfn);
        let (s, _, _) = make_short_name("My Document.docx", &[*b"MYDOCU~1DOC"]).unwrap();
        assert_eq!(&s, b"MYDOCU~2DOC");
        let (s, _, lfn) = make_short_name("صورة الهوية.jpg", &[]).unwrap();
        assert_eq!(&s, b"______~1JPG");
        assert!(lfn);
        let (s, _, lfn) = make_short_name(".bashrc", &[]).unwrap();
        assert_eq!(&s, b"BASHRC~1   ");
        assert!(lfn);
        assert!(make_short_name("bad:name", &[]).is_err());
    }

    #[test]
    fn checksum_matches_spec_example() {
        // Checksum is a rotate-right accumulate over the 11 bytes.
        let s = *b"FOO     BAR";
        let mut sum = 0u8;
        for &b in &s {
            sum = sum.rotate_right(1).wrapping_add(b);
        }
        assert_eq!(sfn_checksum(&s), sum);
    }
}
