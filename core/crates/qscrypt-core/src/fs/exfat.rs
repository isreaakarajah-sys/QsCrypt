//! exFAT, read and write (Microsoft exFAT specification, 2019).
//!
//! The FAT and the allocation bitmap are kept in memory and written back
//! after each operation. New files get one contiguous extent when possible
//! (NoFatChain, as Windows does) and a FAT chain otherwise. Writes go data
//! first, then bitmap/FAT, then directory entries.

use super::{components, same_name, split_parent, validate_name, CheckReport, DirEntry, FileSystem, Progress};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{civil_from_unix, le16, le32, le64, now_unix, put_le16, put_le32, put_le64, unix_from_civil, Civil};
use std::io::{Read, Write};

const ENTRY: usize = 32;
const IO_CHUNK: usize = 1 << 20;
const ATTR_DIRECTORY: u16 = 0x10;
const ATTR_ARCHIVE: u16 = 0x20;
const MAX_DIR_BYTES: u64 = 256 << 20;
const EOC: u32 = 0xFFFF_FFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stream {
    first: u32,
    /// Allocated length (DataLength).
    size: u64,
    /// Bytes actually written (ValidDataLength); the rest reads as zeros.
    valid: u64,
    contiguous: bool,
}

#[derive(Clone, Debug)]
struct Item {
    name: String,
    attr: u16,
    stream: Stream,
    modified: i64,
    /// Raw File entry, to keep the timestamps when renaming.
    file_entry: [u8; ENTRY],
    /// Index of the File entry in its directory, and size of the entry set.
    index: usize,
    count: usize,
}

impl Item {
    fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
}

/// A directory loaded for modification.
struct Dir {
    stream: Stream,
    clusters: Vec<u32>,
    data: Vec<u8>,
    /// Where this directory's own entry set lives (None for the root).
    owner: Option<(Stream, usize)>,
}

pub struct Exfat {
    disk: Box<dyn Disk>,
    read_only: bool,
    cluster_size: u64,
    fat_offset: u64,
    heap_offset: u64,
    cluster_count: u32,
    root: Stream,
    fat: Vec<u8>,
    fat_dirty: Vec<bool>,
    bitmap_clusters: Vec<u32>,
    bitmap: Vec<u8>,
    bitmap_dirty: Vec<bool>,
    upcase: Vec<u16>,
    free_clusters: u32,
    /// Clusters [lo, hi) the allocator must not use, and how many are free.
    reserved: Option<(u32, u32)>,
    reserved_free: u32,
    percent: u8,
    tz: i32,
    label: String,
}

pub(crate) fn entry_set_checksum(set: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        c = (if c & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(c >> 1).wrapping_add(b as u16);
    }
    c
}

pub(crate) fn name_hash(upcased: &[u16]) -> u16 {
    let mut h: u16 = 0;
    for &u in upcased {
        h = (if h & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(h >> 1).wrapping_add(u & 0xFF);
        h = (if h & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(h >> 1).wrapping_add(u >> 8);
    }
    h
}

/// Expands an up-case table (0xFFFF n = the next n characters map to themselves).
pub(crate) fn expand_upcase(bytes: &[u8]) -> Vec<u16> {
    let mut table: Vec<u16> = (0..=0xFFFFu32).map(|c| c as u16).collect();
    let words: Vec<u16> = bytes.chunks_exact(2).map(|w| u16::from_le_bytes([w[0], w[1]])).collect();
    let (mut idx, mut i) = (0usize, 0usize);
    while i < words.len() && idx < 0x10000 {
        if words[i] == 0xFFFF && i + 1 < words.len() {
            idx += words[i + 1] as usize;
            i += 2;
        } else {
            table[idx] = words[i];
            idx += 1;
            i += 1;
        }
    }
    table
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(Error::Io)
}

impl Exfat {
    pub fn mount(mut disk: Box<dyn Disk>, read_only: bool, tz_offset_min: i32) -> Result<Exfat> {
        let mut b = [0u8; 512];
        disk.read_at(0, &mut b)?;
        if &b[3..11] != b"EXFAT   " {
            return Err(Error::corrupt("not an exFAT boot sector"));
        }
        let bps_shift = b[108] as u32;
        let spc_shift = b[109] as u32;
        if !(9..=12).contains(&bps_shift) || bps_shift + spc_shift > 25 {
            return Err(Error::corrupt("bad exFAT geometry"));
        }
        let bps = 1u64 << bps_shift;
        let cluster_size = bps << spc_shift;
        let fat_offset = le32(&b, 80) as u64 * bps;
        let fat_len = le32(&b, 84) as u64 * bps;
        let heap_offset = le32(&b, 88) as u64 * bps;
        let cluster_count = le32(&b, 92);
        let root_cluster = le32(&b, 96);
        let fat_needed = (cluster_count as u64 + 2) * 4;
        if fat_len < fat_needed || heap_offset + cluster_count as u64 * cluster_size > disk.len() {
            return Err(Error::corrupt("exFAT larger than the volume"));
        }
        if fat_needed > 256 << 20 {
            return Err(Error::unsupported("exFAT allocation table larger than 256 MiB"));
        }
        let mut fat = vec![0u8; fat_needed.div_ceil(512) as usize * 512];
        disk.read_at(fat_offset, &mut fat)?;
        let read_only = read_only || disk.is_read_only();
        let mut fs = Exfat {
            disk,
            read_only,
            cluster_size,
            fat_offset,
            heap_offset,
            cluster_count,
            root: Stream { first: root_cluster, size: 0, valid: 0, contiguous: false },
            fat_dirty: vec![false; fat_needed.div_ceil(512) as usize],
            fat,
            bitmap_clusters: Vec::new(),
            bitmap: Vec::new(),
            bitmap_dirty: Vec::new(),
            upcase: Vec::new(),
            free_clusters: 0,
            reserved: None,
            reserved_free: 0,
            percent: b[112],
            tz: tz_offset_min,
            label: String::new(),
        };
        if !fs.valid_cluster(root_cluster) {
            return Err(Error::corrupt("bad exFAT root cluster"));
        }
        let root_len = fs.chain(root_cluster)?.len() as u64 * cluster_size;
        fs.root.size = root_len;
        fs.root.valid = root_len;
        let root = fs.root;
        let data = fs.read_stream(&root, MAX_DIR_BYTES)?;
        let mut bitmap: Option<Stream> = None;
        let mut upcase: Option<Stream> = None;
        for e in data.chunks_exact(ENTRY) {
            match e[0] {
                0x00 => break,
                0x81 if bitmap.is_none() => {
                    let len = le64(e, 24);
                    bitmap = Some(Stream { first: le32(e, 20), size: len, valid: len, contiguous: false });
                }
                0x82 => {
                    let len = le64(e, 24);
                    upcase = Some(Stream { first: le32(e, 20), size: len, valid: len, contiguous: false });
                }
                0x83 => {
                    let n = (e[1] as usize).min(11);
                    let units: Vec<u16> = (0..n).map(|k| le16(e, 2 + 2 * k)).collect();
                    fs.label = String::from_utf16_lossy(&units);
                }
                _ => {}
            }
        }
        let bm = bitmap.ok_or_else(|| Error::corrupt("exFAT without allocation bitmap"))?;
        if bm.size < (cluster_count as u64).div_ceil(8) || bm.size > 64 << 20 {
            return Err(Error::corrupt("bad exFAT allocation bitmap"));
        }
        fs.bitmap_clusters = fs.metadata_clusters(&bm)?;
        let mut bits = vec![0u8; bm.size.div_ceil(512) as usize * 512];
        let raw = fs.read_clusters(&fs.bitmap_clusters.clone(), bm.size)?;
        bits[..raw.len()].copy_from_slice(&raw);
        fs.bitmap_dirty = vec![false; bits.len() / 512];
        fs.bitmap = bits;
        fs.free_clusters = (0..cluster_count).filter(|&i| fs.bitmap[(i / 8) as usize] & (1 << (i % 8)) == 0).count() as u32;
        fs.upcase = match upcase {
            Some(u) if u.size > 0 && u.size <= 0x20000 => {
                let clusters = fs.metadata_clusters(&u)?;
                expand_upcase(&fs.read_clusters(&clusters, u.size)?)
            }
            _ => super::exfat_format::upcase_table(),
        };
        Ok(fs)
    }

    fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.cluster_count + 2
    }

    fn fat_entry(&self, c: u32) -> u32 {
        le32(&self.fat, c as usize * 4)
    }

    fn set_fat(&mut self, c: u32, v: u32) {
        put_le32(&mut self.fat, c as usize * 4, v);
        self.fat_dirty[c as usize * 4 / 512] = true;
    }

    fn used(&self, c: u32) -> bool {
        let i = c - 2;
        self.bitmap[(i / 8) as usize] & (1 << (i % 8)) != 0
    }

    fn set_used(&mut self, c: u32, used: bool) {
        let i = c - 2;
        let byte = (i / 8) as usize;
        let was = self.used(c);
        if used {
            self.bitmap[byte] |= 1 << (i % 8);
        } else {
            self.bitmap[byte] &= !(1 << (i % 8));
        }
        self.bitmap_dirty[byte / 512] = true;
        match (was, used) {
            (false, true) => self.free_clusters -= 1,
            (true, false) => self.free_clusters += 1,
            _ => {}
        }
    }

    fn chain(&self, first: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut c = first;
        loop {
            if !self.valid_cluster(c) {
                return Err(Error::corrupt("bad exFAT cluster chain"));
            }
            out.push(c);
            if out.len() > self.cluster_count as usize {
                return Err(Error::corrupt("exFAT cluster chain loops"));
            }
            let next = self.fat_entry(c);
            if next == EOC {
                return Ok(out);
            }
            c = next;
        }
    }

    fn clusters_of(&self, s: &Stream) -> Result<Vec<u32>> {
        if s.size == 0 {
            return Ok(Vec::new());
        }
        let n = s.size.div_ceil(self.cluster_size);
        if s.contiguous {
            if !self.valid_cluster(s.first) || s.first as u64 + n > self.cluster_count as u64 + 2 {
                return Err(Error::corrupt("exFAT extent outside the volume"));
            }
            Ok((s.first..s.first + n as u32).collect())
        } else {
            let mut c = self.chain(s.first)?;
            if (c.len() as u64) < n {
                return Err(Error::corrupt("exFAT chain shorter than the file"));
            }
            c.truncate(n as usize);
            Ok(c)
        }
    }

    /// Bitmap and up-case table are described by the FAT; tolerate
    /// formatters that only made them contiguous.
    fn metadata_clusters(&self, s: &Stream) -> Result<Vec<u32>> {
        self.clusters_of(s).or_else(|_| self.clusters_of(&Stream { contiguous: true, ..*s }))
    }

    fn cluster_offset(&self, c: u32) -> u64 {
        self.heap_offset + (c as u64 - 2) * self.cluster_size
    }

    fn read_clusters(&mut self, clusters: &[u32], len: u64) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len as usize];
        let cs = self.cluster_size as usize;
        for (i, &c) in clusters.iter().enumerate() {
            let start = i * cs;
            if start >= out.len() {
                break;
            }
            let end = (start + cs).min(out.len());
            let off = self.cluster_offset(c);
            self.disk.read_at(off, &mut out[start..end])?;
        }
        Ok(out)
    }

    /// Streams `[offset, offset + len)` of a stream to `sink`, zero-filling
    /// beyond ValidDataLength.
    fn stream_range(&mut self, s: &Stream, offset: u64, len: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let clusters = self.clusters_of(s)?;
        let cs = self.cluster_size;
        let mut buf = vec![0u8; IO_CHUNK.max(cs as usize)];
        let end = offset + len;
        let mut pos = offset;
        while pos < end {
            let n = (end - pos).min(buf.len() as u64);
            let chunk = &mut buf[..n as usize];
            let mut filled = 0u64;
            while filled < n {
                let p = pos + filled;
                let within = p % cs;
                let take = (cs - within).min(n - filled);
                let dst = &mut chunk[filled as usize..(filled + take) as usize];
                if p >= s.valid {
                    dst.fill(0);
                } else {
                    let c = *clusters.get((p / cs) as usize).ok_or_else(|| Error::corrupt("exFAT data beyond allocation"))?;
                    let real = take.min(s.valid - p);
                    let (head, tail) = dst.split_at_mut(real as usize);
                    self.disk.read_at(self.cluster_offset(c) + within, head)?;
                    tail.fill(0);
                }
                filled += take;
            }
            sink(chunk)?;
            pos += n;
        }
        crate::util::wipe(&mut buf);
        Ok(())
    }

    fn read_stream(&mut self, s: &Stream, max: u64) -> Result<Vec<u8>> {
        if s.size > max {
            return Err(Error::corrupt("directory too large"));
        }
        let mut out = Vec::with_capacity(s.size as usize);
        self.stream_range(s, 0, s.size, &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        })?;
        Ok(out)
    }

    // ------------------------------------------------------------ time

    fn timestamp(&self, ts: u32, ms10: u8, utc: u8) -> i64 {
        if ts == 0 {
            return 0;
        }
        let civil = Civil {
            year: 1980 + (ts >> 25) as i64,
            month: ((ts >> 21) & 0xF).clamp(1, 12),
            day: ((ts >> 16) & 0x1F).clamp(1, 31),
            hour: ((ts >> 11) & 0x1F).min(23),
            minute: ((ts >> 5) & 0x3F).min(59),
            second: ((ts & 0x1F) * 2).min(59),
        };
        let local = unix_from_civil(&civil) + (ms10 as i64) / 100;
        let offset_min = if utc & 0x80 != 0 {
            // 7-bit two's complement, 15-minute steps.
            let raw = (utc & 0x7F) as i64;
            let v = if raw & 0x40 != 0 { raw - 0x80 } else { raw };
            v * 15
        } else {
            self.tz as i64
        };
        local - offset_min * 60
    }

    /// (timestamp, 10 ms increment, UTC offset byte) for "now".
    fn now_stamp(&self) -> (u32, u8, u8) {
        let local = now_unix() + self.tz as i64 * 60;
        let c = civil_from_unix(local);
        let year = (c.year - 1980).clamp(0, 127) as u32;
        let ts = (year << 25) | (c.month << 21) | (c.day << 16) | (c.hour << 11) | (c.minute << 5) | (c.second / 2);
        let ms10 = ((c.second % 2) * 100) as u8;
        let quarter = (self.tz / 15).clamp(-64, 63) as i8;
        (ts, ms10, 0x80 | (quarter as u8 & 0x7F))
    }

    // ------------------------------------------------------------ directories

    fn parse(&self, data: &[u8]) -> Vec<Item> {
        let entries = data.len() / ENTRY;
        let e = |i: usize| &data[i * ENTRY..(i + 1) * ENTRY];
        let mut items = Vec::new();
        let mut i = 0;
        while i < entries {
            let t = e(i)[0];
            if t == 0x00 {
                break;
            }
            if t != 0x85 {
                i += 1;
                continue;
            }
            let file = e(i);
            let secondary = file[1] as usize;
            if secondary < 2 || i + secondary >= entries {
                i += 1;
                continue;
            }
            let set = &data[i * ENTRY..(i + 1 + secondary) * ENTRY];
            if entry_set_checksum(set) != le16(file, 2) || e(i + 1)[0] != 0xC0 {
                i += 1;
                continue;
            }
            let st = e(i + 1);
            let name_len = st[3] as usize;
            let mut units = Vec::with_capacity(name_len);
            for k in 0..secondary - 1 {
                let ne = e(i + 2 + k);
                if ne[0] != 0xC1 {
                    break;
                }
                for c in 0..15 {
                    if units.len() < name_len {
                        units.push(le16(ne, 2 + 2 * c));
                    }
                }
            }
            let size = le64(st, 24);
            items.push(Item {
                name: String::from_utf16_lossy(&units),
                attr: le16(file, 4),
                stream: Stream { first: le32(st, 20), size, valid: le64(st, 8).min(size), contiguous: st[1] & 0x02 != 0 },
                modified: self.timestamp(le32(file, 12), file[21], file[23]),
                file_entry: file.try_into().unwrap(),
                index: i,
                count: 1 + secondary,
            });
            i += 1 + secondary;
        }
        items
    }

    fn dir_items(&mut self, s: &Stream) -> Result<Vec<Item>> {
        let data = self.read_stream(s, MAX_DIR_BYTES)?;
        Ok(self.parse(&data))
    }

    /// (directory stream, its owner) for a path.
    fn resolve_dir(&mut self, comps: &[&str]) -> Result<(Stream, Option<(Stream, usize)>)> {
        let mut cur = self.root;
        let mut owner = None;
        for comp in comps {
            let items = self.dir_items(&cur)?;
            let it = items.into_iter().find(|it| same_name(&it.name, comp)).ok_or(Error::NotFound)?;
            if !it.is_dir() {
                return Err(Error::NotADirectory);
            }
            owner = Some((cur, it.index));
            cur = it.stream;
        }
        Ok((cur, owner))
    }

    fn load_dir(&mut self, comps: &[&str]) -> Result<Dir> {
        let (stream, owner) = self.resolve_dir(comps)?;
        let clusters = self.clusters_of(&stream)?;
        let data = self.read_stream(&stream, MAX_DIR_BYTES)?;
        Ok(Dir { stream, clusters, data, owner })
    }

    fn resolve_item(&mut self, path: &str) -> Result<Item> {
        let (parent, leaf) = split_parent(path)?;
        let (dir, _) = self.resolve_dir(&parent)?;
        self.dir_items(&dir)?.into_iter().find(|it| same_name(&it.name, leaf)).ok_or(Error::NotFound)
    }

    fn to_entry(it: &Item) -> DirEntry {
        DirEntry { name: it.name.clone(), is_dir: it.is_dir(), size: if it.is_dir() { 0 } else { it.stream.size }, modified: it.modified }
    }

    fn write_dir_entries(&mut self, dir: &Dir, from: usize, count: usize) -> Result<()> {
        let cs = self.cluster_size as usize;
        for i in from..from + count {
            let pos = i * ENTRY;
            let off = self.cluster_offset(dir.clusters[pos / cs]) + (pos % cs) as u64;
            self.disk.write_at(off, &dir.data[pos..pos + ENTRY])?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ allocation

    fn blocked(&self, c: u32) -> bool {
        self.used(c) || self.reserved.is_some_and(|(lo, hi)| c >= lo && c < hi)
    }

    fn available(&self) -> u32 {
        self.free_clusters.saturating_sub(self.reserved_free)
    }

    fn find_run(&self, n: u32) -> Option<u32> {
        let mut start = 2u32;
        let mut len = 0u32;
        for c in 2..self.cluster_count + 2 {
            if self.blocked(c) {
                len = 0;
                start = c + 1;
            } else {
                len += 1;
                if len == n {
                    return Some(start);
                }
            }
        }
        None
    }

    /// Allocates `n` clusters: one contiguous extent if possible
    /// (returns true), otherwise a FAT chain.
    fn alloc(&mut self, n: u32) -> Result<(Vec<u32>, bool)> {
        if n == 0 {
            return Ok((Vec::new(), true));
        }
        if self.available() < n {
            return Err(Error::NoSpace);
        }
        if let Some(start) = self.find_run(n) {
            for c in start..start + n {
                self.set_used(c, true);
            }
            return Ok(((start..start + n).collect(), true));
        }
        let mut got = Vec::with_capacity(n as usize);
        for c in 2..self.cluster_count + 2 {
            if !self.blocked(c) {
                got.push(c);
                if got.len() == n as usize {
                    break;
                }
            }
        }
        for &c in &got {
            self.set_used(c, true);
        }
        for w in got.windows(2) {
            self.set_fat(w[0], w[1]);
        }
        self.set_fat(*got.last().unwrap(), EOC);
        Ok((got, false))
    }

    fn release(&mut self, clusters: &[u32], contiguous: bool) {
        for &c in clusters {
            self.set_used(c, false);
            if !contiguous {
                self.set_fat(c, 0);
            }
        }
    }

    fn flush_meta(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        for i in 0..self.fat_dirty.len() {
            if self.fat_dirty[i] {
                let off = self.fat_offset + (i * 512) as u64;
                self.disk.write_at(off, &self.fat[i * 512..(i + 1) * 512])?;
                self.fat_dirty[i] = false;
            }
        }
        let cs = self.cluster_size as usize;
        for i in 0..self.bitmap_dirty.len() {
            if self.bitmap_dirty[i] {
                let pos = i * 512;
                let c = self.bitmap_clusters[pos / cs];
                let off = self.cluster_offset(c) + (pos % cs) as u64;
                self.disk.write_at(off, &self.bitmap[pos..pos + 512])?;
                self.bitmap_dirty[i] = false;
            }
        }
        // PercentInUse is excluded from the boot checksum, so the main boot
        // sector may be updated in place (the backup region is left alone).
        let used = (self.cluster_count - self.free_clusters) as u64;
        let pct = if self.cluster_count == 0 { 0 } else { (used * 100 / self.cluster_count as u64) as u8 };
        if pct != self.percent {
            self.disk.write_at(112, &[pct])?;
            self.percent = pct;
        }
        Ok(())
    }

    fn write_data(&mut self, clusters: &[u32], src: &mut dyn Read, size: u64, progress: Progress) -> Result<()> {
        let cs = self.cluster_size;
        let mut buf = vec![0u8; IO_CHUNK.max(cs as usize)];
        let mut done = 0u64;
        let mut i = 0;
        while i < clusters.len() && done < size {
            let mut j = i + 1;
            while j < clusters.len() && clusters[j] == clusters[j - 1] + 1 && ((j - i + 1) as u64 * cs) <= buf.len() as u64 {
                j += 1;
            }
            let span = ((j - i) as u64 * cs).min(size - done) as usize;
            read_full(src, &mut buf[..span])?;
            self.disk.write_at(self.cluster_offset(clusters[i]), &buf[..span])?;
            done += span as u64;
            if !progress(done) {
                crate::util::wipe(&mut buf);
                return Err(Error::Cancelled);
            }
            i = j;
        }
        crate::util::wipe(&mut buf);
        Ok(())
    }

    /// File + Stream Extension + File Name entries.
    fn entry_set(&self, name: &str, attr: u16, s: Stream, times: Option<&[u8; ENTRY]>) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(15);
        let mut set = vec![0u8; ENTRY * (2 + names)];
        set[0] = 0x85;
        set[1] = (1 + names) as u8;
        put_le16(&mut set, 4, attr);
        match times {
            Some(old) => set[8..26].copy_from_slice(&old[8..26]),
            None => {
                let (ts, ms10, utc) = self.now_stamp();
                for o in [8, 12, 16] {
                    put_le32(&mut set, o, ts);
                }
                set[20] = ms10;
                set[21] = ms10;
                set[22] = utc;
                set[23] = utc;
                set[24] = utc;
            }
        }
        let st = &mut set[ENTRY..2 * ENTRY];
        st[0] = 0xC0;
        st[1] = 0x01 | if s.contiguous && s.size > 0 { 0x02 } else { 0 };
        st[3] = units.len() as u8;
        let up: Vec<u16> = units.iter().map(|&u| self.upcase[u as usize]).collect();
        put_le16(st, 4, name_hash(&up));
        put_le64(st, 8, s.valid);
        put_le32(st, 20, if s.size == 0 { 0 } else { s.first });
        put_le64(st, 24, s.size);
        for (k, chunk) in units.chunks(15).enumerate() {
            let e = &mut set[(2 + k) * ENTRY..(3 + k) * ENTRY];
            e[0] = 0xC1;
            for (j, &u) in chunk.iter().enumerate() {
                put_le16(e, 2 + 2 * j, u);
            }
        }
        let sum = entry_set_checksum(&set);
        put_le16(&mut set, 2, sum);
        set
    }

    /// Updates a directory's own Stream Extension after it grew.
    fn update_owner(&mut self, owner: (Stream, usize), s: Stream) -> Result<()> {
        let (parent, index) = owner;
        let clusters = self.clusters_of(&parent)?;
        let mut data = self.read_stream(&parent, MAX_DIR_BYTES)?;
        let count = 1 + data[index * ENTRY + 1] as usize;
        {
            let st = &mut data[(index + 1) * ENTRY..(index + 2) * ENTRY];
            st[1] = (st[1] & !0x02) | if s.contiguous { 0x02 } else { 0 };
            put_le64(st, 8, s.valid);
            put_le64(st, 24, s.size);
        }
        let sum = entry_set_checksum(&data[index * ENTRY..(index + count) * ENTRY]);
        put_le16(&mut data, index * ENTRY + 2, sum);
        let d = Dir { stream: parent, clusters, data, owner: None };
        self.write_dir_entries(&d, index, count)
    }

    fn grow(&mut self, dir: &mut Dir) -> Result<()> {
        if dir.data.len() as u64 + self.cluster_size > MAX_DIR_BYTES {
            return Err(Error::NoSpace);
        }
        let last = *dir.clusters.last().ok_or_else(|| Error::corrupt("empty exFAT directory"))?;
        let next = last + 1;
        let new = if dir.stream.contiguous && self.valid_cluster(next) && !self.blocked(next) {
            self.set_used(next, true);
            next
        } else {
            if self.available() == 0 {
                return Err(Error::NoSpace);
            }
            let c = (2..self.cluster_count + 2).find(|&c| !self.blocked(c)).ok_or(Error::NoSpace)?;
            self.set_used(c, true);
            if dir.stream.contiguous {
                let existing = dir.clusters.clone();
                for w in existing.windows(2) {
                    self.set_fat(w[0], w[1]);
                }
                dir.stream.contiguous = false;
            }
            self.set_fat(last, c);
            self.set_fat(c, EOC);
            c
        };
        let zeros = vec![0u8; self.cluster_size as usize];
        self.disk.write_at(self.cluster_offset(new), &zeros)?;
        dir.clusters.push(new);
        dir.data.extend_from_slice(&zeros);
        dir.stream.size += self.cluster_size;
        dir.stream.valid = dir.stream.size;
        self.flush_meta()?;
        match dir.owner {
            Some(owner) => self.update_owner(owner, dir.stream),
            None => {
                self.root = dir.stream;
                Ok(())
            }
        }
    }

    fn insert_set(&mut self, dir: &mut Dir, set: &[u8]) -> Result<()> {
        let need = set.len() / ENTRY;
        let at = loop {
            let total = dir.data.len() / ENTRY;
            let mut run = 0;
            let mut found = None;
            for i in 0..total {
                if dir.data[i * ENTRY] & 0x80 == 0 {
                    run += 1;
                    if run == need {
                        found = Some(i + 1 - need);
                        break;
                    }
                } else {
                    run = 0;
                }
            }
            if let Some(at) = found {
                break at;
            }
            self.grow(dir)?;
        };
        dir.data[at * ENTRY..at * ENTRY + set.len()].copy_from_slice(set);
        self.flush_meta()?;
        self.write_dir_entries(dir, at, need)
    }

    fn remove_item(&mut self, dir: &mut Dir, it: &Item) -> Result<()> {
        if it.is_dir() && it.stream.size > 0 {
            let clusters = self.clusters_of(&it.stream)?;
            let data = self.read_stream(&it.stream, MAX_DIR_BYTES)?;
            let mut child = Dir { stream: it.stream, clusters, data, owner: None };
            for c in self.parse(&child.data.clone()) {
                self.remove_item(&mut child, &c)?;
            }
        }
        for i in it.index..it.index + it.count {
            dir.data[i * ENTRY] &= 0x7F;
        }
        self.write_dir_entries(dir, it.index, it.count)?;
        let clusters = self.clusters_of(&it.stream)?;
        self.release(&clusters, it.stream.contiguous);
        self.flush_meta()
    }

    fn find_in(&self, dir: &Dir, name: &str) -> Option<Item> {
        self.parse(&dir.data).into_iter().find(|it| same_name(&it.name, name))
    }
}

impl Exfat {
    fn zero_free_impl(&mut self, cursor: u64, max: u64) -> Result<(u64, bool)> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let cs = self.cluster_size;
        let end = self.cluster_count + 2;
        let mut c = if cursor <= self.heap_offset { 2 } else { 2 + ((cursor - self.heap_offset).div_ceil(cs)) as u32 };
        let budget = max.max(cs);
        let mut written = 0u64;
        let zeros = vec![0u8; IO_CHUNK];
        while c < end && written < budget {
            if self.blocked(c) {
                c += 1;
                continue;
            }
            let start = c;
            let room = ((budget - written) / cs).max(1) as u32;
            while c < end && c - start < room && !self.blocked(c) {
                c += 1;
            }
            let mut off = self.cluster_offset(start);
            let stop = off + (c - start) as u64 * cs;
            while off < stop {
                let n = ((stop - off) as usize).min(IO_CHUNK);
                self.disk.write_at(off, &zeros[..n])?;
                off += n as u64;
            }
            written += (c - start) as u64 * cs;
        }
        self.disk.flush()?;
        if c >= end {
            Ok((self.heap_offset + self.cluster_count as u64 * cs, true))
        } else {
            Ok((self.cluster_offset(c), false))
        }
    }

    fn move_impl(&mut self, path: &str, dest_dir: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        super::check_move(path, dest_dir)?;
        let (parent, leaf) = split_parent(path)?;
        let dest: Vec<&str> = dest_dir.split('/').filter(|c| !c.is_empty()).collect();
        let (from, _) = self.resolve_dir(&parent)?;
        let (to, _) = self.resolve_dir(&dest)?;
        if from.first == to.first {
            return Ok(());
        }
        let src = self.load_dir(&parent)?;
        let it = self.find_in(&src, leaf).ok_or(Error::NotFound)?;
        let mut dst = self.load_dir(&dest)?;
        if self.find_in(&dst, &it.name).is_some() {
            return Err(Error::AlreadyExists);
        }
        let set = self.entry_set(&it.name, it.attr, it.stream, Some(&it.file_entry));
        self.insert_set(&mut dst, &set)?;
        // Growing the destination may have rewritten its entry in the source: reload.
        let mut src = self.load_dir(&parent)?;
        let cur = self.find_in(&src, leaf).ok_or(Error::NotFound)?;
        for i in cur.index..cur.index + cur.count {
            src.data[i * ENTRY] &= 0x7F;
        }
        for i in cur.index..cur.index + cur.count {
            self.write_dir_entries(&src, i, 1)?;
        }
        self.disk.flush()
    }

    fn check_impl(&mut self, repair: bool) -> Result<CheckReport> {
        let mut r = CheckReport::default();
        let repair = repair && !self.read_only;
        let cs = self.cluster_size;
        let end = (self.cluster_count + 2) as usize;
        let mut owner = vec![false; end];
        let claim = |r: &mut CheckReport, owner: &mut Vec<bool>, c: u32, what: &str| -> bool {
            if owner[c as usize] {
                r.cross_linked += 1;
                r.issue(format!("{what}: shares a cluster"));
                return false;
            }
            owner[c as usize] = true;
            true
        };
        for c in self.bitmap_clusters.clone() {
            claim(&mut r, &mut owner, c, "allocation bitmap");
        }
        // The up-case table, from the root's 0x82 entry.
        let root = self.root;
        let root_data = self.read_stream(&root, MAX_DIR_BYTES)?;
        for e in root_data.chunks_exact(ENTRY) {
            if e[0] == 0 {
                break;
            }
            if e[0] == 0x82 {
                let len = le64(e, 24);
                let u = Stream { first: le32(e, 20), size: len, valid: len, contiguous: false };
                if let Ok(cl) = self.metadata_clusters(&u) {
                    for c in cl {
                        claim(&mut r, &mut owner, c, "up-case table");
                    }
                }
            }
        }
        let mut fixes_bitmap = Vec::new();
        let mut stack: Vec<(Stream, String)> = vec![(root, String::new())];
        let mut seen = std::collections::HashSet::new();
        while let Some((dir, path)) = stack.pop() {
            let shown = if path.is_empty() { "/".to_string() } else { path.clone() };
            let clusters = match self.clusters_of(&dir) {
                Ok(c) => c,
                Err(_) => {
                    r.bad_chains += 1;
                    r.issue(format!("{shown}: broken folder chain"));
                    continue;
                }
            };
            for &c in &clusters {
                claim(&mut r, &mut owner, c, &shown);
                if !self.used(c) {
                    r.bitmap_errors += 1;
                    fixes_bitmap.push(c);
                }
            }
            r.used_bytes += clusters.len() as u64 * cs;
            let data = match self.read_stream(&dir, MAX_DIR_BYTES) {
                Ok(d) => d,
                Err(_) => {
                    r.bad_chains += 1;
                    r.issue(format!("{shown}: unreadable folder"));
                    continue;
                }
            };
            let n = data.len() / ENTRY;
            let mut i = 0;
            while i < n {
                let t = data[i * ENTRY];
                if t == 0 {
                    break;
                }
                if t == 0x85 {
                    let sec = data[i * ENTRY + 1] as usize;
                    if sec >= 2 && i + sec < n {
                        let set = &data[i * ENTRY..(i + 1 + sec) * ENTRY];
                        if entry_set_checksum(set) != le16(&data[i * ENTRY..], 2) {
                            r.checksum_errors += 1;
                            r.issue(format!("{shown}: an entry with a bad checksum (hidden)"));
                        }
                        i += 1 + sec;
                        continue;
                    }
                }
                i += 1;
            }
            for it in self.parse(&data) {
                let p = format!("{path}/{}", it.name);
                if it.is_dir() {
                    r.dirs += 1;
                    if seen.insert(it.stream.first) && stack.len() < 10_000 {
                        stack.push((it.stream, p));
                    }
                    continue;
                }
                r.files += 1;
                if it.stream.size == 0 {
                    continue;
                }
                let cl = match self.clusters_of(&it.stream) {
                    Ok(c) => c,
                    Err(_) => {
                        r.bad_chains += 1;
                        r.issue(format!("{p}: broken cluster chain"));
                        continue;
                    }
                };
                if !it.stream.contiguous {
                    if let Ok(full) = self.chain(it.stream.first) {
                        if full.len() > cl.len() {
                            r.size_mismatches += 1;
                            r.issue(format!("{p}: {} extra clusters", full.len() - cl.len()));
                            if repair {
                                self.set_fat(cl[cl.len() - 1], EOC);
                                for &c in &full[cl.len()..] {
                                    self.set_fat(c, 0);
                                }
                                r.repaired += 1;
                            }
                        }
                    }
                }
                for &c in &cl {
                    if !claim(&mut r, &mut owner, c, &p) {
                        break;
                    }
                    if !self.used(c) {
                        r.bitmap_errors += 1;
                        fixes_bitmap.push(c);
                    }
                }
                r.used_bytes += cl.len() as u64 * cs;
            }
        }
        if !fixes_bitmap.is_empty() {
            r.issue(format!("{} clusters in use are marked free", fixes_bitmap.len()));
            if repair {
                for &c in &fixes_bitmap {
                    self.set_used(c, true);
                }
                r.repaired += 1;
            }
        }
        let lost: Vec<u32> = (2..end as u32).filter(|&c| self.used(c) && !owner[c as usize]).collect();
        if !lost.is_empty() {
            r.lost_clusters = lost.len() as u64;
            r.issue(format!("{} lost clusters ({} bytes)", lost.len(), lost.len() as u64 * cs));
            if repair {
                for &c in &lost {
                    self.set_used(c, false);
                }
                r.repaired += 1;
            }
        }
        if repair && r.repaired > 0 {
            self.flush_meta()?;
            self.disk.flush()?;
        }
        Ok(r)
    }
}

impl FileSystem for Exfat {
    fn kind(&self) -> &'static str {
        "exFAT"
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn total_bytes(&self) -> u64 {
        self.cluster_count as u64 * self.cluster_size
    }

    fn free_bytes(&mut self) -> Result<u64> {
        Ok(self.available() as u64 * self.cluster_size)
    }

    fn max_file_size(&self) -> u64 {
        u64::MAX
    }

    fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let comps = components(path)?;
        let (dir, _) = self.resolve_dir(&comps)?;
        Ok(self.dir_items(&dir)?.iter().map(Self::to_entry).collect())
    }

    fn stat(&mut self, path: &str) -> Result<DirEntry> {
        if components(path)?.is_empty() {
            return Ok(DirEntry { name: String::new(), is_dir: true, size: 0, modified: 0 });
        }
        Ok(Self::to_entry(&self.resolve_item(path)?))
    }

    fn read_file(&mut self, path: &str, out: &mut dyn Write, progress: Progress) -> Result<u64> {
        let it = self.resolve_item(path)?;
        if it.is_dir() {
            return Err(Error::IsADirectory);
        }
        let mut done = 0u64;
        let size = it.stream.size;
        self.stream_range(&it.stream, 0, size, &mut |b| {
            out.write_all(b)?;
            done += b.len() as u64;
            if progress(done) {
                Ok(())
            } else {
                Err(Error::Cancelled)
            }
        })?;
        Ok(size)
    }

    fn read_range(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let it = self.resolve_item(path)?;
        if it.is_dir() {
            return Err(Error::IsADirectory);
        }
        if offset >= it.stream.size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(it.stream.size - offset);
        let mut pos = 0usize;
        self.stream_range(&it.stream, offset, n, &mut |b| {
            buf[pos..pos + b.len()].copy_from_slice(b);
            pos += b.len();
            Ok(())
        })?;
        Ok(n as usize)
    }

    fn write_file(&mut self, path: &str, src: &mut dyn Read, size: u64, overwrite: bool, progress: Progress) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (parent, leaf) = split_parent(path)?;
        validate_name(leaf)?;
        let mut dir = self.load_dir(&parent)?;
        if let Some(existing) = self.find_in(&dir, leaf) {
            if existing.is_dir() {
                return Err(Error::IsADirectory);
            }
            if !overwrite {
                return Err(Error::AlreadyExists);
            }
            self.remove_item(&mut dir, &existing)?;
        }
        let n = size.div_ceil(self.cluster_size);
        if n > u32::MAX as u64 {
            return Err(Error::NoSpace);
        }
        let (clusters, contiguous) = self.alloc(n as u32)?;
        if let Err(e) = self.write_data(&clusters, src, size, progress) {
            self.release(&clusters, contiguous);
            self.flush_meta()?;
            return Err(e);
        }
        let s = Stream { first: clusters.first().copied().unwrap_or(0), size, valid: size, contiguous };
        let set = self.entry_set(leaf, ATTR_ARCHIVE, s, None);
        if let Err(e) = self.insert_set(&mut dir, &set) {
            self.release(&clusters, contiguous);
            self.flush_meta()?;
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
        let mut dir = self.load_dir(&parent)?;
        if self.find_in(&dir, leaf).is_some() {
            return Err(Error::AlreadyExists);
        }
        let (clusters, _) = self.alloc(1)?;
        let c = clusters[0];
        let zeros = vec![0u8; self.cluster_size as usize];
        self.disk.write_at(self.cluster_offset(c), &zeros)?;
        let s = Stream { first: c, size: self.cluster_size, valid: self.cluster_size, contiguous: true };
        let set = self.entry_set(leaf, ATTR_DIRECTORY, s, None);
        if let Err(e) = self.insert_set(&mut dir, &set) {
            self.release(&[c], true);
            self.flush_meta()?;
            return Err(e);
        }
        self.disk.flush()
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (parent, leaf) = split_parent(path)?;
        let mut dir = self.load_dir(&parent)?;
        let it = self.find_in(&dir, leaf).ok_or(Error::NotFound)?;
        self.remove_item(&mut dir, &it)?;
        self.disk.flush()
    }

    fn rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        validate_name(new_name)?;
        let (parent, leaf) = split_parent(path)?;
        let mut dir = self.load_dir(&parent)?;
        let it = self.find_in(&dir, leaf).ok_or(Error::NotFound)?;
        if let Some(other) = self.find_in(&dir, new_name) {
            if other.index != it.index {
                return Err(Error::AlreadyExists);
            }
        }
        // Free the old slots in memory first so the new set may reuse them.
        for i in it.index..it.index + it.count {
            dir.data[i * ENTRY] &= 0x7F;
        }
        let set = self.entry_set(new_name, it.attr, it.stream, Some(&it.file_entry));
        self.insert_set(&mut dir, &set)?;
        let stale: Vec<usize> = (it.index..it.index + it.count).filter(|&i| dir.data[i * ENTRY] & 0x80 == 0).collect();
        for i in stale {
            self.write_dir_entries(&dir, i, 1)?;
        }
        self.disk.flush()
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_meta()?;
        self.disk.flush()
    }

    fn raw_disk(&mut self) -> Option<&mut (dyn Disk + 'static)> {
        Some(&mut *self.disk)
    }

    fn extents(&mut self, path: &str) -> Result<Vec<(u64, u64)>> {
        let it = self.resolve_item(path)?;
        let clusters = self.clusters_of(&it.stream)?;
        Ok(super::runs(&clusters, self.heap_offset, self.cluster_size, it.stream.size))
    }

    fn set_hidden_system(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let (parent, leaf) = split_parent(path)?;
        let mut dir = self.load_dir(&parent)?;
        let it = self.find_in(&dir, leaf).ok_or(Error::NotFound)?;
        let at = it.index * ENTRY;
        let attr = le16(&dir.data, at + 4) | 0x06;
        put_le16(&mut dir.data, at + 4, attr);
        let sum = entry_set_checksum(&dir.data[at..at + it.count * ENTRY]);
        put_le16(&mut dir.data, at + 2, sum);
        self.write_dir_entries(&dir, it.index, it.count)
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
        let cs = self.cluster_size;
        if end <= start || end <= self.heap_offset {
            return;
        }
        let lo = 2 + (start.saturating_sub(self.heap_offset) / cs) as u32;
        let hi = (2 + (end - self.heap_offset).div_ceil(cs)).min(self.cluster_count as u64 + 2) as u32;
        if lo >= hi {
            return;
        }
        self.reserved = Some((lo, hi));
        self.reserved_free = (lo..hi).filter(|&c| !self.used(c)).count() as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_skips_its_own_field() {
        let mut set = vec![0u8; 96];
        set[0] = 0x85;
        set[1] = 2;
        set[32] = 0xC0;
        set[64] = 0xC1;
        let c = entry_set_checksum(&set);
        set[2] = 0xAB;
        set[3] = 0xCD;
        assert_eq!(entry_set_checksum(&set), c);
    }

    #[test]
    fn upcase_expansion() {
        // a..c -> A..C, then 0xFFFF 3 (identity for 3), then 'x' maps to 'X'.
        let words: Vec<u16> = vec![0xFFFF, 0x61, b'A' as u16, b'B' as u16, b'C' as u16, 0xFFFF, 3, b'X' as u16];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let t = expand_upcase(&bytes);
        assert_eq!(t[0x61], b'A' as u16);
        assert_eq!(t[0x63], b'C' as u16);
        assert_eq!(t[0x64], 0x64);
        assert_eq!(t[0x67], b'X' as u16);
        assert_eq!(t[0x2000], 0x2000);
    }
}
