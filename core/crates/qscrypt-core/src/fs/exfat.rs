//! exFAT, read-only (Microsoft exFAT specification, 2019).

use super::{components, same_name, split_parent, DirEntry, FileSystem, Progress};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{le16, le32, le64, unix_from_civil, Civil};
use std::io::{Read, Write};

const ENTRY: usize = 32;
const IO_CHUNK: usize = 1 << 20;
const ATTR_DIRECTORY: u16 = 0x10;
const MAX_DIR_BYTES: u64 = 256 << 20;

#[derive(Clone, Copy, Debug)]
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
}

impl Item {
    fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
}

pub struct Exfat {
    disk: Box<dyn Disk>,
    cluster_size: u64,
    heap_offset: u64,
    cluster_count: u32,
    root: Stream,
    fat: Vec<u8>,
    tz: i32,
    label: String,
    bitmap: Option<Stream>,
    free: Option<u64>,
}

fn entry_set_checksum(set: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        c = (if c & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(c >> 1).wrapping_add(b as u16);
    }
    c
}

impl Exfat {
    pub fn mount(mut disk: Box<dyn Disk>, tz_offset_min: i32) -> Result<Exfat> {
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
        let mut fat = vec![0u8; fat_needed as usize];
        disk.read_at(fat_offset, &mut fat)?;
        let mut fs = Exfat {
            disk,
            cluster_size,
            heap_offset,
            cluster_count,
            root: Stream { first: root_cluster, size: 0, valid: 0, contiguous: false },
            fat,
            tz: tz_offset_min,
            label: String::new(),
            bitmap: None,
            free: None,
        };
        if !fs.valid_cluster(root_cluster) {
            return Err(Error::corrupt("bad exFAT root cluster"));
        }
        let root_len = fs.chain(root_cluster)?.len() as u64 * cluster_size;
        fs.root.size = root_len;
        fs.root.valid = root_len;
        let root = fs.root;
        let data = fs.read_stream(&root, MAX_DIR_BYTES)?;
        for e in data.chunks_exact(ENTRY) {
            match e[0] {
                0x00 => break,
                0x81 if fs.bitmap.is_none() => {
                    let len = le64(e, 24);
                    fs.bitmap = Some(Stream { first: le32(e, 20), size: len, valid: len, contiguous: false });
                }
                0x83 => {
                    let n = (e[1] as usize).min(11);
                    let units: Vec<u16> = (0..n).map(|k| le16(e, 2 + 2 * k)).collect();
                    fs.label = String::from_utf16_lossy(&units);
                }
                _ => {}
            }
        }
        Ok(fs)
    }

    fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.cluster_count + 2
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
            let next = le32(&self.fat, c as usize * 4);
            if next == 0xFFFF_FFFF {
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

    fn cluster_offset(&self, c: u32) -> u64 {
        self.heap_offset + (c as u64 - 2) * self.cluster_size
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
            });
            i += 1 + secondary;
        }
        items
    }

    fn dir_items(&mut self, s: &Stream) -> Result<Vec<Item>> {
        let data = self.read_stream(s, MAX_DIR_BYTES)?;
        Ok(self.parse(&data))
    }

    fn resolve_dir(&mut self, comps: &[&str]) -> Result<Stream> {
        let mut cur = self.root;
        for comp in comps {
            let items = self.dir_items(&cur)?;
            let it = items.into_iter().find(|it| same_name(&it.name, comp)).ok_or(Error::NotFound)?;
            if !it.is_dir() {
                return Err(Error::NotADirectory);
            }
            cur = it.stream;
        }
        Ok(cur)
    }

    fn resolve_item(&mut self, path: &str) -> Result<Item> {
        let (parent, leaf) = split_parent(path)?;
        let dir = self.resolve_dir(&parent)?;
        self.dir_items(&dir)?.into_iter().find(|it| same_name(&it.name, leaf)).ok_or(Error::NotFound)
    }

    fn to_entry(it: &Item) -> DirEntry {
        DirEntry { name: it.name.clone(), is_dir: it.is_dir(), size: if it.is_dir() { 0 } else { it.stream.size }, modified: it.modified }
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
        true
    }

    fn total_bytes(&self) -> u64 {
        self.cluster_count as u64 * self.cluster_size
    }

    fn free_bytes(&mut self) -> Result<u64> {
        if let Some(f) = self.free {
            return Ok(f);
        }
        let Some(bm) = self.bitmap else {
            return Ok(0);
        };
        let bytes = self.read_stream(&bm, 64 << 20)?;
        let mut used = 0u64;
        for c in 0..self.cluster_count as usize {
            if bytes.get(c / 8).is_some_and(|b| b & (1 << (c % 8)) != 0) {
                used += 1;
            }
        }
        let free = (self.cluster_count as u64 - used) * self.cluster_size;
        self.free = Some(free);
        Ok(free)
    }

    fn max_file_size(&self) -> u64 {
        u64::MAX
    }

    fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let comps = components(path)?;
        let dir = self.resolve_dir(&comps)?;
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

    fn write_file(&mut self, _: &str, _: &mut dyn Read, _: u64, _: bool, _: Progress) -> Result<()> {
        Err(Error::unsupported("writing to exFAT"))
    }

    fn mkdir(&mut self, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to exFAT"))
    }

    fn remove(&mut self, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to exFAT"))
    }

    fn rename(&mut self, _: &str, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to exFAT"))
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
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
}
