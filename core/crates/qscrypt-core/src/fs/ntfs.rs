//! NTFS, read-only.
//!
//! Enough of NTFS 3.x to browse and read what Windows (or VeraCrypt on
//! Windows) writes: MFT records with update-sequence fixups, data runs,
//! attribute lists for fragmented files, the `$I30` directory B-tree,
//! resident, non-resident and sparse data. Compressed and EFS-encrypted
//! files are reported as unsupported rather than returned wrong.

use super::{components, same_name, DirEntry, FileSystem, Progress};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{le16, le32, le64};
use std::collections::HashSet;
use std::io::{Read, Write};

const IO_CHUNK: usize = 1 << 20;
const ROOT: u64 = 5;
const MFT_RECORD_VOLUME: u64 = 3;
const MFT_RECORD_BITMAP: u64 = 6;

const AT_STANDARD_INFORMATION: u32 = 0x10;
const AT_ATTRIBUTE_LIST: u32 = 0x20;
const AT_VOLUME_NAME: u32 = 0x60;
const AT_DATA: u32 = 0x80;
const AT_INDEX_ROOT: u32 = 0x90;
const AT_INDEX_ALLOCATION: u32 = 0xA0;
const AT_END: u32 = 0xFFFF_FFFF;

const FLAG_COMPRESSED: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 0x4000;

const I30: [u16; 4] = [b'$' as u16, b'I' as u16, b'3' as u16, b'0' as u16];

/// Windows FILETIME (100 ns since 1601) to Unix seconds.
fn nt_time(t: u64) -> i64 {
    if t == 0 {
        0
    } else {
        (t / 10_000_000) as i64 - 11_644_473_600
    }
}

#[derive(Clone, Copy, Debug)]
struct Run {
    vcn: u64,
    /// None for a sparse run.
    lcn: Option<u64>,
    len: u64,
}

#[derive(Clone, Debug)]
struct Attr {
    ty: u32,
    name: Vec<u16>,
    flags: u16,
    resident: Option<Vec<u8>>,
    start_vcn: u64,
    runs: Vec<Run>,
    size: u64,
    init: u64,
}

struct Record {
    flags: u16,
    attrs: Vec<Attr>,
}

/// A whole attribute value, possibly spread over several records.
enum Stream {
    Resident(Vec<u8>),
    NonResident { runs: Vec<Run>, size: u64, init: u64, flags: u16 },
}

impl Stream {
    fn size(&self) -> u64 {
        match self {
            Stream::Resident(v) => v.len() as u64,
            Stream::NonResident { size, .. } => *size,
        }
    }
}

#[derive(Clone, Debug)]
struct Item {
    name: String,
    record: u64,
    is_dir: bool,
}

pub struct Ntfs {
    disk: Box<dyn Disk>,
    cluster_size: u64,
    record_size: usize,
    total_clusters: u64,
    mft: Vec<Run>,
    mft_size: u64,
    label: String,
    free: Option<u64>,
}

fn apply_fixup(buf: &mut [u8], magic: &[u8; 4]) -> Result<()> {
    if &buf[..4] != magic {
        return Err(Error::corrupt(format!("bad {} record", String::from_utf8_lossy(magic))));
    }
    let usa_off = le16(buf, 4) as usize;
    let usa_count = le16(buf, 6) as usize;
    if usa_count == 0 || usa_off + 2 * usa_count > buf.len() {
        return Err(Error::corrupt("bad update sequence array"));
    }
    let usn = [buf[usa_off], buf[usa_off + 1]];
    for i in 1..usa_count {
        let pos = i * 512 - 2;
        if pos + 2 > buf.len() {
            break;
        }
        if buf[pos..pos + 2] != usn {
            return Err(Error::corrupt("torn NTFS record (update sequence mismatch)"));
        }
        let fix = [buf[usa_off + 2 * i], buf[usa_off + 2 * i + 1]];
        buf[pos..pos + 2].copy_from_slice(&fix);
    }
    Ok(())
}

fn decode_runs(data: &[u8], start_vcn: u64) -> Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut vcn = start_vcn;
    let mut lcn: i64 = 0;
    let mut p = 0usize;
    while p < data.len() {
        let h = data[p];
        if h == 0 {
            break;
        }
        let (ls, os) = ((h & 0x0F) as usize, (h >> 4) as usize);
        p += 1;
        if ls == 0 || ls > 8 || os > 8 || p + ls + os > data.len() {
            return Err(Error::corrupt("bad NTFS data run"));
        }
        let mut len = 0u64;
        for k in 0..ls {
            len |= (data[p + k] as u64) << (8 * k);
        }
        p += ls;
        if os == 0 {
            runs.push(Run { vcn, lcn: None, len });
        } else {
            let mut delta = 0i64;
            for k in 0..os {
                delta |= (data[p + k] as i64) << (8 * k);
            }
            // Sign-extend from the field width.
            let shift = 64 - 8 * os as u32;
            delta = (delta << shift) >> shift;
            lcn += delta;
            if lcn < 0 {
                return Err(Error::corrupt("NTFS data run before the volume start"));
            }
            runs.push(Run { vcn, lcn: Some(lcn as u64), len });
        }
        p += os;
        vcn += len;
    }
    Ok(runs)
}

fn parse_record(buf: &[u8]) -> Result<Record> {
    let flags = le16(buf, 22);
    let used = (le32(buf, 24) as usize).min(buf.len());
    let mut off = le16(buf, 20) as usize;
    let mut attrs = Vec::new();
    while off + 8 <= used {
        let ty = le32(buf, off);
        if ty == AT_END {
            break;
        }
        let len = le32(buf, off + 4) as usize;
        if len < 16 || off + len > buf.len() {
            return Err(Error::corrupt("bad NTFS attribute"));
        }
        let a = &buf[off..off + len];
        let name_len = a[9] as usize;
        let name_off = le16(a, 10) as usize;
        let name: Vec<u16> = if name_len > 0 && name_off + 2 * name_len <= len {
            (0..name_len).map(|i| le16(a, name_off + 2 * i)).collect()
        } else {
            Vec::new()
        };
        let aflags = le16(a, 12);
        let attr = if a[8] == 0 {
            let vlen = le32(a, 16) as usize;
            let voff = le16(a, 20) as usize;
            if voff + vlen > len {
                return Err(Error::corrupt("bad resident NTFS attribute"));
            }
            Attr { ty, name, flags: aflags, resident: Some(a[voff..voff + vlen].to_vec()), start_vcn: 0, runs: Vec::new(), size: vlen as u64, init: vlen as u64 }
        } else {
            if len < 64 {
                return Err(Error::corrupt("bad non-resident NTFS attribute"));
            }
            let start_vcn = le64(a, 16);
            let runs_off = le16(a, 32) as usize;
            if runs_off > len {
                return Err(Error::corrupt("bad NTFS run list offset"));
            }
            let runs = decode_runs(&a[runs_off..], start_vcn)?;
            Attr { ty, name, flags: aflags, resident: None, start_vcn, runs, size: le64(a, 48), init: le64(a, 56) }
        };
        attrs.push(attr);
        off += len;
    }
    Ok(Record { flags, attrs })
}

impl Ntfs {
    pub fn mount(mut disk: Box<dyn Disk>) -> Result<Ntfs> {
        let mut b = [0u8; 512];
        disk.read_at(0, &mut b)?;
        if &b[3..11] != b"NTFS    " {
            return Err(Error::corrupt("not an NTFS boot sector"));
        }
        let bps = le16(&b, 11) as u64;
        let spc_raw = b[13];
        let spc = if spc_raw <= 0x80 { spc_raw as u64 } else { 1u64 << (256 - spc_raw as u32).min(31) };
        let cluster_size = bps * spc;
        let size_of = |raw: u8| -> u64 {
            let v = raw as i8;
            if v > 0 {
                v as u64 * cluster_size
            } else {
                1u64 << (-(v as i32)).clamp(0, 31)
            }
        };
        let record_size = size_of(b[64]);
        if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 || cluster_size > (2 << 20) || !(512..=65536).contains(&record_size) {
            return Err(Error::corrupt("unusual NTFS geometry"));
        }
        let total_clusters = le64(&b, 40) * bps / cluster_size;
        let mft_lcn = le64(&b, 48);
        let mut rec0 = vec![0u8; record_size as usize];
        disk.read_at(mft_lcn * cluster_size, &mut rec0)?;
        apply_fixup(&mut rec0, b"FILE")?;
        let r0 = parse_record(&rec0)?;
        let data = r0.attrs.iter().find(|a| a.ty == AT_DATA && a.name.is_empty()).ok_or_else(|| Error::corrupt("$MFT has no data"))?;
        if data.resident.is_some() {
            return Err(Error::corrupt("resident $MFT"));
        }
        let mut fs = Ntfs {
            disk,
            cluster_size,
            record_size: record_size as usize,
            total_clusters,
            mft: data.runs.clone(),
            mft_size: data.size,
            label: String::new(),
            free: None,
        };
        // A very fragmented $MFT continues in extension records.
        if r0.attrs.iter().any(|a| a.ty == AT_ATTRIBUTE_LIST) {
            if let Stream::NonResident { runs, size, .. } = fs.stream(0, AT_DATA, &[])? {
                fs.mft = runs;
                fs.mft_size = size;
            }
        }
        if let Ok(Stream::Resident(v)) = fs.stream(MFT_RECORD_VOLUME, AT_VOLUME_NAME, &[]) {
            let units: Vec<u16> = v.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            fs.label = String::from_utf16_lossy(&units);
        }
        Ok(fs)
    }

    /// Reads `buf.len()` bytes at `offset` of a non-resident stream.
    fn read_runs(&mut self, runs: &[Run], size: u64, init: u64, offset: u64, buf: &mut [u8]) -> Result<()> {
        let cs = self.cluster_size;
        let end = offset + buf.len() as u64;
        if end > size {
            return Err(Error::corrupt("read beyond NTFS stream"));
        }
        let mut pos = offset;
        while pos < end {
            let dst = (pos - offset) as usize;
            if pos >= init {
                buf[dst..].fill(0);
                break;
            }
            let vcn = pos / cs;
            let run = runs.iter().find(|r| vcn >= r.vcn && vcn < r.vcn + r.len).ok_or_else(|| Error::corrupt("NTFS stream hole outside its runs"))?;
            let run_end = (run.vcn + run.len) * cs;
            let n = (run_end.min(end).min(init.max(pos + 1)) - pos) as usize;
            let n = n.min(buf.len() - dst);
            match run.lcn {
                None => buf[dst..dst + n].fill(0),
                Some(lcn) => {
                    let phys = (lcn + (vcn - run.vcn)) * cs + pos % cs;
                    self.disk.read_at(phys, &mut buf[dst..dst + n])?;
                }
            }
            pos += n as u64;
        }
        Ok(())
    }

    fn read_record(&mut self, n: u64) -> Result<Record> {
        let rs = self.record_size as u64;
        let off = n.checked_mul(rs).filter(|o| o + rs <= self.mft_size).ok_or(Error::NotFound)?;
        let mut buf = vec![0u8; self.record_size];
        let (runs, size) = (self.mft.clone(), self.mft_size);
        self.read_runs(&runs, size, size, off, &mut buf)?;
        apply_fixup(&mut buf, b"FILE")?;
        parse_record(&buf)
    }

    /// The complete value of attribute (type, name) of record `n`,
    /// following the attribute list into extension records when present.
    fn stream(&mut self, n: u64, ty: u32, name: &[u16]) -> Result<Stream> {
        let base = self.read_record(n)?;
        let mut parts: Vec<Attr> = Vec::new();
        if let Some(list) = base.attrs.iter().find(|a| a.ty == AT_ATTRIBUTE_LIST).cloned() {
            let bytes = match &list.resident {
                Some(v) => v.clone(),
                None => {
                    let mut v = vec![0u8; list.size as usize];
                    self.read_runs(&list.runs, list.size, list.init, 0, &mut v)?;
                    v
                }
            };
            let mut p = 0usize;
            let mut wanted: Vec<(u64, u64)> = Vec::new(); // (record, start vcn)
            while p + 26 <= bytes.len() {
                let ety = le32(&bytes, p);
                let elen = le16(&bytes, p + 4) as usize;
                if elen < 26 || p + elen > bytes.len() {
                    break;
                }
                let nlen = bytes[p + 6] as usize;
                let noff = bytes[p + 7] as usize;
                let ename: Vec<u16> = (0..nlen).map(|i| le16(&bytes, p + noff + 2 * i)).collect();
                if ety == ty && ename == name {
                    wanted.push((le64(&bytes, p + 16) & 0x0000_FFFF_FFFF_FFFF, le64(&bytes, p + 8)));
                }
                p += elen;
            }
            for (rec, vcn) in wanted {
                let r = if rec == n { None } else { Some(self.read_record(rec)?) };
                let attrs = r.as_ref().map_or(&base.attrs, |r| &r.attrs);
                if let Some(a) = attrs.iter().find(|a| a.ty == ty && a.name == name && a.start_vcn == vcn) {
                    parts.push(a.clone());
                }
            }
        }
        if parts.is_empty() {
            parts.extend(base.attrs.iter().filter(|a| a.ty == ty && a.name == name).cloned());
        }
        parts.sort_by_key(|a| a.start_vcn);
        let first = parts.first().ok_or(Error::NotFound)?.clone();
        if let Some(v) = first.resident {
            return Ok(Stream::Resident(v));
        }
        let mut runs = Vec::new();
        for p in &parts {
            runs.extend_from_slice(&p.runs);
        }
        Ok(Stream::NonResident { runs, size: first.size, init: first.init, flags: first.flags })
    }

    fn read_stream(&mut self, s: &Stream, offset: u64, buf: &mut [u8]) -> Result<()> {
        match s {
            Stream::Resident(v) => {
                let o = offset as usize;
                if o + buf.len() > v.len() {
                    return Err(Error::corrupt("read beyond NTFS value"));
                }
                buf.copy_from_slice(&v[o..o + buf.len()]);
                Ok(())
            }
            Stream::NonResident { runs, size, init, flags } => {
                if flags & FLAG_COMPRESSED != 0 {
                    return Err(Error::unsupported("compressed NTFS files"));
                }
                if flags & FLAG_ENCRYPTED != 0 {
                    return Err(Error::unsupported("EFS-encrypted NTFS files"));
                }
                let runs = runs.clone();
                self.read_runs(&runs, *size, *init, offset, buf)
            }
        }
    }

    fn index_entries(&mut self, data: &[u8], header: usize, out: &mut Vec<(u64, Vec<u8>)>, children: &mut Vec<u64>) -> Result<()> {
        let start = header + le32(data, header) as usize;
        let end = (header + le32(data, header + 4) as usize).min(data.len());
        let mut p = start;
        while p + 16 <= end {
            let elen = le16(data, p + 8) as usize;
            let klen = le16(data, p + 10) as usize;
            let eflags = le16(data, p + 12);
            if elen < 16 || p + elen > end {
                return Err(Error::corrupt("bad NTFS index entry"));
            }
            if eflags & 0x01 != 0 {
                children.push(le64(data, p + elen - 8));
            }
            if eflags & 0x02 != 0 {
                break;
            }
            if 16 + klen <= elen && klen >= 66 {
                out.push((le64(data, p) & 0x0000_FFFF_FFFF_FFFF, data[p + 16..p + 16 + klen].to_vec()));
            }
            p += elen;
        }
        Ok(())
    }

    /// Every (record, $FILE_NAME key) in a directory's $I30 index.
    fn dir_keys(&mut self, dir: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let root = match self.stream(dir, AT_INDEX_ROOT, &I30) {
            Ok(Stream::Resident(v)) => v,
            Ok(_) => return Err(Error::corrupt("non-resident index root")),
            Err(Error::NotFound) => return Err(Error::NotADirectory),
            Err(e) => return Err(e),
        };
        if root.len() < 32 {
            return Err(Error::corrupt("short NTFS index root"));
        }
        let block_size = le32(&root, 8) as u64;
        let mut out = Vec::new();
        let mut pending = Vec::new();
        self.index_entries(&root, 16, &mut out, &mut pending)?;
        if pending.is_empty() {
            return Ok(out);
        }
        let alloc = self.stream(dir, AT_INDEX_ALLOCATION, &I30)?;
        // Index block numbers count clusters, or 512-byte units when blocks
        // are smaller than a cluster.
        let unit = if block_size >= self.cluster_size { self.cluster_size } else { 512 };
        let mut seen = HashSet::new();
        while let Some(vcn) = pending.pop() {
            if !seen.insert(vcn) || seen.len() > 1_000_000 {
                continue;
            }
            let mut block = vec![0u8; block_size as usize];
            let off = vcn * unit;
            if off + block_size > alloc.size() {
                return Err(Error::corrupt("NTFS index block beyond its allocation"));
            }
            self.read_stream(&alloc, off, &mut block)?;
            apply_fixup(&mut block, b"INDX")?;
            self.index_entries(&block, 24, &mut out, &mut pending)?;
        }
        Ok(out)
    }

    fn items(&mut self, dir: u64) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for (record, key) in self.dir_keys(dir)? {
            let nlen = key[64] as usize;
            let namespace = key[65];
            if namespace == 2 || 66 + 2 * nlen > key.len() {
                continue; // DOS 8.3 alias of a long name
            }
            let units: Vec<u16> = (0..nlen).map(|i| le16(&key, 66 + 2 * i)).collect();
            let name = String::from_utf16_lossy(&units);
            if name == "." || (record < 24 && name.starts_with('$')) {
                continue; // the root's self-entry and metadata files
            }
            let is_dir = le32(&key, 56) & 0x1000_0000 != 0;
            items.push(Item { name, record, is_dir });
        }
        Ok(items)
    }

    fn resolve(&mut self, path: &str) -> Result<Item> {
        let comps = components(path)?;
        let mut cur = Item { name: String::new(), record: ROOT, is_dir: true };
        for comp in comps {
            if !cur.is_dir {
                return Err(Error::NotADirectory);
            }
            cur = self.items(cur.record)?.into_iter().find(|it| same_name(&it.name, comp)).ok_or(Error::NotFound)?;
        }
        Ok(cur)
    }

    fn entry_of(&mut self, it: &Item) -> Result<DirEntry> {
        let rec = self.read_record(it.record)?;
        let modified = rec
            .attrs
            .iter()
            .find(|a| a.ty == AT_STANDARD_INFORMATION)
            .and_then(|a| a.resident.as_ref())
            .filter(|v| v.len() >= 16)
            .map_or(0, |v| nt_time(le64(v, 8)));
        let is_dir = it.is_dir || rec.flags & 0x02 != 0;
        let size = if is_dir { 0 } else { self.stream(it.record, AT_DATA, &[]).map_or(0, |s| s.size()) };
        Ok(DirEntry { name: it.name.clone(), is_dir, size, modified })
    }

    fn data_of(&mut self, path: &str) -> Result<Stream> {
        let it = self.resolve(path)?;
        if it.is_dir {
            return Err(Error::IsADirectory);
        }
        self.stream(it.record, AT_DATA, &[])
    }
}

impl FileSystem for Ntfs {
    fn kind(&self) -> &'static str {
        "NTFS"
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn read_only(&self) -> bool {
        true
    }

    fn total_bytes(&self) -> u64 {
        self.total_clusters * self.cluster_size
    }

    fn free_bytes(&mut self) -> Result<u64> {
        if let Some(f) = self.free {
            return Ok(f);
        }
        let bitmap = self.stream(MFT_RECORD_BITMAP, AT_DATA, &[])?;
        let need = self.total_clusters.div_ceil(8).min(bitmap.size());
        let mut used = 0u64;
        let mut pos = 0u64;
        let mut buf = vec![0u8; IO_CHUNK];
        while pos < need {
            let n = ((need - pos) as usize).min(buf.len());
            self.read_stream(&bitmap, pos, &mut buf[..n])?;
            for (i, &b) in buf[..n].iter().enumerate() {
                let bit_base = (pos + i as u64) * 8;
                let valid = (self.total_clusters.saturating_sub(bit_base)).min(8) as u32;
                let mask = if valid >= 8 { 0xFF } else { (1u16 << valid) as u8 - 1 };
                used += (b & mask).count_ones() as u64;
            }
            pos += n as u64;
        }
        let free = (self.total_clusters - used.min(self.total_clusters)) * self.cluster_size;
        self.free = Some(free);
        Ok(free)
    }

    fn max_file_size(&self) -> u64 {
        0
    }

    fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let dir = self.resolve(path)?;
        if !dir.is_dir {
            return Err(Error::NotADirectory);
        }
        let items = self.items(dir.record)?;
        let mut seen = HashSet::new();
        let mut out = Vec::with_capacity(items.len());
        for it in items {
            // Hard links and Win32+DOS pairs can list a record twice.
            if seen.insert((it.record, it.name.clone())) {
                out.push(self.entry_of(&it)?);
            }
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<DirEntry> {
        if components(path)?.is_empty() {
            return Ok(DirEntry { name: String::new(), is_dir: true, size: 0, modified: 0 });
        }
        let it = self.resolve(path)?;
        self.entry_of(&it)
    }

    fn read_file(&mut self, path: &str, out: &mut dyn Write, progress: Progress) -> Result<u64> {
        let s = self.data_of(path)?;
        let size = s.size();
        let mut buf = vec![0u8; IO_CHUNK];
        let mut pos = 0u64;
        while pos < size {
            let n = ((size - pos) as usize).min(buf.len());
            self.read_stream(&s, pos, &mut buf[..n])?;
            out.write_all(&buf[..n])?;
            pos += n as u64;
            if !progress(pos) {
                crate::util::wipe(&mut buf);
                return Err(Error::Cancelled);
            }
        }
        crate::util::wipe(&mut buf);
        Ok(size)
    }

    fn read_range(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let s = self.data_of(path)?;
        let size = s.size();
        if offset >= size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        self.read_stream(&s, offset, &mut buf[..n])?;
        Ok(n)
    }

    fn write_file(&mut self, _: &str, _: &mut dyn Read, _: u64, _: bool, _: Progress) -> Result<()> {
        Err(Error::unsupported("writing to NTFS"))
    }

    fn mkdir(&mut self, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to NTFS"))
    }

    fn remove(&mut self, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to NTFS"))
    }

    fn rename(&mut self, _: &str, _: &str) -> Result<()> {
        Err(Error::unsupported("writing to NTFS"))
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_runs_decode() {
        // 0x21: 1-byte length, 2-byte offset. Then a sparse run, then a negative delta.
        let runs = decode_runs(&[0x21, 0x10, 0x00, 0x01, 0x01, 0x08, 0x11, 0x04, 0xF0, 0x00], 0).unwrap();
        assert_eq!(runs.len(), 3);
        assert_eq!((runs[0].vcn, runs[0].lcn, runs[0].len), (0, Some(0x100), 0x10));
        assert_eq!((runs[1].vcn, runs[1].lcn, runs[1].len), (0x10, None, 8));
        assert_eq!((runs[2].vcn, runs[2].lcn, runs[2].len), (0x18, Some(0x100 - 0x10), 4));
    }

    #[test]
    fn fixups_restore_sector_tails() {
        let mut rec = vec![0u8; 1024];
        rec[..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&48u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[48..50].copy_from_slice(&[0xAB, 0xCD]); // USN
        rec[50..52].copy_from_slice(&[1, 2]);
        rec[52..54].copy_from_slice(&[3, 4]);
        rec[510..512].copy_from_slice(&[0xAB, 0xCD]);
        rec[1022..1024].copy_from_slice(&[0xAB, 0xCD]);
        apply_fixup(&mut rec, b"FILE").unwrap();
        assert_eq!(&rec[510..512], &[1, 2]);
        assert_eq!(&rec[1022..1024], &[3, 4]);
        rec[1022] = 0;
        let mut torn = rec.clone();
        torn[510..512].copy_from_slice(&[9, 9]);
        assert!(apply_fixup(&mut torn, b"FILE").is_err());
    }
}
