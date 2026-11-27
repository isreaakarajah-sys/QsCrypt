//! NTFS, read and write.
//!
//! Reading covers what Windows (or VeraCrypt on Windows) writes: MFT records
//! with update-sequence fixups, data runs, attribute lists for fragmented
//! files, the `$I30` directory B-tree, resident, non-resident and sparse
//! data. Compressed and EFS-encrypted files are reported as unsupported
//! rather than returned wrong.
//!
//! Writing (see `ntfs_write.rs`) is our own implementation, used only when
//! Windows closed the volume cleanly; otherwise the volume stays read-only
//! and says why.

use super::{components, same_name, split_parent, validate_name, CheckReport, DirEntry, FileSystem, Progress};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{le16, le32, le64, put_le16};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::{Read, Write};

#[path = "ntfs_write.rs"]
mod write;

#[cfg(test)]
#[path = "ntfs_tests.rs"]
mod ntfs_tests;

const IO_CHUNK: usize = 1 << 20;
const ROOT: u64 = 5;
const MFT_RECORD_MIRROR: u64 = 1;
const MFT_RECORD_LOGFILE: u64 = 2;
const MFT_RECORD_VOLUME: u64 = 3;
const MFT_RECORD_BITMAP: u64 = 6;
const MFT_RECORD_UPCASE: u64 = 10;
const MFT_RECORD_EXTEND: u64 = 11;

const AT_STANDARD_INFORMATION: u32 = 0x10;
const AT_ATTRIBUTE_LIST: u32 = 0x20;
const AT_FILE_NAME: u32 = 0x30;
const AT_OBJECT_ID: u32 = 0x40;
const AT_SECURITY_DESCRIPTOR: u32 = 0x50;
const AT_VOLUME_NAME: u32 = 0x60;
const AT_VOLUME_INFORMATION: u32 = 0x70;
const AT_DATA: u32 = 0x80;
const AT_INDEX_ROOT: u32 = 0x90;
const AT_INDEX_ALLOCATION: u32 = 0xA0;
const AT_BITMAP: u32 = 0xB0;
const AT_REPARSE_POINT: u32 = 0xC0;
const AT_END: u32 = 0xFFFF_FFFF;

/// $FILE_NAME namespaces.
const NS_POSIX: u8 = 0;
const NS_DOS: u8 = 2;

/// Index collations.
const COLLATION_FILE_NAME: u32 = 1;
const COLLATION_NTOFS_ULONG: u32 = 0x10;
const COLLATION_NTOFS_ULONGS: u32 = 0x13;

/// $FILE_NAME attribute flag of a directory.
const FA_DIRECTORY_INDEX: u32 = 0x1000_0000;

/// The low 48 bits of a file reference: the record number.
const REF_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

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
    /// Sequence number of the record, from the reference that led here.
    seq: u16,
    is_dir: bool,
}

impl Item {
    fn file_ref(&self) -> u64 {
        self.record | (self.seq as u64) << 48
    }
}

pub struct Ntfs {
    disk: Box<dyn Disk>,
    cluster_size: u64,
    record_size: usize,
    index_block_size: u64,
    total_clusters: u64,
    mft: Vec<Run>,
    mft_size: u64,
    /// The $MFT data continues in extension records.
    mft_listed: bool,
    label: String,
    free: Option<u64>,
    root_seq: u16,
    /// $UpCase: the volume's own case table (empty if unreadable).
    upcase: Vec<u16>,
    /// Present when the volume may be written.
    w: Option<Box<write::State>>,
    /// Why a volume opened for writing stays read-only.
    ro_reason: Option<String>,
}

/// One entry of an index node, as stored (header, key, view data, padding)
/// but without its child pointer, which is kept apart.
#[derive(Clone, Debug)]
struct Ent {
    bytes: Vec<u8>,
    child: Option<u64>,
    end: bool,
}

impl Ent {
    fn end(child: Option<u64>) -> Ent {
        let mut bytes = vec![0u8; 16];
        put_le16(&mut bytes, 8, 16);
        put_le16(&mut bytes, 12, 2);
        Ent { bytes, child, end: true }
    }

    fn key(&self) -> &[u8] {
        let n = (le16(&self.bytes, 10) as usize).min(self.bytes.len().saturating_sub(16));
        &self.bytes[16..16 + n]
    }

    fn file_ref(&self) -> u64 {
        le64(&self.bytes, 0)
    }

    fn record(&self) -> u64 {
        self.file_ref() & REF_MASK
    }

    /// Bytes on disk, child pointer included.
    fn size(&self) -> usize {
        self.bytes.len() + if self.child.is_some() { 8 } else { 0 }
    }

    fn with_child(mut self, child: Option<u64>) -> Ent {
        self.child = child;
        self
    }
}

/// The entries of an index node whose header starts at `header`.
fn parse_node(data: &[u8], header: usize) -> Result<Vec<Ent>> {
    if header + 16 > data.len() {
        return Err(Error::corrupt("short NTFS index node"));
    }
    let start = header + le32(data, header) as usize;
    let end = (header + le32(data, header + 4) as usize).min(data.len());
    let mut out = Vec::new();
    let mut p = start;
    loop {
        if p + 16 > end {
            return Err(Error::corrupt("NTFS index node without an end entry"));
        }
        let elen = le16(data, p + 8) as usize;
        let klen = le16(data, p + 10) as usize;
        let eflags = le16(data, p + 12);
        let has_child = eflags & 0x01 != 0;
        let is_end = eflags & 0x02 != 0;
        let body = if has_child { elen.saturating_sub(8) } else { elen };
        if elen < 16 || p + elen > end || elen % 8 != 0 || body < 16 || (!is_end && 16 + klen > body) {
            return Err(Error::corrupt("bad NTFS index entry"));
        }
        let child = if has_child { Some(le64(data, p + elen - 8)) } else { None };
        let bytes = if is_end { data[p..p + 16].to_vec() } else { data[p..p + body].to_vec() };
        out.push(Ent { bytes, child, end: is_end });
        if is_end {
            return Ok(out);
        }
        p += elen;
        if out.len() > 100_000 {
            return Err(Error::corrupt("NTFS index node too long"));
        }
    }
}

/// Appends index entries as stored: lengths and flags are recomputed.
fn put_entries(ents: &[Ent], out: &mut Vec<u8>) {
    for e in ents {
        let at = out.len();
        out.extend_from_slice(&e.bytes);
        if let Some(c) = e.child {
            out.extend_from_slice(&c.to_le_bytes());
        }
        let len = out.len() - at;
        put_le16(out, at + 8, len as u16);
        if e.end {
            put_le16(out, at + 10, 0);
        }
        let mut fl = le16(out, at + 12) & !0x03;
        if e.child.is_some() {
            fl |= 0x01;
        }
        if e.end {
            fl |= 0x02;
        }
        put_le16(out, at + 12, fl);
    }
}

fn entries_size(ents: &[Ent]) -> usize {
    ents.iter().map(Ent::size).sum()
}

/// The UTF-16 name inside a $FILE_NAME value.
fn fn_name(key: &[u8]) -> &[u8] {
    if key.len() < 66 {
        return &[];
    }
    let n = key[64] as usize;
    &key[66..(66 + 2 * n).min(key.len())]
}

fn units_of(name: &[u8]) -> impl Iterator<Item = u16> + '_ {
    name.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
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
    pub fn mount(mut disk: Box<dyn Disk>, read_only: bool) -> Result<Ntfs> {
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
        let index_block_size = size_of(b[68]);
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
            index_block_size,
            total_clusters,
            mft: data.runs.clone(),
            mft_size: data.size,
            mft_listed: false,
            label: String::new(),
            free: None,
            root_seq: ROOT as u16,
            upcase: Vec::new(),
            w: None,
            ro_reason: None,
        };
        // A very fragmented $MFT continues in extension records.
        if r0.attrs.iter().any(|a| a.ty == AT_ATTRIBUTE_LIST) {
            fs.mft_listed = true;
            if let Stream::NonResident { runs, size, .. } = fs.stream(0, AT_DATA, &[])? {
                fs.mft = runs;
                fs.mft_size = size;
            }
        }
        if let Ok(Stream::Resident(v)) = fs.stream(MFT_RECORD_VOLUME, AT_VOLUME_NAME, &[]) {
            let units: Vec<u16> = v.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            fs.label = String::from_utf16_lossy(&units);
        }
        if let Ok(raw) = fs.record_buf(ROOT) {
            fs.root_seq = le16(&raw, 16);
        }
        // The case table orders every directory index. Without it names are
        // looked up one by one, and nothing is written.
        if let Ok(s) = fs.stream(MFT_RECORD_UPCASE, AT_DATA, &[]) {
            if s.size() == 131_072 {
                let mut t = vec![0u8; 131_072];
                if fs.read_stream(&s, 0, &mut t).is_ok() {
                    fs.upcase = units_of(&t).collect();
                }
            }
        }
        if !read_only {
            if fs.disk.is_read_only() {
                fs.ro_reason = Some("the drive itself is read-only".into());
            } else {
                match write::State::open(&mut fs) {
                    Ok(st) => fs.w = Some(Box::new(st)),
                    Err(why) => fs.ro_reason = Some(why),
                }
            }
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

    /// Record `n` with its fixups undone.
    fn record_buf(&mut self, n: u64) -> Result<Vec<u8>> {
        let rs = self.record_size as u64;
        let off = n.checked_mul(rs).filter(|o| o + rs <= self.mft_size).ok_or(Error::NotFound)?;
        let mut buf = vec![0u8; self.record_size];
        let (runs, size) = (std::mem::take(&mut self.mft), self.mft_size);
        let r = self.read_runs(&runs, size, size, off, &mut buf);
        self.mft = runs;
        r?;
        apply_fixup(&mut buf, b"FILE")?;
        Ok(buf)
    }

    fn read_record(&mut self, n: u64) -> Result<Record> {
        let buf = self.record_buf(n)?;
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

    /// The VCN unit of an index: clusters, or 512-byte units when index
    /// blocks are smaller than a cluster.
    fn index_unit(&self, block_size: u64) -> u64 {
        if block_size >= self.cluster_size {
            self.cluster_size
        } else {
            512
        }
    }

    /// Index block at `vcn` of an $INDEX_ALLOCATION stream, fixups undone.
    fn index_block(&mut self, alloc: &Stream, block_size: u64, vcn: u64) -> Result<Vec<u8>> {
        let off = vcn.checked_mul(self.index_unit(block_size)).ok_or_else(|| Error::corrupt("bad NTFS index VCN"))?;
        if off + block_size > alloc.size() {
            return Err(Error::corrupt("NTFS index block beyond its allocation"));
        }
        let mut block = vec![0u8; block_size as usize];
        self.read_stream(alloc, off, &mut block)?;
        apply_fixup(&mut block, b"INDX")?;
        Ok(block)
    }

    /// Every (file reference, $FILE_NAME key) in a directory's $I30 index.
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
        let take = |ents: Vec<Ent>, out: &mut Vec<(u64, Vec<u8>)>, pending: &mut Vec<u64>| {
            for e in ents {
                if let Some(c) = e.child {
                    pending.push(c);
                }
                if !e.end && e.key().len() >= 66 {
                    out.push((e.file_ref(), e.key().to_vec()));
                }
            }
        };
        take(parse_node(&root, 16)?, &mut out, &mut pending);
        if pending.is_empty() {
            return Ok(out);
        }
        let alloc = self.stream(dir, AT_INDEX_ALLOCATION, &I30)?;
        let mut seen = HashSet::new();
        while let Some(vcn) = pending.pop() {
            if !seen.insert(vcn) || seen.len() > 1_000_000 {
                continue;
            }
            let block = self.index_block(&alloc, block_size, vcn)?;
            take(parse_node(&block, 24)?, &mut out, &mut pending);
        }
        Ok(out)
    }

    fn item_of(file_ref: u64, key: &[u8]) -> Item {
        let units: Vec<u16> = units_of(fn_name(key)).collect();
        Item {
            name: String::from_utf16_lossy(&units),
            record: file_ref & REF_MASK,
            seq: (file_ref >> 48) as u16,
            is_dir: le32(key, 56) & FA_DIRECTORY_INDEX != 0,
        }
    }

    fn items(&mut self, dir: u64) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for (file_ref, key) in self.dir_keys(dir)? {
            let namespace = key[65];
            if namespace == NS_DOS {
                continue; // DOS 8.3 alias of a long name
            }
            let it = Self::item_of(file_ref, &key);
            if it.name == "." || (it.record < 24 && it.name.starts_with('$')) {
                continue; // the root's self-entry and metadata files
            }
            items.push(it);
        }
        Ok(items)
    }

    fn up(&self, c: u16) -> u16 {
        match self.upcase.get(c as usize) {
            Some(&u) => u,
            None if (b'a' as u16..=b'z' as u16).contains(&c) => c - 32,
            None => c,
        }
    }

    /// File-name order: upper-cased per $UpCase, then shorter first.
    fn cmp_names_ic(&self, a: &[u8], b: &[u8]) -> Ordering {
        let mut ia = units_of(a);
        let mut ib = units_of(b);
        loop {
            match (ia.next(), ib.next()) {
                (Some(x), Some(y)) => match self.up(x).cmp(&self.up(y)) {
                    Ordering::Equal => continue,
                    o => return o,
                },
                (None, None) => return Ordering::Equal,
                (None, _) => return Ordering::Less,
                (_, None) => return Ordering::Greater,
            }
        }
    }

    /// The order of keys in an index with collation `coll`.
    fn collate(&self, coll: u32, a: &[u8], b: &[u8]) -> Ordering {
        match coll {
            COLLATION_FILE_NAME => {
                let (na, nb) = (fn_name(a), fn_name(b));
                self.cmp_names_ic(na, nb).then_with(|| units_of(na).cmp(units_of(nb)))
            }
            COLLATION_NTOFS_ULONG if a.len() >= 4 && b.len() >= 4 => le32(a, 0).cmp(&le32(b, 0)),
            COLLATION_NTOFS_ULONGS => {
                let words = |k: &[u8]| -> Vec<u32> { k.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect() };
                words(a).cmp(&words(b))
            }
            _ => a.cmp(b),
        }
    }

    /// Looks `name` up in a directory by walking its B-tree (case-insensitive,
    /// as Windows does). Falls back to a full scan when the index cannot be
    /// walked.
    fn lookup(&mut self, dir: u64, name: &str) -> Result<Option<Item>> {
        let probe: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        match self.walk_lookup(dir, &probe) {
            Ok(found) => Ok(found),
            Err(Error::NotADirectory) => Err(Error::NotADirectory),
            Err(_) => Ok(self.items(dir)?.into_iter().find(|it| same_name(&it.name, name))),
        }
    }

    fn walk_lookup(&mut self, dir: u64, probe: &[u8]) -> Result<Option<Item>> {
        let root = match self.stream(dir, AT_INDEX_ROOT, &I30) {
            Ok(Stream::Resident(v)) => v,
            Ok(_) => return Err(Error::corrupt("non-resident index root")),
            Err(Error::NotFound) => return Err(Error::NotADirectory),
            Err(e) => return Err(e),
        };
        if root.len() < 32 || le32(&root, 4) != COLLATION_FILE_NAME || self.upcase.is_empty() {
            return Err(Error::unsupported("index walk"));
        }
        let block_size = le32(&root, 8) as u64;
        let mut ents = parse_node(&root, 16)?;
        let mut alloc: Option<Stream> = None;
        for _depth in 0..64 {
            let mut next = None;
            for e in &ents {
                if e.end {
                    next = e.child;
                    break;
                }
                match self.cmp_names_ic(probe, fn_name(e.key())) {
                    Ordering::Equal => {
                        let it = Self::item_of(e.file_ref(), e.key());
                        return Ok(Some(it));
                    }
                    Ordering::Less => {
                        next = e.child;
                        break;
                    }
                    Ordering::Greater => {}
                }
            }
            let Some(vcn) = next else { return Ok(None) };
            if alloc.is_none() {
                alloc = Some(self.stream(dir, AT_INDEX_ALLOCATION, &I30)?);
            }
            let block = self.index_block(alloc.as_ref().unwrap(), block_size, vcn)?;
            ents = parse_node(&block, 24)?;
        }
        Err(Error::corrupt("NTFS index too deep"))
    }

    fn root_item(&self) -> Item {
        Item { name: String::new(), record: ROOT, seq: self.root_seq, is_dir: true }
    }

    fn resolve(&mut self, path: &str) -> Result<Item> {
        let comps = components(path)?;
        self.resolve_comps(&comps)
    }

    fn resolve_comps(&mut self, comps: &[&str]) -> Result<Item> {
        let mut cur = self.root_item();
        for comp in comps {
            if !cur.is_dir {
                return Err(Error::NotADirectory);
            }
            cur = self.lookup(cur.record, comp)?.ok_or(Error::NotFound)?;
            if cur.name == "." || (cur.record < 24 && cur.name.starts_with('$')) {
                return Err(Error::NotFound);
            }
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
        self.w.is_none()
    }

    fn read_only_reason(&self) -> Option<String> {
        if self.w.is_some() {
            None
        } else {
            self.ro_reason.clone()
        }
    }

    fn total_bytes(&self) -> u64 {
        self.total_clusters * self.cluster_size
    }

    fn free_bytes(&mut self) -> Result<u64> {
        if self.w.is_some() {
            return Ok(self.available()? * self.cluster_size);
        }
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
        (1u64 << 44) - (1 << 16)
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

    fn raw_disk(&mut self) -> Option<&mut (dyn Disk + 'static)> {
        Some(&mut *self.disk)
    }

    /// The clusters of a plain file (not resident, compressed, encrypted or
    /// sparse), in order: what a container stored on NTFS needs.
    fn extents(&mut self, path: &str) -> Result<Vec<(u64, u64)>> {
        let (mut runs, size, init, flags) = match self.data_of(path)? {
            Stream::Resident(_) => return Err(Error::unsupported("a small NTFS file kept inside its record")),
            Stream::NonResident { runs, size, init, flags } => (runs, size, init, flags),
        };
        if flags & (FLAG_COMPRESSED | FLAG_ENCRYPTED) != 0 {
            return Err(Error::unsupported("compressed or EFS-encrypted NTFS files"));
        }
        if init < size {
            return Err(Error::unsupported("an NTFS file whose end was never written"));
        }
        runs.sort_by_key(|r| r.vcn);
        let cs = self.cluster_size;
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut left = size;
        let mut vcn = 0;
        for r in runs {
            if left == 0 {
                break;
            }
            if r.vcn != vcn {
                return Err(Error::corrupt("NTFS runs with a gap"));
            }
            let lcn = r.lcn.ok_or_else(|| Error::unsupported("sparse NTFS files"))?;
            let off = lcn * cs;
            let n = (r.len * cs).min(left);
            match out.last_mut() {
                Some((o, l)) if *o + *l == off => *l += n,
                _ => out.push((off, n)),
            }
            left -= n;
            vcn += r.len;
        }
        if left != 0 {
            return Err(Error::corrupt("NTFS runs shorter than the file"));
        }
        Ok(out)
    }

    fn write_file(&mut self, path: &str, src: &mut dyn Read, size: u64, overwrite: bool, progress: Progress) -> Result<()> {
        self.w_write_file(path, src, size, overwrite, progress)
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        self.w_mkdir(path)
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        self.w_remove(path)
    }

    fn rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        self.w_rename(path, new_name)
    }

    fn move_item(&mut self, path: &str, dest_dir: &str) -> Result<()> {
        self.w_move(path, dest_dir)
    }

    fn flush(&mut self) -> Result<()> {
        self.w_flush()
    }

    fn reserve(&mut self, start: u64, end: u64) {
        self.w_reserve(start, end)
    }

    fn check(&mut self, repair: bool) -> Result<CheckReport> {
        if repair {
            return Err(Error::unsupported("repairing NTFS here (run chkdsk on Windows)"));
        }
        self.w_check()
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
