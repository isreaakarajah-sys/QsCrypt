//! Writing NTFS: our own implementation.
//!
//! What it does: creates, overwrites, renames, moves and deletes files and
//! folders on NTFS 3.1 volumes, the way Windows lays them out (POSIX-namespace
//! names as Windows itself uses when short names are off, B-tree directory
//! indexes ordered by the volume's own $UpCase table, MFT records with
//! update-sequence fixups mirrored in $MFTMirr).
//!
//! When it refuses: the volume was not closed cleanly by Windows (journal in
//! use, fast startup, hibernation), is marked for checking, is older than
//! NTFS 3.1, or has an unusual layout. It then opens read-only and says why.
//!
//! Safety model, as the Linux drivers do it:
//! - Before the first change $LogFile is emptied (all 0xFF), so Windows starts
//!   a fresh journal instead of replaying a stale one over our changes.
//! - From the first change until `flush`, the volume carries the dirty flag:
//!   if the phone or the cable goes away in between, Windows checks the
//!   volume on its next mount.
//! - Every operation writes its records, indexes and bitmaps before it
//!   returns; `flush` only clears the dirty flag.
//!
//! New files get a 48-byte $STANDARD_INFORMATION and their own security
//! descriptor granting everyone full access (as ntfs-3g does), so they open
//! on any Windows PC without touching $Secure.

use super::*;
use crate::util::{put_le32, put_le64, wipe};
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::cmp::Reverse;

/// Bytes of $Bitmap per cached chunk, and how many chunks stay cached.
const BM_CHUNK: u64 = 64 * 1024;
const BM_CACHE: usize = 64;
/// Records below this number belong to the file system.
const FIRST_USER_RECORD: u64 = 24;

const VOLUME_IS_DIRTY: u16 = 0x0001;
const RESTART_VOLUME_IS_CLEAN: u16 = 0x0002;
const LOGFILE_NO_CLIENT: u16 = 0xFFFF;

const FA_ARCHIVE: u32 = 0x20;

const REC_IN_USE: u16 = 0x0001;
const REC_DIRECTORY: u16 = 0x0002;

const I30_NAME: [u16; 4] = I30;
const O_NAME: [u16; 2] = [b'$' as u16, b'O' as u16];

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf)?;
    Ok(())
}

/// Windows FILETIME now (100 ns since 1601).
fn now_filetime() -> u64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() + 11_644_473_600) * 10_000_000 + (d.subsec_nanos() / 100) as u64
}

// ------------------------------------------------------------------ disk I/O

/// The run holding `vcn`, by binary search (runs are in VCN order).
fn run_at(runs: &[Run], vcn: u64) -> Option<&Run> {
    let i = runs.partition_point(|r| r.vcn + r.len <= vcn);
    runs.get(i).filter(|r| vcn >= r.vcn && vcn < r.vcn + r.len)
}

fn runs_io(disk: &mut dyn Disk, cs: u64, runs: &[Run], offset: u64, len: usize, mut f: impl FnMut(&mut dyn Disk, u64, usize, usize) -> Result<()>) -> Result<()> {
    let end = offset + len as u64;
    let mut pos = offset;
    while pos < end {
        let vcn = pos / cs;
        let run = run_at(runs, vcn).ok_or_else(|| Error::corrupt("NTFS stream shorter than expected"))?;
        let lcn = run.lcn.ok_or_else(|| Error::corrupt("sparse run in an NTFS system stream"))?;
        let run_end = (run.vcn + run.len) * cs;
        let n = (run_end.min(end) - pos) as usize;
        let phys = (lcn + (vcn - run.vcn)) * cs + pos % cs;
        f(disk, phys, (pos - offset) as usize, n)?;
        pos += n as u64;
    }
    Ok(())
}

fn runs_read(disk: &mut dyn Disk, cs: u64, runs: &[Run], offset: u64, buf: &mut [u8]) -> Result<()> {
    let len = buf.len();
    runs_io(disk, cs, runs, offset, len, |d, phys, at, n| d.read_at(phys, &mut buf[at..at + n]))
}

fn runs_write(disk: &mut dyn Disk, cs: u64, runs: &[Run], offset: u64, buf: &[u8]) -> Result<()> {
    runs_io(disk, cs, runs, offset, buf.len(), |d, phys, at, n| d.write_at(phys, &buf[at..at + n]))
}

/// Stamps the update sequence into a record or index block before writing:
/// a new sequence number at the end of every 512-byte stride, the original
/// bytes saved in the array.
fn protect(buf: &mut [u8]) {
    let usa_off = le16(buf, 4) as usize;
    let usa_count = le16(buf, 6) as usize;
    let mut usn = le16(buf, usa_off).wrapping_add(1);
    if usn == 0 || usn == 0xFFFF {
        usn = 1;
    }
    put_le16(buf, usa_off, usn);
    for i in 1..usa_count {
        let pos = i * 512 - 2;
        if pos + 2 > buf.len() {
            break;
        }
        let (a, b) = (buf[pos], buf[pos + 1]);
        buf[usa_off + 2 * i] = a;
        buf[usa_off + 2 * i + 1] = b;
        put_le16(buf, pos, usn);
    }
}

// --------------------------------------------------------------- attributes

/// Minimal little-endian width of a signed value (1..=8 bytes).
fn signed_width(v: i64) -> usize {
    for n in 1..8 {
        let shift = 64 - 8 * n as u32;
        if (v << shift) >> shift == v {
            return n;
        }
    }
    8
}

/// Mapping pairs for runs given as (lcn, clusters), in VCN order.
fn encode_runs(runs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = 0i64;
    for &(lcn, len) in runs {
        let delta = lcn as i64 - prev;
        let (lw, ow) = (signed_width(len as i64), signed_width(delta));
        out.push((ow << 4 | lw) as u8);
        out.extend_from_slice(&len.to_le_bytes()[..lw]);
        out.extend_from_slice(&delta.to_le_bytes()[..ow]);
        prev = lcn as i64;
    }
    out.push(0);
    out
}

fn pairs(runs: &[Run]) -> Vec<(u64, u64)> {
    runs.iter().filter_map(|r| r.lcn.map(|l| (l, r.len))).collect()
}

/// Appends (lcn, len) to a VCN-ordered run list, merging when contiguous.
fn push_run(runs: &mut Vec<Run>, lcn: u64, len: u64) {
    let vcn = runs.last().map_or(0, |r| r.vcn + r.len);
    if let Some(last) = runs.last_mut() {
        if last.lcn.is_some_and(|l| l + last.len == lcn) {
            last.len += len;
            return;
        }
    }
    runs.push(Run { vcn, lcn: Some(lcn), len });
}

fn resident_len(name_units: usize, value_len: usize) -> usize {
    align8(align8(0x18 + 2 * name_units) + value_len)
}

fn resident(ty: u32, name: &[u16], value: &[u8], indexed: bool) -> Vec<u8> {
    let value_off = align8(0x18 + 2 * name.len());
    let len = align8(value_off + value.len());
    let mut a = vec![0u8; len];
    put_le32(&mut a, 0, ty);
    put_le32(&mut a, 4, len as u32);
    a[9] = name.len() as u8;
    put_le16(&mut a, 10, 0x18);
    put_le32(&mut a, 16, value.len() as u32);
    put_le16(&mut a, 20, value_off as u16);
    a[22] = indexed as u8;
    for (i, u) in name.iter().enumerate() {
        put_le16(&mut a, 0x18 + 2 * i, *u);
    }
    a[value_off..value_off + value.len()].copy_from_slice(value);
    a
}

fn nonresident_len(name_units: usize, runs: &[(u64, u64)]) -> usize {
    align8(align8(0x40 + 2 * name_units) + encode_runs(runs).len())
}

fn nonresident(ty: u32, name: &[u16], runs: &[(u64, u64)], alloc: u64, size: u64, init: u64) -> Vec<u8> {
    let mp_off = align8(0x40 + 2 * name.len());
    let mp = encode_runs(runs);
    let len = align8(mp_off + mp.len());
    let clusters: u64 = runs.iter().map(|r| r.1).sum();
    let mut a = vec![0u8; len];
    put_le32(&mut a, 0, ty);
    put_le32(&mut a, 4, len as u32);
    a[8] = 1;
    a[9] = name.len() as u8;
    put_le16(&mut a, 10, 0x40);
    put_le64(&mut a, 0x10, 0);
    put_le64(&mut a, 0x18, clusters.wrapping_sub(1));
    put_le16(&mut a, 0x20, mp_off as u16);
    put_le64(&mut a, 0x28, alloc);
    put_le64(&mut a, 0x30, size);
    put_le64(&mut a, 0x38, init);
    for (i, u) in name.iter().enumerate() {
        put_le16(&mut a, 0x40 + 2 * i, *u);
    }
    a[mp_off..mp_off + mp.len()].copy_from_slice(&mp);
    a
}

/// $STANDARD_INFORMATION in its NTFS 1.2 form (48 bytes): the security
/// descriptor then lives in the record itself.
fn si_value(t: u64, fa: u32) -> Vec<u8> {
    let mut v = vec![0u8; 48];
    for i in 0..4 {
        put_le64(&mut v, 8 * i, t);
    }
    put_le32(&mut v, 32, fa);
    v
}

#[allow(clippy::too_many_arguments)]
fn fn_value(parent: u64, times: [u64; 4], alloc: u64, size: u64, fa: u32, name: &[u16], ns: u8) -> Vec<u8> {
    let mut v = vec![0u8; 66 + 2 * name.len()];
    put_le64(&mut v, 0, parent);
    for (i, t) in times.iter().enumerate() {
        put_le64(&mut v, 8 + 8 * i, *t);
    }
    put_le64(&mut v, 40, alloc);
    put_le64(&mut v, 48, size);
    put_le32(&mut v, 56, fa);
    v[64] = name.len() as u8;
    v[65] = ns;
    for (i, u) in name.iter().enumerate() {
        put_le16(&mut v, 66 + 2 * i, *u);
    }
    v
}

/// Self-relative security descriptor: owner and group Administrators, one
/// ACE giving Everyone full control, inherited by files and folders below.
fn sd_everyone() -> Vec<u8> {
    let admins = |v: &mut Vec<u8>| v.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0]);
    let mut v = vec![1, 0, 0x04, 0x80];
    v.extend_from_slice(&20u32.to_le_bytes()); // owner
    v.extend_from_slice(&36u32.to_le_bytes()); // group
    v.extend_from_slice(&0u32.to_le_bytes()); // no SACL
    v.extend_from_slice(&52u32.to_le_bytes()); // DACL
    admins(&mut v);
    admins(&mut v);
    v.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]); // ACL: revision 2, size 28, one ACE
    v.extend_from_slice(&[0, 0x03, 20, 0]); // ACCESS_ALLOWED, object + container inherit
    v.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
    v.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // S-1-1-0 (Everyone)
    v
}

/// An $I30 entry for `key` (a $FILE_NAME value) pointing at `file_ref`.
fn i30_entry(file_ref: u64, key: &[u8]) -> Ent {
    let mut bytes = vec![0u8; align8(16 + key.len())];
    put_le64(&mut bytes, 0, file_ref);
    put_le16(&mut bytes, 10, key.len() as u16);
    bytes[16..16 + key.len()].copy_from_slice(key);
    Ent { bytes, child: None, end: false }
}

// ------------------------------------------------------------------ records

/// An MFT record with its fixups undone, edited in memory.
struct Rec {
    n: u64,
    b: Vec<u8>,
}

impl Rec {
    fn fresh(n: u64, size: usize, seq: u16, flags: u16) -> Rec {
        let mut b = vec![0u8; size];
        b[..4].copy_from_slice(b"FILE");
        let usa_count = size / 512 + 1;
        let attrs = align8(0x30 + 2 * usa_count);
        put_le16(&mut b, 4, 0x30);
        put_le16(&mut b, 6, usa_count as u16);
        put_le16(&mut b, 16, seq);
        put_le16(&mut b, 20, attrs as u16);
        put_le16(&mut b, 22, flags);
        put_le32(&mut b, 24, (attrs + 8) as u32);
        put_le32(&mut b, 28, size as u32);
        put_le32(&mut b, 44, n as u32);
        put_le32(&mut b, attrs, AT_END);
        Rec { n, b }
    }

    fn seq(&self) -> u16 {
        le16(&self.b, 16)
    }

    fn links(&self) -> u16 {
        le16(&self.b, 18)
    }

    fn flags(&self) -> u16 {
        le16(&self.b, 22)
    }

    fn used(&self) -> usize {
        le32(&self.b, 24) as usize
    }

    fn free(&self) -> usize {
        self.b.len().saturating_sub(self.used())
    }

    /// (offset, length) of every attribute, in order.
    fn attrs(&self) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        let used = self.used().min(self.b.len());
        let mut off = le16(&self.b, 20) as usize;
        while off + 8 <= used {
            if le32(&self.b, off) == AT_END {
                break;
            }
            let len = le32(&self.b, off + 4) as usize;
            if len < 16 || off + len > used {
                break;
            }
            v.push((off, len));
            off += len;
        }
        v
    }

    fn end_offset(&self) -> usize {
        self.attrs().last().map_or(le16(&self.b, 20) as usize, |(o, l)| o + l)
    }

    fn ty(&self, off: usize) -> u32 {
        le32(&self.b, off)
    }

    fn name(&self, off: usize) -> Vec<u16> {
        let n = self.b[off + 9] as usize;
        let no = off + le16(&self.b, off + 10) as usize;
        (0..n).map(|i| le16(&self.b, no + 2 * i)).collect()
    }

    fn resident(&self, off: usize) -> bool {
        self.b[off + 8] == 0
    }

    fn value(&self, off: usize) -> &[u8] {
        let vl = le32(&self.b, off + 16) as usize;
        let vo = off + le16(&self.b, off + 20) as usize;
        &self.b[vo..(vo + vl).min(self.b.len())]
    }

    fn find(&self, ty: u32, name: &[u16]) -> Option<usize> {
        self.attrs().into_iter().map(|(o, _)| o).find(|&o| self.ty(o) == ty && self.name(o) == name)
    }

    fn all(&self, ty: u32) -> Vec<usize> {
        self.attrs().into_iter().map(|(o, _)| o).filter(|&o| self.ty(o) == ty).collect()
    }

    /// Runs of the non-resident attribute at `off`.
    fn runs(&self, off: usize) -> Result<Vec<Run>> {
        let len = le32(&self.b, off + 4) as usize;
        let mp = le16(&self.b, off + 0x20) as usize;
        if mp > len {
            return Err(Error::corrupt("bad NTFS run list offset"));
        }
        decode_runs(&self.b[off + mp..off + len], le64(&self.b, off + 0x10))
    }

    fn remove(&mut self, off: usize) {
        let len = le32(&self.b, off + 4) as usize;
        let used = self.used();
        self.b.copy_within(off + len..used, off);
        self.b[used - len..used].fill(0);
        put_le32(&mut self.b, 24, (used - len) as u32);
    }

    /// Inserts an attribute in type order. `instance`: keep a number (when
    /// replacing an attribute) or take the next free one.
    fn insert(&mut self, mut attr: Vec<u8>, instance: Option<u16>) -> Result<()> {
        if attr.len() > self.free() {
            return Err(Error::NoSpace);
        }
        let inst = match instance {
            Some(i) => i,
            None => {
                let i = le16(&self.b, 40);
                put_le16(&mut self.b, 40, i.wrapping_add(1));
                i
            }
        };
        put_le16(&mut attr, 14, inst);
        let ty = le32(&attr, 0);
        let name: Vec<u16> = (0..attr[9] as usize).map(|i| le16(&attr, le16(&attr, 10) as usize + 2 * i)).collect();
        let pos = self
            .attrs()
            .into_iter()
            .map(|(o, _)| o)
            .find(|&o| self.ty(o) > ty || (self.ty(o) == ty && self.name(o) > name))
            .unwrap_or_else(|| self.end_offset());
        let used = self.used();
        self.b.copy_within(pos..used, pos + attr.len());
        self.b[pos..pos + attr.len()].copy_from_slice(&attr);
        put_le32(&mut self.b, 24, (used + attr.len()) as u32);
        Ok(())
    }

    /// Replaces the attribute at `off`, keeping its instance number.
    fn replace(&mut self, off: usize, attr: Vec<u8>) -> Result<()> {
        let inst = le16(&self.b, off + 14);
        let old_len = le32(&self.b, off + 4) as usize;
        if attr.len() > self.free() + old_len {
            return Err(Error::NoSpace);
        }
        self.remove(off);
        self.insert(attr, Some(inst))
    }
}

/// One entry of an $ATTRIBUTE_LIST: where an attribute of an item lives.
#[derive(Clone, Debug)]
struct ListEnt {
    ty: u32,
    name: Vec<u16>,
    vcn: u64,
    file_ref: u64,
    inst: u16,
}

impl ListEnt {
    fn record(&self) -> u64 {
        self.file_ref & REF_MASK
    }
}

fn parse_list(bytes: &[u8]) -> Vec<ListEnt> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 26 <= bytes.len() {
        let len = le16(bytes, p + 4) as usize;
        if len < 26 || p + len > bytes.len() {
            break;
        }
        let nl = bytes[p + 6] as usize;
        let no = bytes[p + 7] as usize;
        let name = (0..nl).filter(|i| p + no + 2 * i + 2 <= p + len).map(|i| le16(bytes, p + no + 2 * i)).collect();
        out.push(ListEnt { ty: le32(bytes, p), name, vcn: le64(bytes, p + 8), file_ref: le64(bytes, p + 16), inst: le16(bytes, p + 24) });
        p += len;
    }
    out
}

fn list_bytes(ents: &[ListEnt]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in ents {
        let len = align8(0x1A + 2 * e.name.len());
        let at = out.len();
        out.resize(at + len, 0);
        put_le32(&mut out, at, e.ty);
        put_le16(&mut out, at + 4, len as u16);
        out[at + 6] = e.name.len() as u8;
        out[at + 7] = 0x1A;
        put_le64(&mut out, at + 8, e.vcn);
        put_le64(&mut out, at + 16, e.file_ref);
        put_le16(&mut out, at + 24, e.inst);
        for (i, u) in e.name.iter().enumerate() {
            put_le16(&mut out, at + 0x1A + 2 * i, *u);
        }
    }
    out
}

// -------------------------------------------------------------------- state

enum MftBitmapAt {
    Resident,
    NonResident { runs: Vec<Run>, alloc: u64 },
}

struct Chunk {
    data: Vec<u8>,
    /// Changed 512-byte sectors of the chunk.
    dirty: u128,
}

pub(super) struct State {
    mirror: Vec<Run>,
    mirror_records: u64,
    bm_runs: Vec<Run>,
    bm_size: u64,
    chunks: HashMap<u64, Chunk>,
    free: u64,
    hint: u64,
    mftbm: Vec<u8>,
    mftbm_at: MftBitmapAt,
    /// Changed 512-byte sectors of the MFT bitmap.
    mftbm_dirty: BTreeSet<usize>,
    rec_hint: u64,
    reserved: Option<(u64, u64)>,
    reserved_free: u64,
    dirty_on_disk: bool,
    log_emptied: bool,
    /// An operation failed half-way: the dirty flag must stay for chkdsk.
    damaged: bool,
}

/// What a $LogFile restart page says: None when blank (all 0xFF), otherwise
/// (current LSN, clean).
fn restart_page(b: &[u8]) -> std::result::Result<Option<(u64, bool)>, ()> {
    if b.iter().all(|&x| x == 0xFF) {
        return Ok(None);
    }
    if b.len() < 512 || &b[..4] != b"RSTR" {
        return Err(());
    }
    let ra = le16(b, 0x18) as usize;
    if ra + 0x10 > 510 {
        return Err(());
    }
    let in_use = le16(b, ra + 0x0C);
    let flags = le16(b, ra + 0x0E);
    Ok(Some((le64(b, ra), flags & RESTART_VOLUME_IS_CLEAN != 0 || in_use == LOGFILE_NO_CLIENT)))
}

impl State {
    pub(super) fn open(fs: &mut Ntfs) -> std::result::Result<State, String> {
        let unreadable = |what: &str, e: Error| format!("{what} could not be read ({e})");
        if fs.upcase.len() != 65_536 {
            return Err("its case table ($UpCase) could not be read".into());
        }
        if !matches!(fs.record_size, 1024 | 2048 | 4096) || !fs.index_block_size.is_power_of_two() || !(512..=65_536).contains(&fs.index_block_size) {
            return Err("its layout is unusual (record or index size)".into());
        }
        let r0 = fs.record_buf(0).map_err(|e| unreadable("$MFT", e))?;
        if le16(&r0, 4) != 0x30 {
            return Err("its records use an old layout".into());
        }

        // $Volume: version and flags.
        let vol = fs.record_buf(MFT_RECORD_VOLUME).map_err(|e| unreadable("$Volume", e))?;
        let vr = Rec { n: MFT_RECORD_VOLUME, b: vol };
        let vi = vr.find(AT_VOLUME_INFORMATION, &[]).filter(|&o| vr.resident(o) && vr.value(o).len() >= 12).ok_or("its $Volume has no version information")?;
        let v = vr.value(vi);
        let (major, minor, flags) = (v[8], v[9], le16(v, 10));
        if major != 3 || minor < 1 {
            return Err(format!("NTFS {major}.{minor} is older than what QsCrypt writes (3.1)"));
        }
        if flags & VOLUME_IS_DIRTY != 0 {
            return Err("Windows marked this drive for checking: run “Scan and fix” (chkdsk) on Windows first".into());
        }

        // $LogFile: must be clean or blank.
        let log = fs.stream(MFT_RECORD_LOGFILE, AT_DATA, &[]).map_err(|e| unreadable("$LogFile", e))?;
        if log.size() < 8192 {
            return Err("its journal ($LogFile) is too small".into());
        }
        let mut p0 = vec![0u8; 4096];
        fs.read_stream(&log, 0, &mut p0).map_err(|e| unreadable("$LogFile", e))?;
        let page = if &p0[..4] == b"RSTR" { (le32(&p0, 0x10) as u64).clamp(512, 65_536) } else { 4096 };
        let mut p1 = vec![0u8; 4096];
        if page + 4096 <= log.size() {
            fs.read_stream(&log, page, &mut p1).map_err(|e| unreadable("$LogFile", e))?;
        } else {
            p1.fill(0xFF);
        }
        let pages = [restart_page(&p0), restart_page(&p1)];
        let valid: Vec<(u64, bool)> = pages.iter().filter_map(|p| p.ok().flatten()).collect();
        let clean = match valid.iter().max_by_key(|p| p.0) {
            Some(&(_, clean)) => clean,
            None => pages.iter().all(|p| matches!(p, Ok(None))),
        };
        if !clean {
            return Err("Windows did not close this drive (fast startup, hibernation or removal without “Eject”): shut Windows down fully or eject the drive there, then try again".into());
        }
        // Hibernated Windows on this volume.
        if let Ok(Some(h)) = fs.lookup(ROOT, "hiberfil.sys") {
            if !h.is_dir {
                if let Ok(s) = fs.stream(h.record, AT_DATA, &[]) {
                    let mut sig = [0u8; 4];
                    if s.size() >= 4 && fs.read_stream(&s, 0, &mut sig).is_ok() && sig.eq_ignore_ascii_case(b"hibr") {
                        return Err("Windows is hibernated on this drive: start Windows and shut it down fully first".into());
                    }
                }
            }
        }

        // $MFTMirr.
        let rs = fs.record_size as u64;
        let (mirror, mirror_records) = match fs.stream(MFT_RECORD_MIRROR, AT_DATA, &[]) {
            Ok(Stream::NonResident { runs, size, .. }) if size >= rs => (runs, (size / rs).min(fs.mft_size / rs)),
            _ => return Err("its $MFTMirr is unusable".into()),
        };

        // $Bitmap.
        let (bm_runs, bm_size) = match fs.stream(MFT_RECORD_BITMAP, AT_DATA, &[]) {
            Ok(Stream::NonResident { runs, size, init, flags }) if init >= size && flags & (FLAG_COMPRESSED | FLAG_ENCRYPTED) == 0 => (runs, size),
            _ => return Err("its cluster bitmap is unusable".into()),
        };
        if bm_size * 8 < fs.total_clusters {
            return Err("its cluster bitmap is too short".into());
        }

        // The $MFT's own bitmap.
        let r0 = Rec { n: 0, b: r0 };
        let bo = r0.find(AT_BITMAP, &[]).ok_or("$MFT has no bitmap")?;
        let (mftbm, mftbm_at) = if r0.resident(bo) {
            (r0.value(bo).to_vec(), MftBitmapAt::Resident)
        } else {
            let runs = r0.runs(bo).map_err(|e| unreadable("$MFT bitmap", e))?;
            let size = le64(&r0.b, bo + 0x30);
            let alloc = le64(&r0.b, bo + 0x28);
            let mut v = vec![0u8; size as usize];
            runs_read(fs.disk.as_mut(), fs.cluster_size, &runs, 0, &mut v).map_err(|e| unreadable("$MFT bitmap", e))?;
            (v, MftBitmapAt::NonResident { runs, alloc })
        };

        // Free clusters.
        let total = fs.total_clusters;
        let mut used = 0u64;
        let mut buf = vec![0u8; IO_CHUNK];
        let need = total.div_ceil(8);
        let mut pos = 0u64;
        while pos < need {
            let n = ((need - pos) as usize).min(buf.len());
            runs_read(fs.disk.as_mut(), fs.cluster_size, &bm_runs, pos, &mut buf[..n]).map_err(|e| unreadable("$Bitmap", e))?;
            for (i, &b) in buf[..n].iter().enumerate() {
                let base = (pos + i as u64) * 8;
                let valid = total.saturating_sub(base).min(8) as u32;
                let mask = if valid >= 8 { 0xFF } else { ((1u16 << valid) - 1) as u8 };
                used += (b & mask).count_ones() as u64;
            }
            pos += n as u64;
        }

        // File data starts past the zone kept for the MFT to grow into.
        let mft_end = fs.mft.iter().filter_map(|r| r.lcn.map(|l| l + r.len)).max().unwrap_or(0);
        let zone = (total / 16).min((200 << 20) / fs.cluster_size);
        let hint = if mft_end + zone < total { mft_end + zone } else { 0 };

        Ok(State {
            mirror,
            mirror_records,
            bm_runs,
            bm_size,
            chunks: HashMap::new(),
            free: total - used.min(total),
            hint,
            mftbm,
            mftbm_at,
            mftbm_dirty: BTreeSet::new(),
            rec_hint: FIRST_USER_RECORD,
            reserved: None,
            reserved_free: 0,
            dirty_on_disk: false,
            log_emptied: false,
            damaged: false,
        })
    }

    fn chunk(&mut self, disk: &mut dyn Disk, cs: u64, idx: u64) -> Result<&mut Chunk> {
        if !self.chunks.contains_key(&idx) {
            if self.chunks.len() >= BM_CACHE {
                let victim = self.chunks.iter().find(|(_, c)| c.dirty == 0).map(|(k, _)| *k);
                match victim {
                    Some(k) => {
                        self.chunks.remove(&k);
                    }
                    None => self.flush_chunks(disk, cs)?,
                }
            }
            let off = idx * BM_CHUNK;
            let n = BM_CHUNK.min(self.bm_size - off) as usize;
            let mut data = vec![0u8; n];
            runs_read(disk, cs, &self.bm_runs, off, &mut data)?;
            self.chunks.insert(idx, Chunk { data, dirty: 0 });
        }
        Ok(self.chunks.get_mut(&idx).unwrap())
    }

    fn byte(&mut self, disk: &mut dyn Disk, cs: u64, i: u64) -> Result<u8> {
        let c = self.chunk(disk, cs, i / BM_CHUNK)?;
        Ok(c.data[(i % BM_CHUNK) as usize])
    }

    fn used(&mut self, disk: &mut dyn Disk, cs: u64, c: u64) -> Result<bool> {
        Ok(self.byte(disk, cs, c / 8)? & (1 << (c % 8)) != 0)
    }

    fn in_reserved(&self, c: u64) -> bool {
        self.reserved.is_some_and(|(lo, hi)| c >= lo && c < hi)
    }

    fn blocked(&mut self, disk: &mut dyn Disk, cs: u64, c: u64) -> Result<bool> {
        Ok(self.in_reserved(c) || self.used(disk, cs, c)?)
    }

    fn set_range(&mut self, disk: &mut dyn Disk, cs: u64, start: u64, len: u64, used: bool) -> Result<()> {
        let mut c = start;
        while c < start + len {
            let i = c / 8;
            let ch = self.chunk(disk, cs, i / BM_CHUNK)?;
            ch.dirty |= 1u128 << ((i % BM_CHUNK) / 512);
            let b = &mut ch.data[(i % BM_CHUNK) as usize];
            if c % 8 == 0 && c + 8 <= start + len {
                *b = if used { 0xFF } else { 0 };
                c += 8;
            } else {
                if used {
                    *b |= 1 << (c % 8);
                } else {
                    *b &= !(1 << (c % 8));
                }
                c += 1;
            }
        }
        Ok(())
    }

    /// Writes the changed sectors of cached bitmap chunks, runs of adjacent
    /// sectors at once.
    fn flush_chunks(&mut self, disk: &mut dyn Disk, cs: u64) -> Result<()> {
        let mut keys: Vec<u64> = self.chunks.iter().filter(|(_, c)| c.dirty != 0).map(|(k, _)| *k).collect();
        keys.sort_unstable();
        for k in keys {
            let c = self.chunks.get_mut(&k).unwrap();
            let mut s = 0usize;
            while s < 128 {
                if c.dirty & (1u128 << s) == 0 {
                    s += 1;
                    continue;
                }
                let first = s;
                while s < 128 && c.dirty & (1u128 << s) != 0 {
                    s += 1;
                }
                let (a, b) = (first * 512, (s * 512).min(c.data.len()));
                if a < b {
                    runs_write(disk, cs, &self.bm_runs, k * BM_CHUNK + a as u64, &c.data[a..b])?;
                }
            }
            c.dirty = 0;
        }
        Ok(())
    }

    fn rec_used(&self, n: u64) -> bool {
        self.mftbm.get((n / 8) as usize).is_some_and(|b| b & (1 << (n % 8)) != 0)
    }

    fn set_rec(&mut self, n: u64, used: bool) {
        if let Some(b) = self.mftbm.get_mut((n / 8) as usize) {
            if used {
                *b |= 1 << (n % 8);
            } else {
                *b &= !(1 << (n % 8));
            }
            self.mftbm_dirty.insert((n / 8) as usize / 512);
        }
    }
}

// ------------------------------------------------------------------ indexes

struct Node {
    ents: Vec<Ent>,
    usn: u16,
    lsn: u64,
}

/// A directory ($I30) or view ($O) index being changed.
struct Ix {
    rec: u64,
    name: Vec<u16>,
    coll: u32,
    ibs: u64,
    unit: u64,
    head: Vec<u8>,
    root: Vec<Ent>,
    runs: Vec<Run>,
    bytes: u64,
    bitmap: Vec<u8>,
    /// Record bytes besides the index's own three attributes.
    base_used: usize,
    nodes: HashMap<u64, Node>,
    usns: HashMap<u64, u16>,
    dirty: BTreeSet<u64>,
    meta: bool,
    /// Clusters taken for new index blocks since the last commit: given back
    /// when a change is abandoned before it is written.
    grown: Vec<(u64, u64)>,
    /// The owner has an attribute list; its allocation and bitmap may then
    /// live in extension records (these, when so).
    listed: bool,
    alloc_rec: Option<u64>,
    bitmap_rec: Option<u64>,
}

impl Ix {
    fn ents(&self, id: Option<u64>) -> &Vec<Ent> {
        match id {
            None => &self.root,
            Some(v) => &self.nodes[&v].ents,
        }
    }

    fn ents_mut(&mut self, id: Option<u64>) -> &mut Vec<Ent> {
        match id {
            None => {
                self.meta = true;
                &mut self.root
            }
            Some(v) => {
                self.dirty.insert(v);
                &mut self.nodes.get_mut(&v).unwrap().ents
            }
        }
    }

    fn blocks(&self) -> u64 {
        self.bytes / self.ibs
    }

    fn block_used(&self, k: u64) -> bool {
        self.bitmap.get((k / 8) as usize).is_some_and(|b| b & (1 << (k % 8)) != 0)
    }

    fn set_block(&mut self, k: u64, used: bool) {
        let i = (k / 8) as usize;
        if used {
            self.bitmap[i] |= 1 << (k % 8);
        } else {
            self.bitmap[i] &= !(1 << (k % 8));
        }
        self.meta = true;
    }

    /// Room for entries in an index block.
    fn block_cap(&self) -> usize {
        let ibs = self.ibs as usize;
        ibs - 0x18 - align8(16 + 2 * (ibs / 512 + 1))
    }

    fn root_attr_len(&self, entries: usize) -> usize {
        align8(0x18 + 2 * self.name.len()) + 32 + entries
    }

    /// Bytes the allocation and bitmap take in the owner's base record.
    fn alloc_attr_len(&self) -> usize {
        if self.bytes == 0 {
            return 0;
        }
        let a = if self.alloc_rec.is_none() { nonresident_len(self.name.len(), &pairs(&self.runs)) } else { 0 };
        let b = if self.bitmap_rec.is_none() { resident_len(self.name.len(), self.bitmap.len()) } else { 0 };
        a + b
    }

    fn new_node(&mut self, vcn: u64, ents: Vec<Ent>) {
        let usn = self.usns.get(&vcn).copied().unwrap_or(0);
        self.nodes.insert(vcn, Node { ents, usn, lsn: 0 });
        self.dirty.insert(vcn);
    }
}

/// Splits an overflowing node around a middle entry by bytes:
/// (left with its end entry, middle, right with the original end entry).
fn split_node(mut ents: Vec<Ent>) -> Result<(Vec<Ent>, Ent, Vec<Ent>)> {
    let end = ents.pop().ok_or_else(|| Error::corrupt("empty NTFS index node"))?;
    if ents.len() < 3 {
        return Err(Error::corrupt("NTFS index entries larger than a block"));
    }
    let total: usize = entries_size(&ents);
    let mut acc = 0;
    let mut m = ents.len() / 2;
    for (i, e) in ents.iter().enumerate() {
        if acc + e.size() > total / 2 {
            m = i;
            break;
        }
        acc += e.size();
    }
    let m = m.clamp(1, ents.len() - 2);
    let mut right = ents.split_off(m + 1);
    let mid = ents.pop().unwrap();
    ents.push(Ent::end(mid.child));
    right.push(end);
    Ok((ents, mid.with_child(None), right))
}

/// Leaves for a rebuilt index: (nodes with end entries, separators between).
fn pack_leaves(all: Vec<Ent>, target: usize) -> (Vec<Vec<Ent>>, Vec<Ent>) {
    let mut nodes: Vec<Vec<Ent>> = vec![Vec::new()];
    let mut seps = Vec::new();
    let mut size = 0;
    for e in all {
        let cur = nodes.last_mut().unwrap();
        if !cur.is_empty() && size + e.size() + 16 > target {
            seps.push(e);
            nodes.push(Vec::new());
            size = 0;
            continue;
        }
        size += e.size();
        cur.push(e);
    }
    if nodes.len() > 1 && nodes.last().unwrap().is_empty() {
        let s = seps.pop().unwrap();
        let k = nodes.len() - 2;
        let p = nodes[k].pop().unwrap();
        seps.push(p);
        nodes.last_mut().unwrap().push(s);
    }
    for n in &mut nodes {
        n.push(Ent::end(None));
    }
    (nodes, seps)
}

/// One internal level over `children` (one more than `seps`).
fn pack_internal(children: &[u64], seps: Vec<Ent>, target: usize) -> (Vec<Vec<Ent>>, Vec<Ent>) {
    let mut nodes: Vec<Vec<Ent>> = Vec::new();
    let mut ups = Vec::new();
    let mut cur: Vec<Ent> = Vec::new();
    let mut size = 0;
    let mut last = children[0];
    for (i, s) in seps.into_iter().enumerate() {
        let next = children[i + 1];
        let e = s.with_child(Some(last));
        if !cur.is_empty() && size + e.size() + 24 > target {
            cur.push(Ent::end(Some(last)));
            nodes.push(std::mem::take(&mut cur));
            size = 0;
            ups.push(e.with_child(None));
            last = next;
            continue;
        }
        size += e.size();
        cur.push(e);
        last = next;
    }
    if cur.is_empty() && !nodes.is_empty() {
        let prev = nodes.last_mut().unwrap();
        let prev_end = prev.pop().unwrap();
        let ym = prev.pop().unwrap();
        prev.push(Ent::end(ym.child));
        let s = ups.pop().unwrap();
        cur.push(s.with_child(prev_end.child));
        ups.push(ym.with_child(None));
    }
    cur.push(Ent::end(Some(last)));
    nodes.push(cur);
    (nodes, ups)
}

fn root_over(children: &[u64], seps: &[Ent]) -> Vec<Ent> {
    let mut r: Vec<Ent> = seps.iter().zip(children).map(|(s, &c)| s.clone().with_child(Some(c))).collect();
    r.push(Ent::end(children.last().copied()));
    r
}

impl Ntfs {
    fn st(&mut self) -> Result<&mut State> {
        self.w.as_deref_mut().ok_or(Error::ReadOnly)
    }

    // ------------------------------------------------------------- records

    fn read_rec(&mut self, n: u64) -> Result<Rec> {
        Ok(Rec { n, b: self.record_buf(n)? })
    }

    fn write_rec(&mut self, r: &Rec) -> Result<()> {
        let mut buf = r.b.clone();
        protect(&mut buf);
        let rs = self.record_size as u64;
        let cs = self.cluster_size;
        runs_write(self.disk.as_mut(), cs, &self.mft, r.n * rs, &buf)?;
        let st = self.w.as_deref().ok_or(Error::ReadOnly)?;
        if r.n < st.mirror_records {
            let mirror = st.mirror.clone();
            runs_write(self.disk.as_mut(), cs, &mirror, r.n * rs, &buf)?;
        }
        Ok(())
    }

    /// (looks like a record, sequence number, in use) without fixup checks.
    fn record_header(&mut self, n: u64) -> Result<(bool, u16, bool)> {
        let mut b = [0u8; 512];
        let cs = self.cluster_size;
        runs_read(self.disk.as_mut(), cs, &self.mft, n * self.record_size as u64, &mut b)?;
        let valid = &b[..4] == b"FILE";
        Ok((valid, le16(&b, 16), valid && le16(&b, 22) & REC_IN_USE != 0))
    }

    fn set_volume_dirty(&mut self, on: bool) -> Result<()> {
        let mut r = self.read_rec(MFT_RECORD_VOLUME)?;
        let o = r.find(AT_VOLUME_INFORMATION, &[]).ok_or_else(|| Error::corrupt("no $VOLUME_INFORMATION"))?;
        let vo = o + le16(&r.b, o + 20) as usize;
        let mut f = le16(&r.b, vo + 10);
        if on {
            f |= VOLUME_IS_DIRTY;
        } else {
            f &= !VOLUME_IS_DIRTY;
        }
        put_le16(&mut r.b, vo + 10, f);
        self.write_rec(&r)
    }

    fn empty_logfile(&mut self) -> Result<()> {
        let s = self.stream(MFT_RECORD_LOGFILE, AT_DATA, &[])?;
        let Stream::NonResident { runs, size, .. } = &s else {
            return Err(Error::corrupt("resident $LogFile"));
        };
        let mut head = vec![0u8; 8192.min(*size as usize)];
        self.read_stream(&s, 0, &mut head)?;
        if head.iter().all(|&b| b == 0xFF) {
            return Ok(());
        }
        let ff = vec![0xFFu8; IO_CHUNK];
        let cs = self.cluster_size;
        let mut pos = 0u64;
        while pos < *size {
            let n = ((*size - pos) as usize).min(ff.len());
            runs_write(self.disk.as_mut(), cs, runs, pos, &ff[..n])?;
            pos += n as u64;
        }
        Ok(())
    }

    /// Before the first change: blank the journal, raise the dirty flag.
    fn begin(&mut self) -> Result<()> {
        let st = self.st()?;
        if !st.log_emptied {
            self.empty_logfile()?;
            self.disk.flush()?;
            self.st()?.log_emptied = true;
        }
        if !self.st()?.dirty_on_disk {
            self.set_volume_dirty(true)?;
            self.disk.flush()?;
            self.st()?.dirty_on_disk = true;
        }
        Ok(())
    }

    /// After every operation: bitmaps to disk.
    fn finish(&mut self) -> Result<()> {
        let cs = self.cluster_size;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        st.flush_chunks(disk.as_mut(), cs)?;
        if !st.mftbm_dirty.is_empty() {
            let sectors = std::mem::take(&mut st.mftbm_dirty);
            match &st.mftbm_at {
                MftBitmapAt::NonResident { runs, .. } => {
                    for s in sectors {
                        let (a, b) = (s * 512, ((s + 1) * 512).min(st.mftbm.len()));
                        if a < b {
                            runs_write(disk.as_mut(), cs, runs, a as u64, &st.mftbm[a..b])?;
                        }
                    }
                }
                MftBitmapAt::Resident => self.write_mft_record0()?,
            }
        }
        self.disk.flush()
    }

    /// Ends an operation: a failure other than a clean refusal (nothing
    /// written, or everything undone) leaves the volume for chkdsk.
    fn after<T>(&mut self, r: Result<T>) -> Result<T> {
        let f = self.finish();
        if let Err(e) = &r {
            let clean = matches!(e, Error::Cancelled | Error::NoSpace | Error::AlreadyExists | Error::InvalidName | Error::NotFound | Error::NotADirectory | Error::IsADirectory | Error::ReadOnly | Error::Unsupported(_));
            if !clean {
                self.damage();
            }
        }
        if f.is_err() {
            self.damage();
        }
        r.and_then(|x| f.map(|_| x))
    }

    fn damage(&mut self) {
        if let Some(st) = self.w.as_deref_mut() {
            st.damaged = true;
        }
    }

    /// Everything below an item can be deleted (checked before deleting
    /// anything, so a deletion never stops half-way).
    fn check_tree(&mut self, it: &Item, depth: usize) -> Result<()> {
        if depth > 256 {
            return Err(Error::corrupt("NTFS folders nested too deep"));
        }
        let rec = self.read_rec(it.record)?;
        self.check_deletable(&rec)?;
        if rec.flags() & REC_DIRECTORY != 0 {
            let mut done = HashSet::new();
            for (file_ref, key) in self.dir_keys(it.record)? {
                let n = file_ref & REF_MASK;
                if n != it.record && done.insert(n) {
                    self.check_tree(&Self::item_of(file_ref, &key), depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn writable(&mut self) -> Result<()> {
        if self.w.is_none() {
            return Err(Error::ReadOnly);
        }
        Ok(())
    }

    // -------------------------------------------------------- allocation

    pub(super) fn available(&mut self) -> Result<u64> {
        let st = self.st()?;
        Ok(st.free.saturating_sub(st.reserved_free))
    }

    fn range_free(&mut self, start: u64, n: u64) -> Result<bool> {
        let cs = self.cluster_size;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        for c in start..start + n {
            if st.blocked(disk.as_mut(), cs, c)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// First free stretch of `n` clusters within [from, to).
    fn find_stretch(&mut self, n: u64, from: u64, to: u64) -> Result<Option<u64>> {
        let cs = self.cluster_size;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        let (mut start, mut len, mut c) = (from, 0u64, from);
        while c < to {
            if c % 8 == 0 && c + 8 <= to && !st.in_reserved(c) && !st.in_reserved(c + 7) {
                let b = st.byte(disk.as_mut(), cs, c / 8)?;
                if b == 0xFF {
                    len = 0;
                    c += 8;
                    continue;
                }
                if b == 0 {
                    if len == 0 {
                        start = c;
                    }
                    len += 8;
                    if len >= n {
                        return Ok(Some(start));
                    }
                    c += 8;
                    continue;
                }
            }
            if st.blocked(disk.as_mut(), cs, c)? {
                len = 0;
            } else {
                if len == 0 {
                    start = c;
                }
                len += 1;
                if len >= n {
                    return Ok(Some(start));
                }
            }
            c += 1;
        }
        Ok(None)
    }

    /// The longest free stretches (start, len), longest first.
    fn longest_stretches(&mut self, keep: usize) -> Result<Vec<(u64, u64)>> {
        let total = self.total_clusters;
        let cs = self.cluster_size;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        let mut heap: BinaryHeap<Reverse<(u64, u64)>> = BinaryHeap::new();
        let push = |heap: &mut BinaryHeap<Reverse<(u64, u64)>>, start: u64, len: u64| {
            if len == 0 {
                return;
            }
            heap.push(Reverse((len, start)));
            if heap.len() > keep {
                heap.pop();
            }
        };
        let (mut start, mut len) = (0u64, 0u64);
        let mut c = 0u64;
        while c < total {
            if c % 8 == 0 && c + 8 <= total && !st.in_reserved(c) && !st.in_reserved(c + 7) {
                let b = st.byte(disk.as_mut(), cs, c / 8)?;
                if b == 0xFF {
                    push(&mut heap, start, len);
                    len = 0;
                    c += 8;
                    continue;
                }
                if b == 0 {
                    if len == 0 {
                        start = c;
                    }
                    len += 8;
                    c += 8;
                    continue;
                }
            }
            if st.blocked(disk.as_mut(), cs, c)? {
                push(&mut heap, start, len);
                len = 0;
            } else {
                if len == 0 {
                    start = c;
                }
                len += 1;
            }
            c += 1;
        }
        push(&mut heap, start, len);
        let mut v: Vec<(u64, u64)> = heap.into_iter().map(|Reverse((l, s))| (s, l)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(v)
    }

    fn take(&mut self, start: u64, len: u64) -> Result<()> {
        let cs = self.cluster_size;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        st.set_range(disk.as_mut(), cs, start, len, true)?;
        st.free -= len;
        Ok(())
    }

    /// `n` clusters in as few runs as possible: at `near` when free there,
    /// else the first stretch long enough after the allocation point, else
    /// the longest stretches. Runs come back in disk order.
    fn alloc_clusters(&mut self, n: u64, near: Option<u64>, max_runs: usize) -> Result<Vec<(u64, u64)>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.available()? < n {
            return Err(Error::NoSpace);
        }
        let total = self.total_clusters;
        let mut start = None;
        if let Some(at) = near.filter(|&a| a > 0 && a + n <= total) {
            if self.range_free(at, n)? {
                start = Some(at);
            }
        }
        if start.is_none() {
            let hint = self.st()?.hint.min(total);
            start = match self.find_stretch(n, hint, total)? {
                Some(s) => Some(s),
                None => self.find_stretch(n, 1, hint.max(1))?,
            };
        }
        let runs = match start {
            Some(s) => vec![(s, n)],
            None => {
                let mut got = Vec::new();
                let mut left = n;
                for (s, l) in self.longest_stretches(max_runs.max(1) * 4)? {
                    if left == 0 {
                        break;
                    }
                    let take = l.min(left);
                    got.push((s, take));
                    left -= take;
                }
                if left > 0 || got.len() > max_runs {
                    return Err(Error::NoSpace);
                }
                got.sort_unstable();
                got
            }
        };
        for &(s, l) in &runs {
            self.take(s, l)?;
        }
        if near.is_none() {
            let last = runs.last().unwrap();
            self.st()?.hint = last.0 + last.1;
        }
        Ok(runs)
    }

    fn release(&mut self, runs: &[(u64, u64)]) -> Result<()> {
        let cs = self.cluster_size;
        let total = self.total_clusters;
        let Ntfs { w, disk, .. } = self;
        let st = w.as_deref_mut().ok_or(Error::ReadOnly)?;
        for &(s, l) in runs {
            if s + l > total {
                return Err(Error::corrupt("NTFS run beyond the volume"));
            }
            st.set_range(disk.as_mut(), cs, s, l, false)?;
            st.free += l;
            if let Some((lo, hi)) = st.reserved {
                let (a, b) = (s.max(lo), (s + l).min(hi));
                if a < b {
                    st.reserved_free += b - a;
                }
            }
        }
        Ok(())
    }

    pub(super) fn w_reserve(&mut self, start: u64, end: u64) {
        let cs = self.cluster_size;
        let total = self.total_clusters;
        let Ntfs { w, disk, .. } = self;
        let Some(st) = w.as_deref_mut() else { return };
        let lo = start / cs;
        let hi = end.div_ceil(cs).min(total);
        if lo >= hi {
            return;
        }
        st.reserved = None;
        let mut free = 0;
        for c in lo..hi {
            match st.used(disk.as_mut(), cs, c) {
                Ok(false) => free += 1,
                Ok(true) => {}
                Err(_) => return,
            }
        }
        st.reserved = Some((lo, hi));
        st.reserved_free = free;
    }

    // ------------------------------------------------------------- the MFT

    fn alloc_record(&mut self) -> Result<(u64, u16)> {
        let rs = self.record_size as u64;
        for _round in 0..4 {
            let records = self.mft_size / rs;
            let start = self.st()?.rec_hint.clamp(FIRST_USER_RECORD, records.max(FIRST_USER_RECORD));
            let mut found = None;
            for n in (start..records).chain(FIRST_USER_RECORD..start) {
                if self.st()?.rec_used(n) {
                    continue;
                }
                let (valid, seq, in_use) = self.record_header(n)?;
                if in_use {
                    continue; // bitmap and record disagree: leave it to chkdsk
                }
                found = Some((n, if valid && seq != 0 { seq } else { 1 }));
                break;
            }
            if let Some((n, seq)) = found {
                let st = self.st()?;
                st.set_rec(n, true);
                st.rec_hint = n + 1;
                return Ok((n, seq));
            }
            self.extend_mft()?;
        }
        Err(Error::NoSpace)
    }

    fn free_record(&mut self, r: &mut Rec) -> Result<()> {
        let flags = r.flags() & !REC_IN_USE;
        put_le16(&mut r.b, 22, flags);
        let seq = match r.seq().wrapping_add(1) {
            0 => 1,
            s => s,
        };
        put_le16(&mut r.b, 16, seq);
        self.write_rec(r)?;
        let n = r.n;
        let st = self.st()?;
        st.set_rec(n, false);
        st.rec_hint = st.rec_hint.min(n);
        Ok(())
    }

    /// Grows the $MFT, preferably right after its end. Record 0 is built and
    /// checked before anything is written; on a refusal everything is given
    /// back.
    fn extend_mft(&mut self) -> Result<()> {
        if self.mft_listed {
            return Err(Error::NoSpace);
        }
        let rs = self.record_size as u64;
        let cs = self.cluster_size;
        let have = self.mft_size / rs;
        let want = (have / 8).clamp(64, 8192);
        let clusters = (want * rs).div_ceil(cs);
        let add = clusters * cs / rs;
        let near = self.mft.last().and_then(|r| r.lcn.map(|l| l + r.len));
        let new_runs = self.alloc_clusters(clusters, near, 8)?;
        let mut mft = self.mft.clone();
        for &(lcn, len) in &new_runs {
            push_run(&mut mft, lcn, len);
        }
        let size = self.mft_size + add * rs;
        // Room in the MFT's bitmap for the new records.
        let need = align8((have + add).div_ceil(8) as usize);
        let mut bitmap = self.st()?.mftbm.clone();
        if bitmap.len() < need {
            bitmap.resize(need, 0);
        }
        let mut more = Vec::new();
        let at = match &self.st()?.mftbm_at {
            MftBitmapAt::Resident => MftBitmapAt::Resident,
            MftBitmapAt::NonResident { runs, alloc } => {
                let (mut runs, mut alloc) = (runs.clone(), *alloc);
                if need as u64 > alloc {
                    let n = (need as u64 - alloc).div_ceil(cs);
                    let near = runs.last().and_then(|r| r.lcn.map(|l| l + r.len));
                    match self.alloc_clusters(n, near, 4) {
                        Ok(got) => more = got,
                        Err(e) => {
                            self.release(&new_runs)?;
                            return Err(e);
                        }
                    }
                    for &(lcn, len) in &more {
                        push_run(&mut runs, lcn, len);
                        alloc += len * cs;
                    }
                }
                MftBitmapAt::NonResident { runs, alloc }
            }
        };
        let r0 = match self.mft_record0(&mft, size, &bitmap, &at) {
            Ok(r) => r,
            Err(e) => {
                self.release(&new_runs)?;
                self.release(&more)?;
                return Err(e);
            }
        };
        // Format the new records (not in use), zero new bitmap clusters,
        // then make them part of $MFT.
        let mut n = have;
        for &(lcn, len) in &new_runs {
            let count = len * cs / rs;
            let mut buf = Vec::with_capacity((len * cs) as usize);
            for i in 0..count {
                let mut r = Rec::fresh(n + i, rs as usize, 1, 0);
                protect(&mut r.b);
                buf.extend_from_slice(&r.b);
            }
            self.disk.write_at(lcn * cs, &buf)?;
            n += count;
        }
        for &(lcn, len) in &more {
            self.disk.write_at(lcn * cs, &vec![0u8; (len * cs) as usize])?;
        }
        if let MftBitmapAt::NonResident { runs, .. } = &at {
            runs_write(self.disk.as_mut(), cs, runs, 0, &bitmap)?;
        }
        self.mft = mft;
        self.mft_size = size;
        let st = self.st()?;
        st.mftbm = bitmap;
        st.mftbm_at = at;
        st.mftbm_dirty.clear();
        self.write_rec(&r0)
    }

    /// Record 0 describing the given $MFT runs, size and bitmap.
    fn mft_record0(&mut self, mft: &[Run], size: u64, bitmap: &[u8], at: &MftBitmapAt) -> Result<Rec> {
        let mut r = self.read_rec(0)?;
        let cs = self.cluster_size;
        let d = r.find(AT_DATA, &[]).ok_or_else(|| Error::corrupt("$MFT has no data"))?;
        let runs = pairs(mft);
        let alloc: u64 = runs.iter().map(|r| r.1).sum::<u64>() * cs;
        r.replace(d, nonresident(AT_DATA, &[], &runs, alloc, size, size))?;
        let b = r.find(AT_BITMAP, &[]).ok_or_else(|| Error::corrupt("$MFT has no bitmap"))?;
        let len = bitmap.len() as u64;
        let attr = match at {
            MftBitmapAt::Resident => resident(AT_BITMAP, &[], bitmap, false),
            MftBitmapAt::NonResident { runs, alloc } => nonresident(AT_BITMAP, &[], &pairs(runs), *alloc, len, len),
        };
        r.replace(b, attr)?;
        Ok(r)
    }

    /// Record 0 after its bitmap changed (resident bitmaps, tiny volumes).
    fn write_mft_record0(&mut self) -> Result<()> {
        let mft = self.mft.clone();
        let size = self.mft_size;
        let st = self.w.as_deref().ok_or(Error::ReadOnly)?;
        let bitmap = st.mftbm.clone();
        let at = match &st.mftbm_at {
            MftBitmapAt::Resident => MftBitmapAt::Resident,
            MftBitmapAt::NonResident { runs, alloc } => MftBitmapAt::NonResident { runs: runs.clone(), alloc: *alloc },
        };
        let r = self.mft_record0(&mft, size, &bitmap, &at)?;
        self.write_rec(&r)
    }

    // ---------------------------------------------------------- data I/O

    fn write_data(&mut self, runs: &[(u64, u64)], src: &mut dyn Read, size: u64, progress: Progress) -> Result<()> {
        let cs = self.cluster_size;
        let mut buf = vec![0u8; IO_CHUNK.max(cs as usize)];
        let mut done = 0u64;
        let r = (|| -> Result<()> {
            for &(lcn, len) in runs {
                let mut off = lcn * cs;
                let end = off + len * cs;
                while off < end {
                    let n = ((end - off) as usize).min(buf.len());
                    let want = (size - done).min(n as u64) as usize;
                    read_full(src, &mut buf[..want])?;
                    buf[want..n].fill(0);
                    self.disk.write_at(off, &buf[..n])?;
                    done += want as u64;
                    off += n as u64;
                    if !progress(done) {
                        return Err(Error::Cancelled);
                    }
                }
            }
            Ok(())
        })();
        wipe(&mut buf);
        r
    }

    // ------------------------------------------------------------ indexes

    /// The attribute list of an item, if it has one.
    fn attr_list(&mut self, r: &Rec) -> Result<Option<(Vec<ListEnt>, bool)>> {
        let Some(lo) = r.find(AT_ATTRIBUTE_LIST, &[]) else { return Ok(None) };
        if r.resident(lo) {
            return Ok(Some((parse_list(r.value(lo)), true)));
        }
        let runs = r.runs(lo)?;
        let size = le64(&r.b, lo + 0x30);
        let mut v = vec![0u8; size as usize];
        let cs = self.cluster_size;
        runs_read(self.disk.as_mut(), cs, &runs, 0, &mut v)?;
        Ok(Some((parse_list(&v), false)))
    }

    fn load_ix(&mut self, rec: u64, name: &[u16]) -> Result<Ix> {
        let r = self.read_rec(rec)?;
        let list = self.attr_list(&r)?;
        let ro = r.find(AT_INDEX_ROOT, name).filter(|&o| r.resident(o)).ok_or(Error::NotADirectory)?;
        let v = r.value(ro).to_vec();
        if v.len() < 32 {
            return Err(Error::corrupt("short NTFS index root"));
        }
        let coll = le32(&v, 4);
        let ibs = le32(&v, 8) as u64;
        if !ibs.is_power_of_two() || !(512..=65_536).contains(&ibs) {
            return Err(Error::corrupt("bad NTFS index block size"));
        }
        let root = parse_node(&v, 16)?;
        let mut base_used = r.used() - le32(&r.b, ro + 4) as usize;
        // Where the allocation and the bitmap live (an extension record,
        // with an attribute list), each in one piece.
        let (mut alloc_rec, mut bitmap_rec) = (None, None);
        if let Some((ents, _)) = &list {
            let at = |ty: u32| -> Result<Option<u64>> {
                let found: Vec<&ListEnt> = ents.iter().filter(|e| e.ty == ty && e.name == name).collect();
                if found.len() > 1 {
                    return Err(Error::unsupported("changing a folder this large on NTFS (index in several pieces)"));
                }
                Ok(found.first().map(|e| e.record()).filter(|&n| n != rec))
            };
            alloc_rec = at(AT_INDEX_ALLOCATION)?;
            bitmap_rec = at(AT_BITMAP)?;
            if ents.iter().any(|e| e.ty == AT_INDEX_ROOT && e.name == name && e.record() != rec) {
                return Err(Error::unsupported("changing a folder this large on NTFS (index root elsewhere)"));
            }
        }
        let ar = match alloc_rec {
            Some(n) => self.read_rec(n)?,
            None => Rec { n: rec, b: r.b.clone() },
        };
        let (mut runs, mut bytes) = (Vec::new(), 0);
        if let Some(ao) = ar.find(AT_INDEX_ALLOCATION, name) {
            if ar.resident(ao) {
                return Err(Error::corrupt("resident NTFS index allocation"));
            }
            if le64(&ar.b, ao + 0x10) != 0 {
                return Err(Error::unsupported("changing a folder this large on NTFS (index in several pieces)"));
            }
            runs = ar.runs(ao)?;
            bytes = le64(&ar.b, ao + 0x30);
            if le64(&ar.b, ao + 0x38) < bytes || runs.iter().any(|r| r.lcn.is_none()) {
                return Err(Error::unsupported("an NTFS index with a sparse allocation"));
            }
            if alloc_rec.is_none() {
                base_used -= le32(&ar.b, ao + 4) as usize;
            }
        } else if alloc_rec.is_some() {
            return Err(Error::corrupt("NTFS attribute list points to a missing index allocation"));
        }
        let br = match bitmap_rec {
            Some(n) => self.read_rec(n)?,
            None => Rec { n: rec, b: r.b.clone() },
        };
        let mut bitmap = Vec::new();
        if let Some(bo) = br.find(AT_BITMAP, name) {
            if !br.resident(bo) {
                return Err(Error::unsupported("changing a folder this large on NTFS (index bitmap)"));
            }
            bitmap = br.value(bo).to_vec();
            if bitmap_rec.is_none() {
                base_used -= le32(&br.b, bo + 4) as usize;
            }
        } else if bitmap_rec.is_some() {
            return Err(Error::corrupt("NTFS attribute list points to a missing index bitmap"));
        }
        if bytes > 0 && (bitmap.len() as u64) * 8 < bytes / ibs {
            return Err(Error::corrupt("NTFS index bitmap too short"));
        }
        Ok(Ix {
            rec,
            name: name.to_vec(),
            coll,
            ibs,
            unit: self.index_unit(ibs),
            head: v[..16].to_vec(),
            root,
            runs,
            bytes,
            bitmap,
            base_used,
            nodes: HashMap::new(),
            usns: HashMap::new(),
            dirty: BTreeSet::new(),
            meta: false,
            grown: Vec::new(),
            listed: list.is_some(),
            alloc_rec,
            bitmap_rec,
        })
    }

    fn ix_load(&mut self, ix: &mut Ix, vcn: u64) -> Result<()> {
        if ix.nodes.contains_key(&vcn) {
            return Ok(());
        }
        let off = vcn.checked_mul(ix.unit).filter(|o| o + ix.ibs <= ix.bytes).ok_or_else(|| Error::corrupt("NTFS index block beyond its allocation"))?;
        let mut b = vec![0u8; ix.ibs as usize];
        let cs = self.cluster_size;
        runs_read(self.disk.as_mut(), cs, &ix.runs, off, &mut b)?;
        apply_fixup(&mut b, b"INDX")?;
        if le64(&b, 16) != vcn {
            return Err(Error::corrupt("NTFS index block at the wrong place"));
        }
        let usn = le16(&b, le16(&b, 4) as usize);
        let ents = parse_node(&b, 24)?;
        ix.usns.insert(vcn, usn);
        ix.nodes.insert(vcn, Node { ents, usn, lsn: le64(&b, 8) });
        Ok(())
    }

    fn ix_root_fits(&self, ix: &Ix, root_entries: usize) -> bool {
        ix.base_used + ix.root_attr_len(root_entries) + ix.alloc_attr_len() <= self.record_size
    }

    /// Adds index blocks (doubling, up to 256 at a time).
    fn ix_grow(&mut self, ix: &mut Ix) -> Result<()> {
        if ix.listed && ix.bytes == 0 {
            return Err(Error::unsupported("changing a folder this large on NTFS (attribute list)"));
        }
        let cs = self.cluster_size;
        let blocks = ix.blocks();
        let add = blocks.clamp(1, 256);
        let clusters = (add * ix.ibs).div_ceil(cs);
        let near = ix.runs.last().and_then(|r| r.lcn.map(|l| l + r.len));
        for (lcn, len) in self.alloc_clusters(clusters, near, 4)? {
            push_run(&mut ix.runs, lcn, len);
            ix.bytes += len * cs;
            ix.grown.push((lcn, len));
        }
        let need = align8(ix.blocks().div_ceil(8) as usize).max(8);
        if ix.bitmap.len() < need {
            ix.bitmap.resize(need, 0);
        }
        ix.meta = true;
        Ok(())
    }

    fn ix_new_block(&mut self, ix: &mut Ix) -> Result<u64> {
        let k = match (0..ix.blocks()).find(|&k| !ix.block_used(k)) {
            Some(k) => k,
            None => {
                let k = ix.blocks();
                self.ix_grow(ix)?;
                k
            }
        };
        ix.set_block(k, true);
        Ok(k * ix.ibs / ix.unit)
    }

    /// Position of `key` in a node: (index, equal entry found).
    fn ix_pos(&self, ix: &Ix, id: Option<u64>, key: &[u8]) -> (usize, bool) {
        let ents = ix.ents(id);
        for (i, e) in ents.iter().enumerate() {
            if e.end {
                return (i, false);
            }
            match self.collate(ix.coll, key, e.key()) {
                Ordering::Less => return (i, false),
                Ordering::Equal => return (i, true),
                Ordering::Greater => {}
            }
        }
        (ents.len().saturating_sub(1), false)
    }

    fn ix_insert(&mut self, ix: &mut Ix, ent: Ent) -> Result<()> {
        let mut path: Vec<(Option<u64>, usize)> = Vec::new();
        let mut cur: Option<u64> = None;
        let pos = loop {
            let (pos, equal) = self.ix_pos(ix, cur, ent.key());
            if equal {
                return Err(Error::AlreadyExists);
            }
            match ix.ents(cur)[pos].child {
                Some(c) => {
                    if path.len() > 64 {
                        return Err(Error::corrupt("NTFS index too deep"));
                    }
                    path.push((cur, pos));
                    self.ix_load(ix, c)?;
                    cur = Some(c);
                }
                None => break pos,
            }
        };
        ix.ents_mut(cur).insert(pos, ent);
        self.ix_settle(ix, cur, path)
    }

    /// Splits overflowing blocks upwards and keeps the root within its record.
    fn ix_settle(&mut self, ix: &mut Ix, mut cur: Option<u64>, mut path: Vec<(Option<u64>, usize)>) -> Result<()> {
        loop {
            match cur {
                Some(vcn) => {
                    if entries_size(&ix.nodes[&vcn].ents) <= ix.block_cap() {
                        cur = None;
                        path.clear();
                        continue;
                    }
                    let ents = std::mem::take(&mut ix.nodes.get_mut(&vcn).unwrap().ents);
                    let (left, mid, right) = split_node(ents)?;
                    ix.nodes.get_mut(&vcn).unwrap().ents = left;
                    ix.dirty.insert(vcn);
                    let rvcn = self.ix_new_block(ix)?;
                    ix.new_node(rvcn, right);
                    let (pid, ppos) = path.pop().ok_or_else(|| Error::corrupt("NTFS index block without a parent"))?;
                    let pents = ix.ents_mut(pid);
                    pents[ppos].child = Some(rvcn);
                    pents.insert(ppos, mid.with_child(Some(vcn)));
                    cur = pid;
                }
                None => {
                    if self.ix_root_fits(ix, entries_size(&ix.root)) {
                        return Ok(());
                    }
                    if ix.root.len() == 1 {
                        return Err(Error::unsupported("this NTFS folder's record is full"));
                    }
                    // Move the root's entries down into a block of their own.
                    let vcn = self.ix_new_block(ix)?;
                    let ents = std::mem::replace(&mut ix.root, vec![Ent::end(Some(vcn))]);
                    ix.new_node(vcn, ents);
                    ix.meta = true;
                    cur = Some(vcn);
                    path = vec![(None, 0)];
                }
            }
        }
    }

    /// Every entry, in order, without child pointers.
    fn ix_all(&mut self, ix: &mut Ix) -> Result<Vec<Ent>> {
        let root = ix.root.clone();
        let mut out = Vec::new();
        for e in root {
            if let Some(c) = e.child {
                out.extend(self.ix_subtree(ix, c, 1)?);
            }
            if !e.end {
                out.push(e.with_child(None));
            }
        }
        Ok(out)
    }

    fn ix_subtree(&mut self, ix: &mut Ix, vcn: u64, depth: usize) -> Result<Vec<Ent>> {
        if depth > 64 {
            return Err(Error::corrupt("NTFS index too deep"));
        }
        self.ix_load(ix, vcn)?;
        let ents = ix.nodes[&vcn].ents.clone();
        let mut out = Vec::new();
        for e in ents {
            if let Some(c) = e.child {
                out.extend(self.ix_subtree(ix, c, depth + 1)?);
            }
            if !e.end {
                out.push(e.with_child(None));
            }
        }
        Ok(out)
    }

    /// Rebuilds the whole index from sorted entries (after deletions that
    /// would empty a node).
    fn ix_rebuild(&mut self, ix: &mut Ix, all: Vec<Ent>) -> Result<()> {
        let size = entries_size(&all) + 16;
        // With an attribute list the allocation stays (taking it away would
        // mean editing the list): the entries then go into blocks.
        let alone = !ix.listed && ix.base_used + ix.root_attr_len(size) <= self.record_size;
        if alone {
            let runs = pairs(&ix.runs);
            self.release(&runs)?;
            ix.runs.clear();
            ix.bytes = 0;
            ix.bitmap.clear();
            ix.nodes.clear();
            ix.dirty.clear();
            ix.root = all;
            ix.root.push(Ent::end(None));
            ix.meta = true;
            return Ok(());
        }
        for b in ix.bitmap.iter_mut() {
            *b = 0;
        }
        ix.nodes.clear();
        ix.dirty.clear();
        ix.meta = true;
        let target = ix.block_cap() * 4 / 5;
        let (leaves, mut seps) = pack_leaves(all, target);
        let mut children = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let vcn = self.ix_new_block(ix)?;
            ix.new_node(vcn, leaf);
            children.push(vcn);
        }
        loop {
            let root = root_over(&children, &seps);
            if self.ix_root_fits(ix, entries_size(&root)) {
                ix.root = root;
                return Ok(());
            }
            if children.len() == 1 {
                return Err(Error::unsupported("this NTFS folder's record is full"));
            }
            let (nodes, ups) = pack_internal(&children, seps, target);
            children.clear();
            for n in nodes {
                let vcn = self.ix_new_block(ix)?;
                ix.new_node(vcn, n);
                children.push(vcn);
            }
            seps = ups;
        }
    }

    /// Removes the entry with `key` that `pick` accepts. False if absent.
    fn ix_remove(&mut self, ix: &mut Ix, key: &[u8], pick: &dyn Fn(&Ent) -> bool) -> Result<bool> {
        let mut cur: Option<u64> = None;
        for _depth in 0..64 {
            let mut next = None;
            let mut hit = None;
            for (i, e) in ix.ents(cur).iter().enumerate() {
                if e.end {
                    next = e.child;
                    break;
                }
                match self.collate(ix.coll, key, e.key()) {
                    Ordering::Equal if pick(e) => {
                        hit = Some(i);
                        break;
                    }
                    Ordering::Less => {
                        next = e.child;
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(i) = hit {
                let ents = ix.ents(cur);
                let leaf = ents[i].child.is_none();
                if leaf && (cur.is_none() || ents.len() > 2) {
                    ix.ents_mut(cur).remove(i);
                    return Ok(true);
                }
                let mut all = self.ix_all(ix)?;
                let at = all.iter().position(|e| self.collate(ix.coll, key, e.key()) == Ordering::Equal && pick(e));
                if let Some(at) = at {
                    all.remove(at);
                }
                self.ix_rebuild(ix, all)?;
                return Ok(true);
            }
            match next {
                Some(c) => {
                    self.ix_load(ix, c)?;
                    cur = Some(c);
                }
                None => return Ok(false),
            }
        }
        Err(Error::corrupt("NTFS index too deep"))
    }

    fn block_image(ix: &Ix, vcn: u64) -> Vec<u8> {
        let node = &ix.nodes[&vcn];
        let ibs = ix.ibs as usize;
        let usa_count = ibs / 512 + 1;
        let eo = align8(16 + 2 * usa_count);
        let mut b = vec![0u8; ibs];
        b[..4].copy_from_slice(b"INDX");
        put_le16(&mut b, 4, 0x28);
        put_le16(&mut b, 6, usa_count as u16);
        put_le64(&mut b, 8, node.lsn);
        put_le64(&mut b, 16, vcn);
        let mut ents = Vec::new();
        put_entries(&node.ents, &mut ents);
        put_le32(&mut b, 0x18, eo as u32);
        put_le32(&mut b, 0x1C, (eo + ents.len()) as u32);
        put_le32(&mut b, 0x20, (ibs - 0x18) as u32);
        b[0x24] = node.ents.last().is_some_and(|e| e.child.is_some()) as u8;
        b[0x18 + eo..0x18 + eo + ents.len()].copy_from_slice(&ents);
        put_le16(&mut b, 0x28, node.usn);
        protect(&mut b);
        b
    }

    fn root_value(ix: &Ix) -> Vec<u8> {
        let mut ents = Vec::new();
        put_entries(&ix.root, &mut ents);
        let mut v = ix.head.clone();
        let mut hdr = [0u8; 16];
        put_le32(&mut hdr, 0, 16);
        put_le32(&mut hdr, 4, 16 + ents.len() as u32);
        put_le32(&mut hdr, 8, 16 + ents.len() as u32);
        hdr[12] = ix.root.last().is_some_and(|e| e.child.is_some()) as u8;
        v.extend_from_slice(&hdr);
        v.extend_from_slice(&ents);
        v
    }

    /// Writes changed blocks, then the owner record. The record is built and
    /// checked first, so a record that cannot hold the index changes nothing.
    fn ix_commit(&mut self, ix: &mut Ix) -> Result<()> {
        let mut recs: Vec<Rec> = Vec::new();
        if ix.meta {
            let mut r = self.read_rec(ix.rec)?;
            let ro = r.find(AT_INDEX_ROOT, &ix.name).ok_or_else(|| Error::corrupt("NTFS index root vanished"))?;
            r.replace(ro, resident(AT_INDEX_ROOT, &ix.name, &Self::root_value(ix), false))?;
            let alloc = (ix.bytes > 0).then(|| nonresident(AT_INDEX_ALLOCATION, &ix.name, &pairs(&ix.runs), ix.bytes, ix.bytes, ix.bytes));
            let bitmap = (ix.bytes > 0).then(|| resident(AT_BITMAP, &ix.name, &ix.bitmap, false));
            let mut others: Vec<Rec> = Vec::new();
            for (ty, attr, at) in [(AT_INDEX_ALLOCATION, alloc, ix.alloc_rec), (AT_BITMAP, bitmap, ix.bitmap_rec)] {
                match at {
                    // In an extension record: replaced there, in place.
                    Some(n) => {
                        let i = match others.iter().position(|o| o.n == n) {
                            Some(i) => i,
                            None => {
                                others.push(self.read_rec(n)?);
                                others.len() - 1
                            }
                        };
                        let x = &mut others[i];
                        let o = x.find(ty, &ix.name).ok_or_else(|| Error::corrupt("NTFS index attribute vanished"))?;
                        match attr {
                            Some(a) => x.replace(o, a)?,
                            None => return Err(Error::unsupported("changing a folder this large on NTFS (attribute list)")),
                        }
                    }
                    None => match (r.find(ty, &ix.name), attr) {
                        (Some(o), Some(a)) => r.replace(o, a)?,
                        (Some(o), None) if !ix.listed => r.remove(o),
                        (None, Some(a)) if !ix.listed => r.insert(a, None)?,
                        (None, None) => {}
                        _ => return Err(Error::unsupported("changing a folder this large on NTFS (attribute list)")),
                    },
                }
            }
            recs.push(r);
            recs.extend(others);
        }
        let cs = self.cluster_size;
        let dirty: Vec<u64> = std::mem::take(&mut ix.dirty).into_iter().collect();
        for vcn in dirty {
            if !ix.nodes.contains_key(&vcn) {
                continue;
            }
            let img = Self::block_image(ix, vcn);
            let usn = le16(&img, 0x28);
            runs_write(self.disk.as_mut(), cs, &ix.runs, vcn * ix.unit, &img)?;
            ix.nodes.get_mut(&vcn).unwrap().usn = usn;
            ix.usns.insert(vcn, usn);
        }
        // Extension records first: the base record is what points at them.
        for r in recs.iter().rev() {
            self.write_rec(r)?;
        }
        ix.meta = false;
        ix.grown.clear();
        Ok(())
    }

    /// Gives back what an abandoned (never committed) change to `ix` took.
    fn ix_abandon(&mut self, ix: &mut Ix) -> Result<()> {
        let grown = std::mem::take(&mut ix.grown);
        self.release(&grown)
    }

    /// The INDEX_ROOT header of a directory (index type, collation, sizes),
    /// for a new directory made inside it.
    fn i30_head(&mut self, dir: u64) -> Result<Vec<u8>> {
        let r = self.read_rec(dir)?;
        let o = r.find(AT_INDEX_ROOT, &I30_NAME).filter(|&o| r.resident(o)).ok_or(Error::NotADirectory)?;
        let v = r.value(o);
        if v.len() < 16 {
            return Err(Error::corrupt("short NTFS index root"));
        }
        Ok(v[..16].to_vec())
    }

    // -------------------------------------------------------- operations

    /// Refuses system records, hard-linked files (more than one name besides
    /// a DOS short name) and reparse points.
    fn check_deletable(&mut self, r: &Rec) -> Result<()> {
        if r.n < FIRST_USER_RECORD {
            return Err(Error::ReadOnly);
        }
        if r.find(AT_REPARSE_POINT, &[]).is_some() {
            return Err(Error::unsupported("changing a Windows link or cloud placeholder (reparse point)"));
        }
        let long_names = self.names_of(r)?.iter().filter(|v| v.get(65) != Some(&NS_DOS)).count();
        if long_names > 1 {
            return Err(Error::unsupported("deleting or moving an NTFS file with several hard links"));
        }
        Ok(())
    }

    /// Every $FILE_NAME value of an item, extension records included.
    fn names_of(&mut self, r: &Rec) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = r.all(AT_FILE_NAME).into_iter().map(|o| r.value(o).to_vec()).collect();
        if r.find(AT_ATTRIBUTE_LIST, &[]).is_some() {
            let base = Rec { n: r.n, b: r.b.clone() };
            for x in self.item_records(base)?.into_iter().skip(1) {
                out.extend(x.all(AT_FILE_NAME).into_iter().map(|o| x.value(o).to_vec()));
            }
        }
        Ok(out)
    }

    /// The records an item spans: its base record and, with an attribute
    /// list, its extension records.
    fn item_records(&mut self, base: Rec) -> Result<Vec<Rec>> {
        let mut out = vec![base];
        if let Some(lo) = out[0].find(AT_ATTRIBUTE_LIST, &[]) {
            let bytes = if out[0].resident(lo) {
                out[0].value(lo).to_vec()
            } else {
                let runs = out[0].runs(lo)?;
                let size = le64(&out[0].b, lo + 0x30);
                let mut v = vec![0u8; size as usize];
                let cs = self.cluster_size;
                runs_read(self.disk.as_mut(), cs, &runs, 0, &mut v)?;
                v
            };
            let mut seen = HashSet::new();
            seen.insert(out[0].n);
            let mut p = 0;
            while p + 26 <= bytes.len() {
                let len = le16(&bytes, p + 4) as usize;
                if len < 26 || p + len > bytes.len() {
                    break;
                }
                let n = le64(&bytes, p + 16) & REF_MASK;
                if seen.insert(n) {
                    out.push(self.read_rec(n)?);
                }
                p += len;
            }
        }
        Ok(out)
    }

    /// Deletes an item (a folder with everything in it). With `parent`, its
    /// names also leave the parent's index (committed by the caller).
    fn delete_item(&mut self, it: &Item, parent: Option<&mut Ix>) -> Result<()> {
        let base = self.read_rec(it.record)?;
        if base.flags() & REC_IN_USE == 0 || (it.seq != 0 && base.seq() != it.seq) {
            return Err(Error::corrupt("NTFS index points to a deleted file"));
        }
        self.check_deletable(&base)?;
        if base.flags() & REC_DIRECTORY != 0 {
            let mut done = HashSet::new();
            for (file_ref, key) in self.dir_keys(it.record)? {
                let n = file_ref & REF_MASK;
                if n == it.record || !done.insert(n) {
                    continue;
                }
                let child = Self::item_of(file_ref, &key);
                self.delete_item(&child, None)?;
            }
        }
        if let Some(ix) = parent {
            for v in self.names_of(&base)? {
                if v.len() >= 66 && le64(&v, 0) & REF_MASK == ix.rec {
                    let n = base.n;
                    self.ix_remove(ix, &v, &|e: &Ent| e.record() == n)?;
                }
            }
        }
        if let Some(o) = base.find(AT_OBJECT_ID, &[]) {
            if base.resident(o) && base.value(o).len() >= 16 {
                let oid = base.value(o)[..16].to_vec();
                self.delete_object_id(&oid, base.n)?;
            }
        }
        let mut records = self.item_records(base)?;
        for r in &records {
            for (o, _) in r.attrs() {
                if !r.resident(o) {
                    let runs = pairs(&r.runs(o)?);
                    self.release(&runs)?;
                }
            }
        }
        for r in &mut records {
            self.free_record(r)?;
        }
        Ok(())
    }

    /// Takes a deleted file's object id out of $Extend\$ObjId:$O.
    fn delete_object_id(&mut self, oid: &[u8], record: u64) -> Result<()> {
        let Some(objid) = self.lookup(MFT_RECORD_EXTEND, "$ObjId")? else {
            return Ok(());
        };
        let mut ix = match self.load_ix(objid.record, &O_NAME) {
            Ok(ix) => ix,
            Err(Error::NotADirectory) => return Ok(()),
            Err(e) => return Err(e),
        };
        let pick = |e: &Ent| {
            let off = le16(&e.bytes, 0) as usize;
            off + 8 <= e.bytes.len() && le64(&e.bytes, off) & REF_MASK == record
        };
        if self.ix_remove(&mut ix, oid, &pick)? {
            self.ix_commit(&mut ix)?;
        }
        Ok(())
    }

    fn parent_dir(&mut self, comps: &[&str]) -> Result<Item> {
        let p = self.resolve_comps(comps)?;
        if !p.is_dir {
            return Err(Error::NotADirectory);
        }
        Ok(p)
    }

    /// Size of the fixed part of a new record: header, $STANDARD_INFORMATION,
    /// $FILE_NAME, $SECURITY_DESCRIPTOR and the end marker.
    fn fixed_part(&self, name_units: usize) -> usize {
        align8(0x30 + 2 * (self.record_size / 512 + 1)) + resident_len(0, 48) + resident_len(0, 66 + 2 * name_units) + resident_len(0, sd_everyone().len()) + 8
    }

    fn new_record(&self, n: u64, seq: u16, flags: u16, t: u64, fa: u32, fnv: &[u8]) -> Result<Rec> {
        let mut r = Rec::fresh(n, self.record_size, seq, flags);
        put_le16(&mut r.b, 18, 1);
        r.insert(resident(AT_STANDARD_INFORMATION, &[], &si_value(t, fa), false), None)?;
        r.insert(resident(AT_FILE_NAME, &[], fnv, true), None)?;
        r.insert(resident(AT_SECURITY_DESCRIPTOR, &[], &sd_everyone(), false), None)?;
        Ok(r)
    }

    pub(super) fn w_write_file(&mut self, path: &str, src: &mut dyn Read, size: u64, overwrite: bool, progress: Progress) -> Result<()> {
        self.writable()?;
        let (pc, leaf) = split_parent(path)?;
        validate_name(leaf)?;
        let parent = self.parent_dir(&pc)?;
        let existing = self.lookup(parent.record, leaf)?;
        if let Some(e) = &existing {
            if e.is_dir {
                return Err(Error::IsADirectory);
            }
            if !overwrite || e.record < FIRST_USER_RECORD {
                return Err(Error::AlreadyExists);
            }
            self.check_tree(e, 0)?;
        } else if size.div_ceil(self.cluster_size) > self.available()? {
            return Err(Error::NoSpace);
        }
        self.begin()?;
        let r = self.write_file_in(&parent, existing.as_ref(), leaf, src, size, progress);
        self.after(r)
    }

    fn write_file_in(&mut self, parent: &Item, existing: Option<&Item>, leaf: &str, src: &mut dyn Read, size: u64, progress: Progress) -> Result<()> {
        let mut ix = self.load_ix(parent.record, &I30_NAME)?;
        if let Some(e) = existing {
            if let Err(err) = self.delete_item(e, Some(&mut ix)).and_then(|_| self.ix_commit(&mut ix)) {
                self.damage();
                return Err(err);
            }
        }
        let name: Vec<u16> = leaf.encode_utf16().collect();
        let cs = self.cluster_size;
        let fixed = self.fixed_part(name.len());
        let resident_fits = fixed + resident_len(0, size as usize) <= self.record_size && size < self.record_size as u64;
        let (data_attr, runs, alloc) = if resident_fits {
            let mut v = vec![0u8; size as usize];
            read_full(src, &mut v)?;
            if !progress(size) {
                return Err(Error::Cancelled);
            }
            let a = resident(AT_DATA, &[], &v, false);
            wipe(&mut v);
            (a, Vec::new(), align8(size as usize) as u64)
        } else {
            let clusters = size.div_ceil(cs);
            let room = self.record_size.saturating_sub(fixed + 0x40 + 8);
            let runs = self.alloc_clusters(clusters, None, (room / 10).max(1))?;
            let attr = nonresident(AT_DATA, &[], &runs, clusters * cs, size, size);
            if fixed + attr.len() > self.record_size {
                self.release(&runs)?;
                return Err(Error::unsupported("the drive's free space is too fragmented for this file"));
            }
            if let Err(e) = self.write_data(&runs, src, size, progress) {
                self.release(&runs)?;
                return Err(e);
            }
            (attr, runs, clusters * cs)
        };
        let (n, seq) = match self.alloc_record() {
            Ok(x) => x,
            Err(e) => {
                self.release(&runs)?;
                if !matches!(e, Error::NoSpace) {
                    self.damage();
                }
                return Err(e);
            }
        };
        let t = now_filetime();
        let fnv = fn_value(parent.file_ref(), [t; 4], alloc, size, FA_ARCHIVE, &name, NS_POSIX);
        let built = self.new_record(n, seq, REC_IN_USE, t, FA_ARCHIVE, &fnv).and_then(|mut r| r.insert(data_attr, None).map(|_| r));
        let mut rec = match built {
            Ok(r) => r,
            Err(e) => {
                self.st()?.set_rec(n, false);
                self.release(&runs)?;
                return Err(e);
            }
        };
        self.write_rec(&rec)?;
        if let Err(e) = self.ix_insert(&mut ix, i30_entry(n | (seq as u64) << 48, &fnv)) {
            self.ix_abandon(&mut ix)?;
            self.free_record(&mut rec)?;
            self.release(&runs)?;
            return Err(e);
        }
        if let Err(e) = self.ix_commit(&mut ix) {
            self.damage();
            return Err(e);
        }
        Ok(())
    }

    pub(super) fn w_mkdir(&mut self, path: &str) -> Result<()> {
        self.writable()?;
        let (pc, leaf) = split_parent(path)?;
        validate_name(leaf)?;
        let parent = self.parent_dir(&pc)?;
        if self.lookup(parent.record, leaf)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        let head = self.i30_head(parent.record)?;
        let name: Vec<u16> = leaf.encode_utf16().collect();
        if self.fixed_part(name.len()) + resident_len(4, 48) + 128 > self.record_size {
            return Err(Error::InvalidName);
        }
        self.begin()?;
        let r = (|| -> Result<()> {
            let mut ix = self.load_ix(parent.record, &I30_NAME)?;
            let (n, seq) = self.alloc_record()?;
            let t = now_filetime();
            let fnv = fn_value(parent.file_ref(), [t; 4], 0, 0, FA_DIRECTORY_INDEX, &name, NS_POSIX);
            let mut value = head.clone();
            let mut hdr = [0u8; 16];
            put_le32(&mut hdr, 0, 16);
            put_le32(&mut hdr, 4, 32);
            put_le32(&mut hdr, 8, 32);
            value.extend_from_slice(&hdr);
            put_entries(&[Ent::end(None)], &mut value);
            let built = self.new_record(n, seq, REC_IN_USE | REC_DIRECTORY, t, 0, &fnv).and_then(|mut r| r.insert(resident(AT_INDEX_ROOT, &I30_NAME, &value, false), None).map(|_| r));
            let mut rec = match built {
                Ok(r) => r,
                Err(e) => {
                    self.st()?.set_rec(n, false);
                    return Err(e);
                }
            };
            self.write_rec(&rec)?;
            if let Err(e) = self.ix_insert(&mut ix, i30_entry(n | (seq as u64) << 48, &fnv)) {
                self.ix_abandon(&mut ix)?;
                self.free_record(&mut rec)?;
                return Err(e);
            }
            if let Err(e) = self.ix_commit(&mut ix) {
                self.damage();
                return Err(e);
            }
            Ok(())
        })();
        self.after(r)
    }

    pub(super) fn w_remove(&mut self, path: &str) -> Result<()> {
        self.writable()?;
        let (pc, leaf) = split_parent(path)?;
        let parent = self.parent_dir(&pc)?;
        let it = self.lookup(parent.record, leaf)?.ok_or(Error::NotFound)?;
        if it.record < FIRST_USER_RECORD || it.record == parent.record {
            return Err(Error::ReadOnly);
        }
        self.check_tree(&it, 0)?;
        self.begin()?;
        let r = (|| -> Result<()> {
            let mut ix = self.load_ix(parent.record, &I30_NAME)?;
            self.delete_item(&it, Some(&mut ix))?;
            self.ix_commit(&mut ix)
        })();
        if r.is_err() {
            self.damage();
        }
        self.after(r)
    }

    /// Makes room in a record: a file's data moves out to clusters, a
    /// folder's index entries move down into an index block. False when
    /// nothing could move.
    fn make_room(&mut self, rec: &mut Rec) -> Result<bool> {
        if rec.flags() & REC_DIRECTORY != 0 {
            let mut ix = self.load_ix(rec.n, &I30_NAME)?;
            if ix.root.len() <= 1 {
                return Ok(false);
            }
            let vcn = self.ix_new_block(&mut ix)?;
            let ents = std::mem::replace(&mut ix.root, vec![Ent::end(Some(vcn))]);
            ix.new_node(vcn, ents);
            ix.meta = true;
            self.ix_commit(&mut ix)?;
            *rec = self.read_rec(rec.n)?;
            return Ok(true);
        }
        let Some(d) = rec.find(AT_DATA, &[]).filter(|&d| rec.resident(d)) else {
            return Ok(false);
        };
        let v = rec.value(d).to_vec();
        if v.is_empty() {
            return Ok(false);
        }
        let cs = self.cluster_size;
        let clusters = (v.len() as u64).div_ceil(cs);
        let runs = self.alloc_clusters(clusters, None, 1)?;
        if let Err(e) = self.write_data(&runs, &mut &v[..], v.len() as u64, &mut |_| true) {
            self.release(&runs)?;
            return Err(e);
        }
        let len = v.len() as u64;
        rec.replace(d, nonresident(AT_DATA, &[], &runs, clusters * cs, len, len))?;
        Ok(true)
    }

    /// The record with `fnv` as its only name in `from`'s place; an attribute
    /// list (resident) follows: entries of the old names out, the new one in.
    fn renamed(rec: &Rec, mine: &[usize], fnv: &[u8]) -> Result<Rec> {
        let mut r = Rec { n: rec.n, b: rec.b.clone() };
        let gone: Vec<u16> = mine.iter().map(|&o| le16(&rec.b, o + 14)).collect();
        let mut offs = mine.to_vec();
        offs.sort_unstable_by(|a, b| b.cmp(a));
        for o in offs {
            r.remove(o);
        }
        r.insert(resident(AT_FILE_NAME, &[], fnv, true), None)?;
        put_le16(&mut r.b, 18, 1);
        if let Some(lo) = r.find(AT_ATTRIBUTE_LIST, &[]) {
            if !r.resident(lo) {
                return Err(Error::unsupported("renaming a heavily fragmented NTFS file (attribute list)"));
            }
            let inst = r.all(AT_FILE_NAME).into_iter().map(|o| le16(&r.b, o + 14)).max().unwrap_or(0);
            let base = rec.n;
            let mut ents: Vec<ListEnt> = parse_list(r.value(lo)).into_iter().filter(|e| !(e.ty == AT_FILE_NAME && e.record() == base && gone.contains(&e.inst))).collect();
            let at = ents.iter().position(|e| e.ty > AT_FILE_NAME).unwrap_or(ents.len());
            ents.insert(at, ListEnt { ty: AT_FILE_NAME, name: Vec::new(), vcn: 0, file_ref: base | (rec.seq() as u64) << 48, inst });
            r.replace(lo, resident(AT_ATTRIBUTE_LIST, &[], &list_bytes(&ents), false))?;
        }
        Ok(r)
    }

    /// Gives an item a new name and/or parent.
    fn relink(&mut self, it: &Item, from: &Item, to: &Item, new_name: Option<&str>) -> Result<()> {
        let rec = self.read_rec(it.record)?;
        self.check_deletable(&rec)?;
        if let Some((ents, resident)) = self.attr_list(&rec)? {
            // Names kept in extension records, or a list too long to stay in
            // the record, are left to Windows.
            if !resident || ents.iter().any(|e| e.ty == AT_FILE_NAME && e.record() != rec.n) {
                return Err(Error::unsupported("renaming a heavily fragmented NTFS file (attribute list)"));
            }
        }
        self.begin()?;
        let r = self.relink_in(rec, it, from, to, new_name);
        self.after(r)
    }

    fn relink_in(&mut self, mut rec: Rec, it: &Item, from: &Item, to: &Item, new_name: Option<&str>) -> Result<()> {
        let mut moved = false;
        let (new_rec, fnv, old_keys) = loop {
            let mine: Vec<usize> = rec.all(AT_FILE_NAME).into_iter().filter(|&o| le64(rec.value(o), 0) & REF_MASK == from.record).collect();
            let base = mine.iter().copied().find(|&o| rec.value(o).get(65) != Some(&NS_DOS)).or(mine.first().copied()).ok_or_else(|| Error::corrupt("NTFS file without its name"))?;
            let old = rec.value(base).to_vec();
            let units: Vec<u16> = match new_name {
                Some(n) => n.encode_utf16().collect(),
                None => units_of(fn_name(&old)).collect(),
            };
            let (alloc, size) = if rec.flags() & REC_DIRECTORY != 0 {
                (0, 0)
            } else {
                match rec.find(AT_DATA, &[]) {
                    Some(d) if rec.resident(d) => {
                        let l = rec.value(d).len();
                        (align8(l) as u64, l as u64)
                    }
                    Some(d) => (le64(&rec.b, d + 0x28), le64(&rec.b, d + 0x30)),
                    None => (le64(&old, 40), le64(&old, 48)),
                }
            };
            let times = [le64(&old, 8), le64(&old, 16), now_filetime(), le64(&old, 32)];
            let fnv = fn_value(to.file_ref(), times, alloc, size, le32(&old, 56), &units, NS_POSIX);
            let old_keys: Vec<Vec<u8>> = mine.iter().map(|&o| rec.value(o).to_vec()).collect();
            match Self::renamed(&rec, &mine, &fnv) {
                Ok(r) => break (r, fnv, old_keys),
                Err(Error::NoSpace) if !moved => {
                    let file = rec.flags() & REC_DIRECTORY == 0;
                    match self.make_room(&mut rec) {
                        Ok(true) => moved = true,
                        Ok(false) => return Err(Error::InvalidName),
                        Err(e) => {
                            if !file {
                                self.damage();
                            }
                            return Err(e);
                        }
                    }
                }
                Err(Error::NoSpace) => {
                    // Still too long: give back the clusters the data moved to.
                    if let Some(d) = rec.find(AT_DATA, &[]).filter(|&d| !rec.resident(d) && rec.flags() & REC_DIRECTORY == 0) {
                        let runs = pairs(&rec.runs(d)?);
                        let old = self.read_rec(rec.n)?;
                        if old.find(AT_DATA, &[]).is_some_and(|o| old.resident(o)) {
                            self.release(&runs)?;
                        }
                    }
                    return Err(Error::InvalidName);
                }
                Err(e) => return Err(e),
            }
        };
        // Data moved out of the record in memory only: its clusters go back
        // if the change is abandoned.
        let moved_runs = match (rec.find(AT_DATA, &[]), self.read_rec(rec.n)?.find(AT_DATA, &[])) {
            (Some(d), Some(_)) if moved && !rec.resident(d) && rec.flags() & REC_DIRECTORY == 0 => pairs(&rec.runs(d)?),
            _ => Vec::new(),
        };
        let n = it.record;
        let file_ref = it.record | (new_rec.seq() as u64) << 48;
        let mut fix = self.load_ix(from.record, &I30_NAME)?;
        let mut tix = if from.record == to.record { None } else { Some(self.load_ix(to.record, &I30_NAME)?) };
        let staged = (|| -> Result<()> {
            for k in &old_keys {
                self.ix_remove(&mut fix, k, &|e: &Ent| e.record() == n)?;
            }
            match tix.as_mut() {
                None => self.ix_insert(&mut fix, i30_entry(file_ref, &fnv)),
                Some(t) => self.ix_insert(t, i30_entry(file_ref, &fnv)),
            }
        })();
        if let Err(e) = staged {
            self.ix_abandon(&mut fix)?;
            if let Some(t) = tix.as_mut() {
                self.ix_abandon(t)?;
            }
            let old = self.read_rec(rec.n)?;
            if old.find(AT_DATA, &[]).is_some_and(|o| old.resident(o)) {
                self.release(&moved_runs)?;
            }
            return Err(e);
        }
        let r = (|| -> Result<()> {
            self.ix_commit(&mut fix)?;
            if let Some(t) = tix.as_mut() {
                self.ix_commit(t)?;
            }
            self.write_rec(&new_rec)
        })();
        if r.is_err() {
            self.damage();
        }
        r
    }

    pub(super) fn w_rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        self.writable()?;
        validate_name(new_name)?;
        let (pc, leaf) = split_parent(path)?;
        let parent = self.parent_dir(&pc)?;
        let it = self.lookup(parent.record, leaf)?.ok_or(Error::NotFound)?;
        if it.record < FIRST_USER_RECORD {
            return Err(Error::ReadOnly);
        }
        if it.name == new_name {
            return Ok(());
        }
        if let Some(other) = self.lookup(parent.record, new_name)? {
            if other.record != it.record {
                return Err(Error::AlreadyExists);
            }
        }
        self.relink(&it, &parent, &parent, Some(new_name))
    }

    pub(super) fn w_move(&mut self, path: &str, dest_dir: &str) -> Result<()> {
        self.writable()?;
        super::super::check_move(path, dest_dir)?;
        let (pc, leaf) = split_parent(path)?;
        let from = self.parent_dir(&pc)?;
        let it = self.lookup(from.record, leaf)?.ok_or(Error::NotFound)?;
        if it.record < FIRST_USER_RECORD {
            return Err(Error::ReadOnly);
        }
        let to = self.resolve(dest_dir)?;
        if !to.is_dir {
            return Err(Error::NotADirectory);
        }
        if to.record == from.record {
            return Ok(());
        }
        if to.record == it.record {
            return Err(Error::invalid("cannot move a folder into itself"));
        }
        let rec = self.read_rec(it.record)?;
        let name = rec
            .all(AT_FILE_NAME)
            .into_iter()
            .map(|o| rec.value(o).to_vec())
            .find(|v| v.get(65) != Some(&NS_DOS))
            .map(|v| String::from_utf16_lossy(&units_of(fn_name(&v)).collect::<Vec<u16>>()))
            .unwrap_or_else(|| it.name.clone());
        if self.lookup(to.record, &name)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        self.relink(&it, &from, &to, Some(&name))
    }

    pub(super) fn w_flush(&mut self) -> Result<()> {
        if self.w.is_none() {
            return self.disk.flush();
        }
        self.finish()?;
        let st = self.st()?;
        if st.dirty_on_disk && !st.damaged {
            self.set_volume_dirty(false)?;
            self.disk.flush()?;
            self.st()?.dirty_on_disk = false;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------- check

/// What one index walk found.
struct IxWalk {
    entries: Vec<(u64, Vec<u8>)>,
    blocks: HashSet<u64>,
    leaf_depths: HashSet<usize>,
}

impl Ntfs {
    fn walk_index(&mut self, dir: u64, rep: &mut CheckReport) -> Result<Option<IxWalk>> {
        let r = self.read_rec(dir)?;
        let Some(ro) = r.find(AT_INDEX_ROOT, &I30_NAME).filter(|&o| r.resident(o)) else {
            rep.issue(format!("folder record {dir} has no $I30 index root"));
            rep.bad_chains += 1;
            return Ok(None);
        };
        let v = r.value(ro).to_vec();
        let ibs = le32(&v, 8) as u64;
        let coll = le32(&v, 4);
        let alloc = match self.stream(dir, AT_INDEX_ALLOCATION, &I30) {
            Ok(a) => Some(a),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        let bitmap = match self.stream(dir, AT_BITMAP, &I30) {
            Ok(Stream::Resident(b)) => b,
            Ok(s @ Stream::NonResident { .. }) => {
                let mut b = vec![0u8; s.size() as usize];
                self.read_stream(&s, 0, &mut b)?;
                b
            }
            Err(_) => Vec::new(),
        };
        let mut w = IxWalk { entries: Vec::new(), blocks: HashSet::new(), leaf_depths: HashSet::new() };
        let mut prev: Option<Vec<u8>> = None;
        let root = parse_node(&v, 16)?;
        self.walk_node(dir, coll, ibs, alloc.as_ref(), root, 0, &mut w, &mut prev, rep)?;
        if w.leaf_depths.len() > 1 {
            rep.bad_chains += 1;
            rep.issue(format!("folder record {dir}: index leaves at depths {:?}", w.leaf_depths));
        }
        let unit = self.index_unit(ibs);
        let blocks = alloc.as_ref().map_or(0, |a| a.size() / ibs);
        for k in 0..blocks {
            let marked = bitmap.get((k / 8) as usize).is_some_and(|b| b & (1 << (k % 8)) != 0);
            let used = w.blocks.contains(&(k * ibs / unit));
            if marked != used {
                rep.bitmap_errors += 1;
                rep.issue(format!("folder record {dir}: index block {k} {}", if used { "used but free in its bitmap" } else { "marked used but unreachable" }));
            }
        }
        Ok(Some(w))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_node(&mut self, dir: u64, coll: u32, ibs: u64, alloc: Option<&Stream>, ents: Vec<Ent>, depth: usize, w: &mut IxWalk, prev: &mut Option<Vec<u8>>, rep: &mut CheckReport) -> Result<()> {
        if depth > 32 {
            rep.bad_chains += 1;
            rep.issue(format!("folder record {dir}: index too deep"));
            return Ok(());
        }
        let internal = ents.last().is_some_and(|e| e.child.is_some());
        if !internal {
            w.leaf_depths.insert(depth);
        }
        if depth > 0 && ents.len() < 2 {
            rep.bad_chains += 1;
            rep.issue(format!("folder record {dir}: empty index block"));
        }
        for e in ents {
            if e.child.is_some() != internal {
                rep.bad_chains += 1;
                rep.issue(format!("folder record {dir}: index node mixes leaf and inner entries"));
            }
            if let Some(vcn) = e.child {
                let Some(a) = alloc else {
                    rep.bad_chains += 1;
                    rep.issue(format!("folder record {dir}: child block without an allocation"));
                    continue;
                };
                if !w.blocks.insert(vcn) {
                    rep.cross_linked += 1;
                    rep.issue(format!("folder record {dir}: index block {vcn} reached twice"));
                    continue;
                }
                let block = match self.index_block(a, ibs, vcn) {
                    Ok(b) => b,
                    Err(err) => {
                        rep.bad_chains += 1;
                        rep.issue(format!("folder record {dir}: index block {vcn}: {err}"));
                        continue;
                    }
                };
                if le64(&block, 16) != vcn {
                    rep.bad_chains += 1;
                    rep.issue(format!("folder record {dir}: index block {vcn} says it is {}", le64(&block, 16)));
                }
                let flag = block[0x24] & 1 != 0;
                let sub = parse_node(&block, 24)?;
                if flag != sub.last().is_some_and(|e| e.child.is_some()) {
                    rep.bad_chains += 1;
                    rep.issue(format!("folder record {dir}: index block {vcn} has a wrong node flag"));
                }
                self.walk_node(dir, coll, ibs, alloc, sub, depth + 1, w, prev, rep)?;
            }
            if !e.end {
                let key = e.key().to_vec();
                if let Some(p) = prev.as_ref() {
                    if self.collate(coll, p, &key) != Ordering::Less {
                        rep.bad_chains += 1;
                        rep.issue(format!("folder record {dir}: index out of order at {:?}", String::from_utf16_lossy(&units_of(fn_name(&key)).collect::<Vec<u16>>())));
                    }
                }
                w.entries.push((e.file_ref(), key.clone()));
                *prev = Some(key);
            }
        }
        Ok(())
    }

    /// Checks records, cluster and record bitmaps, and every folder index
    /// (order, balance, block bitmaps, and that names and records agree).
    /// Reports only: repairs are left to Windows' chkdsk.
    pub(super) fn w_check(&mut self) -> Result<CheckReport> {
        let mut rep = CheckReport::default();
        let rs = self.record_size as u64;
        let cs = self.cluster_size;
        let total = self.total_clusters;
        let records = self.mft_size / rs;
        let bm_stream = self.stream(MFT_RECORD_BITMAP, AT_DATA, &[])?;
        let mut bm = vec![0u8; total.div_ceil(8) as usize];
        self.read_stream(&bm_stream, 0, &mut bm)?;
        let r0 = self.read_rec(0)?;
        let mftbm = match r0.find(AT_BITMAP, &[]) {
            Some(o) if r0.resident(o) => r0.value(o).to_vec(),
            Some(o) => {
                let runs = r0.runs(o)?;
                let mut v = vec![0u8; le64(&r0.b, o + 0x30) as usize];
                runs_read(self.disk.as_mut(), cs, &runs, 0, &mut v)?;
                v
            }
            None => return Err(Error::corrupt("$MFT has no bitmap")),
        };
        let bit = |v: &[u8], i: u64| v.get((i / 8) as usize).is_some_and(|b| b & (1 << (i % 8)) != 0);
        if let Ok(Stream::NonResident { runs, size, .. }) = self.stream(MFT_RECORD_MIRROR, AT_DATA, &[]) {
            for n in 0..(size / rs).min(4) {
                let mut m = vec![0u8; rs as usize];
                runs_read(self.disk.as_mut(), cs, &runs, n * rs, &mut m)?;
                let main = self.record_buf(n)?;
                if apply_fixup(&mut m, b"FILE").is_err() || m[..le32(&main, 24) as usize] != main[..le32(&main, 24) as usize] {
                    rep.bad_chains += 1;
                    rep.issue(format!("$MFTMirr record {n} differs from $MFT"));
                }
            }
        }
        let mut seen = vec![0u8; bm.len()];
        let mut dirs = Vec::new();
        let mut names: Vec<(u64, u64, Vec<u8>)> = Vec::new(); // (parent, record, key)
        let mut seqs: HashMap<u64, u16> = HashMap::new();
        for n in 0..records {
            let (valid, seq, in_use) = self.record_header(n)?;
            let marked = bit(&mftbm, n);
            if in_use && !marked {
                rep.bitmap_errors += 1;
                rep.issue(format!("record {n} in use but free in the MFT bitmap"));
            }
            if !in_use && marked && n >= FIRST_USER_RECORD && valid {
                rep.bitmap_errors += 1;
                rep.issue(format!("record {n} free but marked in the MFT bitmap"));
            }
            if !in_use {
                continue;
            }
            let rec = match self.read_rec(n) {
                Ok(r) => r,
                Err(e) => {
                    rep.bad_chains += 1;
                    rep.issue(format!("record {n}: {e}"));
                    continue;
                }
            };
            seqs.insert(n, seq);
            let base = le64(&rec.b, 32) & REF_MASK != 0;
            if le32(&rec.b, 24) as usize > rec.b.len() || le32(&rec.b, 24) % 8 != 0 {
                rep.bad_chains += 1;
                rep.issue(format!("record {n}: bad used size"));
            }
            let mut insts = HashSet::new();
            for (o, _) in rec.attrs() {
                if !insts.insert(le16(&rec.b, o + 14)) {
                    rep.bad_chains += 1;
                    rep.issue(format!("record {n}: attribute instance used twice"));
                }
                if le16(&rec.b, o + 14) >= le16(&rec.b, 40) && !base {
                    rep.bad_chains += 1;
                    rep.issue(format!("record {n}: attribute instance not below the next free one"));
                }
                if rec.resident(o) {
                    continue;
                }
                let runs = match rec.runs(o) {
                    Ok(r) => r,
                    Err(e) => {
                        rep.bad_chains += 1;
                        rep.issue(format!("record {n}: {e}"));
                        continue;
                    }
                };
                let clusters: u64 = runs.iter().map(|r| r.len).sum();
                let first = le64(&rec.b, o + 0x10);
                if first == 0 && le64(&rec.b, o + 0x28) != clusters * cs && le16(&rec.b, o + 12) & (FLAG_COMPRESSED | 0x8000) == 0 && rec.find(AT_ATTRIBUTE_LIST, &[]).is_none() {
                    rep.size_mismatches += 1;
                    rep.issue(format!("record {n}: allocated size of attribute {:#x} differs from its runs", rec.ty(o)));
                }
                for r in runs {
                    let Some(lcn) = r.lcn else { continue };
                    if lcn + r.len > total {
                        rep.bad_chains += 1;
                        rep.issue(format!("record {n}: run beyond the volume"));
                        continue;
                    }
                    for c in lcn..lcn + r.len {
                        if bit(&seen, c) {
                            rep.cross_linked += 1;
                            if rep.cross_linked < 5 {
                                rep.issue(format!("record {n}: cluster {c} used twice"));
                            }
                        }
                        seen[(c / 8) as usize] |= 1 << (c % 8);
                        if !bit(&bm, c) {
                            rep.bitmap_errors += 1;
                            if rep.bitmap_errors < 5 {
                                rep.issue(format!("record {n}: cluster {c} in use but free in $Bitmap"));
                            }
                        }
                    }
                }
            }
            if base {
                let owner = le64(&rec.b, 32) & REF_MASK;
                for o in rec.all(AT_FILE_NAME) {
                    let v = rec.value(o).to_vec();
                    if v.len() >= 66 {
                        names.push((le64(&v, 0) & REF_MASK, owner, v));
                    }
                }
                continue;
            }
            if rec.flags() & REC_DIRECTORY != 0 {
                dirs.push(n);
                rep.dirs += 1;
            } else if n >= FIRST_USER_RECORD {
                rep.files += 1;
            }
            let listed = rec.find(AT_ATTRIBUTE_LIST, &[]).is_some();
            let mut links = 0;
            for o in rec.all(AT_FILE_NAME) {
                let v = rec.value(o).to_vec();
                if v.len() < 66 {
                    continue;
                }
                links += 1;
                if rec.b[o + 22] & 1 == 0 {
                    rep.bad_chains += 1;
                    rep.issue(format!("record {n}: file name not flagged as indexed"));
                }
                names.push((le64(&v, 0) & REF_MASK, n, v));
            }
            // Every name counts, a DOS short name too; with an attribute
            // list some names may live in extension records.
            if (links != rec.links() as usize && !listed || links > rec.links() as usize) && n >= FIRST_USER_RECORD {
                rep.bad_chains += 1;
                rep.issue(format!("record {n}: link count {} but {links} names", rec.links()));
            }
            if let Some(d) = rec.find(AT_DATA, &[]) {
                rep.used_bytes += if rec.resident(d) { rec.value(d).len() as u64 } else { le64(&rec.b, d + 0x30) };
            }
        }
        for c in 0..total {
            if bit(&bm, c) && !bit(&seen, c) {
                rep.lost_clusters += 1;
            }
        }
        if rep.lost_clusters > 0 {
            rep.issue(format!("{} clusters marked used that nothing refers to", rep.lost_clusters));
        }
        let mut indexed: HashSet<(u64, u64, Vec<u16>)> = HashSet::new();
        for d in dirs {
            let Some(w) = self.walk_index(d, &mut rep)? else { continue };
            for (file_ref, key) in w.entries {
                let n = file_ref & REF_MASK;
                match seqs.get(&n) {
                    None => {
                        rep.bad_chains += 1;
                        rep.issue(format!("folder record {d}: entry for free record {n}"));
                    }
                    Some(&s) if s != (file_ref >> 48) as u16 => {
                        rep.bad_chains += 1;
                        rep.issue(format!("folder record {d}: entry for record {n} with an old sequence number"));
                    }
                    _ => {}
                }
                if le64(&key, 0) & REF_MASK != d {
                    rep.bad_chains += 1;
                    rep.issue(format!("folder record {d}: entry whose name says another parent"));
                }
                indexed.insert((d, n, units_of(fn_name(&key)).collect()));
            }
        }
        for (parent, n, key) in names {
            if n == ROOT && parent == ROOT {
                continue;
            }
            if !indexed.contains(&(parent, n, units_of(fn_name(&key)).collect())) {
                rep.bad_chains += 1;
                rep.issue(format!("record {n}: name {:?} missing from folder record {parent}", String::from_utf16_lossy(&units_of(fn_name(&key)).collect::<Vec<u16>>())));
            }
        }
        Ok(rep)
    }
}

// ---------------------------------------------------------- test helpers

/// Gives a file an object id the way Windows' link tracking does: the
/// attribute in its record and an entry in $ObjId:$O.
#[cfg(test)]
pub(super) fn test_add_object_id(fs: &mut Ntfs, record: u64, seq: u16, objid: u64, oid: &[u8]) -> Result<()> {
    fs.begin()?;
    let mut r = fs.read_rec(record)?;
    r.insert(resident(AT_OBJECT_ID, &[], oid, false), None)?;
    fs.write_rec(&r)?;
    let mut ix = fs.load_ix(objid, &O_NAME)?;
    let mut bytes = vec![0u8; 88];
    put_le16(&mut bytes, 0, 32);
    put_le16(&mut bytes, 2, 56);
    put_le16(&mut bytes, 10, 16);
    bytes[16..32].copy_from_slice(oid);
    put_le64(&mut bytes, 32, record | (seq as u64) << 48);
    fs.ix_insert(&mut ix, Ent { bytes, child: None, end: false })?;
    fs.ix_commit(&mut ix)?;
    fs.finish()
}

#[cfg(test)]
pub(super) fn test_has_object_id(fs: &mut Ntfs, objid: u64, oid: &[u8]) -> Result<bool> {
    let mut ix = fs.load_ix(objid, &O_NAME)?;
    Ok(fs.ix_all(&mut ix)?.iter().any(|e| e.key() == oid))
}

/// Moves a folder's $INDEX_ALLOCATION and $BITMAP into an extension record
/// behind an attribute list, as Windows does when a folder's record fills.
#[cfg(test)]
pub(super) fn test_move_index_out(fs: &mut Ntfs, dir: u64) -> Result<u64> {
    fs.begin()?;
    let mut base = fs.read_rec(dir)?;
    let base_ref = dir | (base.seq() as u64) << 48;
    let (n, seq) = fs.alloc_record()?;
    let mut ext = Rec::fresh(n, fs.record_size, seq, REC_IN_USE);
    put_le64(&mut ext.b, 32, base_ref);
    let mut ents: Vec<ListEnt> = base
        .attrs()
        .into_iter()
        .map(|(o, _)| ListEnt { ty: base.ty(o), name: base.name(o), vcn: if base.resident(o) { 0 } else { le64(&base.b, o + 0x10) }, file_ref: base_ref, inst: le16(&base.b, o + 14) })
        .collect();
    let mut top = 0;
    for ty in [AT_INDEX_ALLOCATION, AT_BITMAP] {
        let o = base.find(ty, &I30_NAME).ok_or(Error::NotFound)?;
        let len = le32(&base.b, o + 4) as usize;
        let bytes = base.b[o..o + len].to_vec();
        let inst = le16(&bytes, 14);
        base.remove(o);
        ext.insert(bytes, Some(inst))?;
        top = top.max(inst + 1);
        for e in ents.iter_mut().filter(|e| e.ty == ty) {
            e.file_ref = n | (seq as u64) << 48;
        }
    }
    put_le16(&mut ext.b, 40, top);
    base.insert(resident(AT_ATTRIBUTE_LIST, &[], &list_bytes(&ents), false), None)?;
    fs.write_rec(&ext)?;
    fs.write_rec(&base)?;
    fs.finish()?;
    Ok(n)
}

#[cfg(test)]
impl Ntfs {
    /// Attribute types of a record.
    pub(super) fn read_rec_for_test(&mut self, n: u64) -> Vec<u32> {
        let r = self.read_rec(n).unwrap();
        r.attrs().into_iter().map(|(o, _)| r.ty(o)).collect()
    }

    pub(super) fn st_for_test_rec_used(&mut self, n: u64) -> bool {
        self.st().unwrap().rec_used(n)
    }
}
