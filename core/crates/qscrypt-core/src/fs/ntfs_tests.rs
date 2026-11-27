//! NTFS writing on volumes made by mkntfs (stored sparse in testdata):
//! 4 KiB clusters, and 1 KiB clusters with index blocks spanning several.

use super::write::*;
use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const MKNTFS_4K: &[u8] = include_bytes!("../../../../testdata/ntfs_mkntfs_4k.qsparse");
const MKNTFS_1K: &[u8] = include_bytes!("../../../../testdata/ntfs_mkntfs_1k.qsparse");

#[derive(Clone)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Disk for Shared {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let d = self.0.lock().unwrap();
        let o = offset as usize;
        if o + buf.len() > d.len() {
            return Err(Error::invalid("oob"));
        }
        buf.copy_from_slice(&d[o..o + buf.len()]);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        let o = offset as usize;
        if o + buf.len() > d.len() {
            return Err(Error::invalid("oob"));
        }
        d[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }
}

/// Expands a fixture: (offset, length, kind) segments, kind 0 = bytes
/// follow, 1 = all 0xFF; everything else is zero.
fn fixture(b: &[u8]) -> Shared {
    assert_eq!(&b[..8], b"QSPARSE1");
    let total = le64(b, 8) as usize;
    let mut v = vec![0u8; total];
    let mut p = 16;
    loop {
        let off = le64(b, p) as usize;
        let len = le32(b, p + 8) as usize;
        let kind = b[p + 12];
        p += 13;
        if len == 0 {
            break;
        }
        if kind == 0 {
            v[off..off + len].copy_from_slice(&b[p..p + len]);
            p += len;
        } else {
            v[off..off + len].fill(0xFF);
        }
    }
    Shared(Arc::new(Mutex::new(v)))
}

fn rw(d: &Shared) -> Ntfs {
    let fs = Ntfs::mount(Box::new(d.clone()), false).unwrap();
    assert!(!fs.read_only(), "opened read-only: {:?}", fs.read_only_reason());
    fs
}

fn put(fs: &mut Ntfs, path: &str, data: &[u8]) {
    fs.write_file(path, &mut &data[..], data.len() as u64, false, &mut |_| true).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn get(fs: &mut Ntfs, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_file(path, &mut out, &mut |_| true).unwrap_or_else(|e| panic!("read {path}: {e}"));
    out
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(seed) >> 13) as u8).collect()
}

fn clean(fs: &mut Ntfs, when: &str) {
    let r = fs.check(false).unwrap();
    assert!(r.clean(), "{when}: {r:#?}");
}

/// Every file under `dir` with its content, read through the file system.
fn tree(fs: &mut Ntfs, dir: &str, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
    for e in fs.list(dir).unwrap() {
        let p = if dir == "/" { format!("/{}", e.name) } else { format!("{dir}/{}", e.name) };
        if e.is_dir {
            out.insert(p.clone(), None);
            tree(fs, &p, out);
        } else {
            let c = get(fs, &p);
            assert_eq!(c.len() as u64, e.size, "{p}");
            out.insert(p, Some(c));
        }
    }
}

fn exercise(d: &Shared) {
    let mut fs = rw(d);
    assert_eq!(fs.kind(), "NTFS");
    let free0 = fs.free_bytes().unwrap();
    let mut model: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let long = format!("/{}.txt", "طويل-".repeat(50)); // 254 UTF-16 units
    let files: Vec<(String, Vec<u8>)> = vec![
        ("/empty.bin".into(), vec![]),
        ("/one.bin".into(), data(1, 1)),
        ("/README.TXT".into(), data(511, 2)),
        ("/exact.bin".into(), data(4096, 3)),
        ("/صورة الهوية.jpg".into(), data(70_001, 4)),
        (long.clone(), data(1234, 5)),
        ("/Mixed Case Name.Document".into(), data(10, 6)),
    ];
    for (p, c) in &files {
        put(&mut fs, p, c);
        model.insert(p.clone(), Some(c.clone()));
    }
    fs.flush().unwrap();
    drop(fs);

    let mut fs = rw(d);
    for (p, c) in &files {
        assert_eq!(&get(&mut fs, p), c, "{p}");
    }
    assert_eq!(get(&mut fs, "/readme.txt"), files[2].1, "names are case-insensitive");
    let mut buf = vec![0u8; 5000];
    let n = fs.read_range("/صورة الهوية.jpg", 66_000, &mut buf).unwrap();
    assert_eq!(&buf[..n], &files[4].1[66_000..]);
    assert!(matches!(fs.write_file("/one.BIN", &mut &b"x"[..], 1, false, &mut |_| true), Err(Error::AlreadyExists)));
    clean(&mut fs, "files");

    // A folder big enough for a B-tree of several levels.
    fs.mkdir("/a").unwrap();
    fs.mkdir("/a/b").unwrap();
    assert!(matches!(fs.mkdir("/A"), Err(Error::AlreadyExists)));
    model.insert("/a".into(), None);
    model.insert("/a/b".into(), None);
    for i in (0..700).rev() {
        let p = format!("/a/b/file number {:04} ملف.dat", (i * 7919) % 700);
        let c = data(i % 50 * 37, i as u32);
        put(&mut fs, &p, &c);
        model.insert(p, Some(c));
    }
    fs.flush().unwrap();
    drop(fs);
    let mut fs = rw(d);
    assert_eq!(fs.list("/a/b").unwrap().len(), 700);
    clean(&mut fs, "big folder");

    // Overwrite, rename (longer, case only), move, delete half the folder.
    fs.write_file("/one.bin", &mut &b"replaced"[..], 8, true, &mut |_| true).unwrap();
    model.insert("/one.bin".into(), Some(b"replaced".to_vec()));
    fs.rename("/README.TXT", "اقرأني — a much longer name than before.txt").unwrap();
    let v = model.remove("/README.TXT").unwrap();
    model.insert("/اقرأني — a much longer name than before.txt".into(), v);
    fs.rename("/exact.bin", "EXACT.bin").unwrap();
    let v = model.remove("/exact.bin").unwrap();
    model.insert("/EXACT.bin".into(), v);
    fs.move_item(&long, "/a").unwrap();
    let v = model.remove(&long).unwrap();
    model.insert(format!("/a{long}"), v);
    for i in (0..700).filter(|i| i % 3 != 1) {
        let p = format!("/a/b/file number {i:04} ملف.dat");
        fs.remove(&p).unwrap_or_else(|e| panic!("remove {p}: {e}"));
        model.remove(&p);
    }
    fs.mkdir("/c").unwrap();
    fs.move_item("/a/b", "/c").unwrap();
    let moved: Vec<_> = model.keys().filter(|k| k.starts_with("/a/b")).cloned().collect();
    for k in moved {
        let v = model.remove(&k).unwrap();
        model.insert(format!("/c/b{}", &k[4..]), v);
    }
    model.insert("/c".into(), None);
    assert!(matches!(fs.move_item("/c", "/c/b"), Err(Error::InvalidArgument(_))));
    fs.flush().unwrap();
    drop(fs);
    let mut fs = rw(d);
    let mut got = BTreeMap::new();
    tree(&mut fs, "/", &mut got);
    assert_eq!(got.keys().collect::<Vec<_>>(), model.keys().collect::<Vec<_>>());
    assert!(got == model, "contents differ");
    clean(&mut fs, "changes");

    // Everything goes; the volume opens writable again (dirty flag cleared).
    for top in ["/a", "/c", "/one.bin", "/empty.bin", "/EXACT.bin", "/صورة الهوية.jpg", "/Mixed Case Name.Document", "/اقرأني — a much longer name than before.txt"] {
        fs.remove(top).unwrap_or_else(|e| panic!("remove {top}: {e}"));
    }
    assert!(fs.list("/").unwrap().is_empty());
    fs.flush().unwrap();
    drop(fs);
    let mut fs = rw(d);
    clean(&mut fs, "emptied");
    let free1 = fs.free_bytes().unwrap();
    // Only the $MFT, which never shrinks, may keep what it grew by.
    assert!(free1 <= free0 && free0 - free1 <= 1 << 20, "{free0} -> {free1}");

    // Errors leave no trace.
    assert!(matches!(fs.stat("/missing"), Err(Error::NotFound)));
    assert!(matches!(fs.write_file("/bad|name", &mut &b""[..], 0, false, &mut |_| true), Err(Error::InvalidName)));
    put(&mut fs, "/f", b"1");
    assert!(matches!(fs.list("/f"), Err(Error::NotADirectory)));
    assert!(matches!(fs.write_file("/x", &mut &b"ab"[..], 5000, false, &mut |_| true), Err(Error::Io(_))));
    assert!(matches!(fs.stat("/x"), Err(Error::NotFound)));
    let big = data(3_000_000, 9);
    let before = fs.free_bytes().unwrap();
    let mut calls = 0;
    let r = fs.write_file("/c", &mut big.as_slice(), big.len() as u64, false, &mut |_| {
        calls += 1;
        calls < 2
    });
    assert!(matches!(r, Err(Error::Cancelled)));
    assert!(matches!(fs.stat("/c"), Err(Error::NotFound)));
    assert_eq!(fs.free_bytes().unwrap(), before);
    clean(&mut fs, "after errors");
    fs.flush().unwrap();
}

#[test]
fn ntfs_full_cycle_4k_clusters() {
    exercise(&fixture(MKNTFS_4K));
}

#[test]
fn ntfs_full_cycle_1k_clusters() {
    exercise(&fixture(MKNTFS_1K));
}

#[test]
fn ntfs_interrupted_session_needs_chkdsk() {
    let d = fixture(MKNTFS_4K);
    let mut fs = rw(&d);
    put(&mut fs, "/written.txt", b"before the cable came out");
    drop(fs); // no flush: the dirty flag stays
    let fs = Ntfs::mount(Box::new(d.clone()), false).unwrap();
    assert!(fs.read_only());
    assert!(fs.read_only_reason().unwrap().contains("chkdsk"));
    let mut ro = Ntfs::mount(Box::new(d.clone()), true).unwrap();
    assert_eq!(get(&mut ro, "/written.txt"), b"before the cable came out");
    // The journal was blanked before the first change.
    let log = ro.stream(MFT_RECORD_LOGFILE, AT_DATA, &[]).unwrap();
    let mut head = vec![0u8; 8192];
    ro.read_stream(&log, 0, &mut head).unwrap();
    assert!(head.iter().all(|&b| b == 0xFF));
}

#[test]
fn ntfs_journal_in_use_stays_read_only() {
    let d = fixture(MKNTFS_4K);
    let mut fs = Ntfs::mount(Box::new(d.clone()), true).unwrap();
    let Stream::NonResident { runs, .. } = fs.stream(MFT_RECORD_LOGFILE, AT_DATA, &[]).unwrap() else { panic!() };
    let at = runs[0].lcn.unwrap() * fs.cluster_size;
    // A restart page with a client in use and no "clean" flag.
    let mut page = vec![0u8; 4096];
    page[..4].copy_from_slice(b"RSTR");
    put_le16(&mut page, 0x18, 0x30);
    put_le16(&mut page, 0x30 + 0x0C, 0);
    put_le16(&mut page, 0x30 + 0x0E, 0);
    for off in [at, at + 4096] {
        d.clone().write_at(off, &page).unwrap();
    }
    let fs = Ntfs::mount(Box::new(d.clone()), false).unwrap();
    assert!(fs.read_only());
    assert!(fs.read_only_reason().unwrap().contains("did not close"), "{:?}", fs.read_only_reason());
    // Marked clean, it opens writable.
    put_le16(&mut page, 0x30 + 0x0E, 0x0002);
    for off in [at, at + 4096] {
        d.clone().write_at(off, &page).unwrap();
    }
    assert!(!Ntfs::mount(Box::new(d.clone()), false).unwrap().read_only());
}

#[test]
fn ntfs_reserved_range_is_avoided() {
    let d = fixture(MKNTFS_4K);
    let mut fs = rw(&d);
    let total = fs.total_bytes();
    let free = fs.free_bytes().unwrap();
    // Protect the second half of the volume, as for a hidden volume.
    fs.reserve(total / 2, total);
    let left = fs.free_bytes().unwrap();
    assert!(left < free);
    let c = data(200_000, 3);
    put(&mut fs, "/kept.bin", &c);
    for (off, len) in fs.extents("/kept.bin").unwrap() {
        assert!(off + len <= total / 2, "allocated inside the reserved range");
    }
    let too_big = vec![0u8; (left + 4096) as usize];
    assert!(matches!(fs.write_file("/big", &mut too_big.as_slice(), too_big.len() as u64, false, &mut |_| true), Err(Error::NoSpace)));
    clean(&mut fs, "reserved");
    fs.flush().unwrap();
}

#[test]
fn ntfs_object_ids_leave_with_their_file() {
    let d = fixture(MKNTFS_4K);
    let mut fs = rw(&d);
    put(&mut fs, "/tracked.doc", &data(9000, 1));
    let it = fs.resolve("/tracked.doc").unwrap();
    let oid: Vec<u8> = (0..16).map(|i| 0xA0 + i as u8).collect();
    let objid = fs.lookup(MFT_RECORD_EXTEND, "$ObjId").unwrap().expect("mkntfs makes $ObjId");
    // Give the file an object id, as Windows' link tracking does.
    test_add_object_id(&mut fs, it.record, it.seq, objid.record, &oid).unwrap();
    assert!(test_has_object_id(&mut fs, objid.record, &oid).unwrap());
    fs.remove("/tracked.doc").unwrap();
    assert!(!test_has_object_id(&mut fs, objid.record, &oid).unwrap());
    clean(&mut fs, "object id");
    fs.flush().unwrap();
}

#[test]
fn ntfs_full_disk_is_a_clean_refusal() {
    let d = fixture(MKNTFS_4K);
    let mut fs = rw(&d);
    let mut n = 0;
    // Big files until the clusters run out, then tiny ones until the
    // records (and the room to grow the $MFT and the index) run out too.
    loop {
        let c = data(150_000, n);
        match fs.write_file(&format!("/big {n}.bin"), &mut c.as_slice(), c.len() as u64, false, &mut |_| true) {
            Ok(()) => n += 1,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("big {n}: {e}"),
        }
    }
    let mut m = 0;
    loop {
        let c = data(700 + (m as usize % 40) * 13, m);
        match fs.write_file(&format!("/tiny file with a fairly long name {m}.txt"), &mut c.as_slice(), c.len() as u64, false, &mut |_| true) {
            Ok(()) => m += 1,
            Err(Error::NoSpace) | Err(Error::Unsupported(_)) => break,
            Err(e) => panic!("tiny {m}: {e}"),
        }
        assert!(m < 100_000);
    }
    assert!(n > 10 && m > 0, "{n} big, {m} tiny");
    clean(&mut fs, "full");
    fs.flush().unwrap();
    drop(fs);
    // The refusals did not leave the volume marked for chkdsk.
    let mut fs = rw(&d);
    for i in 0..n / 2 {
        fs.remove(&format!("/big {i}.bin")).unwrap();
    }
    put(&mut fs, "/after.bin", &data(400_000, 77));
    assert_eq!(get(&mut fs, "/after.bin"), data(400_000, 77));
    assert_eq!(get(&mut fs, &format!("/big {}.bin", n - 1)), data(150_000, n - 1));
    clean(&mut fs, "after freeing");
    fs.flush().unwrap();
}

#[test]
fn ntfs_folder_with_an_attribute_list() {
    let d = fixture(MKNTFS_4K);
    let mut fs = rw(&d);
    fs.mkdir("/big").unwrap();
    let mut model = BTreeMap::new();
    for i in 0..300 {
        let p = format!("/big/entry {i:03} with a name.txt");
        let c = data(i * 3, i as u32);
        put(&mut fs, &p, &c);
        model.insert(p, Some(c));
    }
    let dir = fs.resolve("/big").unwrap();
    let ext = test_move_index_out(&mut fs, dir.record).unwrap();
    assert!(fs.read_rec_for_test(dir.record).contains(&AT_ATTRIBUTE_LIST));
    clean(&mut fs, "moved out");
    // Changes inside: the allocation is edited in the extension record.
    for i in 300..700 {
        let p = format!("/big/entry {i:03} with a name.txt");
        let c = data(i % 90, i as u32);
        put(&mut fs, &p, &c);
        model.insert(p, Some(c));
    }
    for i in (0..700).step_by(2) {
        let p = format!("/big/entry {i:03} with a name.txt");
        fs.remove(&p).unwrap();
        model.remove(&p);
    }
    fs.rename("/big/entry 001 with a name.txt", "renamed inside.txt").unwrap();
    let v = model.remove("/big/entry 001 with a name.txt").unwrap();
    model.insert("/big/renamed inside.txt".into(), v);
    clean(&mut fs, "changed inside");
    // The folder itself renamed: its attribute list follows.
    fs.rename("/big", "a new name for the big folder").unwrap();
    let mut got = BTreeMap::new();
    tree(&mut fs, "/a new name for the big folder", &mut got);
    let want: BTreeMap<String, Option<Vec<u8>>> = model.into_iter().map(|(k, v)| (format!("/a new name for the big folder{}", &k[4..]), v)).collect();
    assert!(got == want, "contents differ");
    clean(&mut fs, "folder renamed");
    fs.flush().unwrap();
    drop(fs);
    let mut fs = rw(&d);
    // Gone with its extension record.
    fs.remove("/a new name for the big folder").unwrap();
    assert!(!fs.st_for_test_rec_used(ext));
    clean(&mut fs, "removed");
    fs.flush().unwrap();
}
