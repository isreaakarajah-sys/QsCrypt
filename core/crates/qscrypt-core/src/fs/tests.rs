//! File-system tests on plain in-memory images.

use super::fat_format::format_plan_fat32;
use super::*;
use crate::disk::MemDisk;
use std::sync::{Arc, Mutex};

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

fn image(size: usize, plan: FatPlan) -> Shared {
    let mut d = MemDisk::new(size);
    apply_patches(&plan.patches, 0, &mut d.data);
    Shared(Arc::new(Mutex::new(d.data)))
}

fn fat_image(size: usize) -> Shared {
    image(size, format_plan(size as u64, "TEST VOL", 0xCAFE).unwrap())
}

fn fs_of(d: &Shared) -> Box<dyn FileSystem> {
    mount(Box::new(d.clone()), false, 0).unwrap()
}

fn put(fs: &mut Box<dyn FileSystem>, path: &str, data: &[u8]) {
    fs.write_file(path, &mut &data[..], data.len() as u64, false, &mut |_| true).unwrap();
}

fn get(fs: &mut Box<dyn FileSystem>, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_file(path, &mut out, &mut |_| true).unwrap();
    out
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(seed) >> 13) as u8).collect()
}

#[test]
fn plan_types_by_size() {
    assert_eq!(format_plan(3 << 20, "", 1).unwrap().fat_type, "FAT12");
    assert_eq!(format_plan(20 << 20, "", 1).unwrap().fat_type, "FAT16");
    assert_eq!(format_plan(200 << 20, "", 1).unwrap().fat_type, "FAT16");
    assert_eq!(format_plan(600 << 20, "", 1).unwrap().fat_type, "FAT32");
    assert_eq!(format_plan(64 << 30, "", 1).unwrap().fat_type, "FAT32");
    assert_eq!(format_plan(64 << 30, "", 1).unwrap().cluster_size, 32768);
}

fn exercise(d: &Shared, expect_kind: &str, fixed_root: bool) {
    exercise_with(d, expect_kind, fixed_root, true)
}

fn exercise_with(d: &Shared, expect_kind: &str, fixed_root: bool, short_names: bool) {
    let mut fs = fs_of(d);
    assert_eq!(fs.kind(), expect_kind);
    assert_eq!(fs.label(), "TEST VOL");
    let free0 = fs.free_bytes().unwrap();
    assert!(free0 > 0 && free0 <= fs.total_bytes());

    // Sizes around cluster boundaries, empty files, long and Arabic names.
    let long_name = format!("{}.txt", "طويل-".repeat(40)); // > 200 UTF-16 units
    let files: Vec<(String, Vec<u8>)> = vec![
        ("/empty.bin".into(), vec![]),
        ("/one.bin".into(), data(1, 1)),
        ("/README.TXT".into(), data(511, 2)),
        ("/exact.bin".into(), data(4096, 3)),
        ("/صورة الهوية.jpg".into(), data(70_001, 4)),
        (format!("/{long_name}"), data(1234, 5)),
        ("/Mixed Case Name.Document".into(), data(10, 6)),
    ];
    for (p, c) in &files {
        put(&mut fs, p, c);
    }
    fs.flush().unwrap();
    drop(fs);

    let mut fs = fs_of(d);
    for (p, c) in &files {
        assert_eq!(&get(&mut fs, p), c, "{p}");
        assert_eq!(fs.stat(p).unwrap().size, c.len() as u64);
    }
    // Case-insensitive lookup and 8.3 aliases.
    assert_eq!(get(&mut fs, "/readme.txt"), files[2].1);
    if short_names {
        assert_eq!(get(&mut fs, "/MIXEDC~1.DOC"), files[6].1);
    }
    let names: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
    assert!(names.contains(&long_name), "{names:?}");

    // Random access.
    let mut buf = vec![0u8; 5000];
    let n = fs.read_range("/صورة الهوية.jpg", 66_000, &mut buf).unwrap();
    assert_eq!(n, 4001);
    assert_eq!(&buf[..n], &files[4].1[66_000..]);

    // Directories, nesting, growth beyond one cluster.
    fs.mkdir("/a").unwrap();
    fs.mkdir("/a/b").unwrap();
    assert!(matches!(fs.mkdir("/a"), Err(Error::AlreadyExists)));
    for i in 0..150 {
        put(&mut fs, &format!("/a/b/file number {i:03}.dat"), &data(i * 10, i as u32));
    }
    drop(fs);
    let mut fs = fs_of(d);
    let listing = fs.list("/a/b").unwrap();
    assert_eq!(listing.len(), 150);
    for i in [0usize, 77, 149] {
        assert_eq!(get(&mut fs, &format!("/a/b/file number {i:03}.dat")), data(i * 10, i as u32));
    }
    assert!(fs.list("/a").unwrap().iter().any(|e| e.name == "b" && e.is_dir));

    // Overwrite, rename, delete.
    assert!(matches!(fs.write_file("/one.bin", &mut &b"x"[..], 1, false, &mut |_| true), Err(Error::AlreadyExists)));
    fs.write_file("/one.bin", &mut &b"replaced"[..], 8, true, &mut |_| true).unwrap();
    assert_eq!(get(&mut fs, "/one.bin"), b"replaced");
    fs.rename("/README.TXT", "اقرأني.txt").unwrap();
    assert!(matches!(fs.stat("/README.TXT"), Err(Error::NotFound)));
    assert_eq!(get(&mut fs, "/اقرأني.txt"), files[2].1);
    fs.rename("/a", "renamed dir").unwrap();
    assert_eq!(fs.list("/renamed dir/b").unwrap().len(), 150);
    fs.remove("/renamed dir").unwrap();
    assert!(matches!(fs.stat("/renamed dir"), Err(Error::NotFound)));
    for (p, _) in &files {
        if p != "/README.TXT" && p != "/one.bin" {
            fs.remove(p).unwrap();
        }
    }
    fs.remove("/one.bin").unwrap();
    fs.remove("/اقرأني.txt").unwrap();
    assert!(fs.list("/").unwrap().is_empty());
    fs.flush().unwrap();
    drop(fs);

    // Everything freed, and the image still mounts cleanly.
    let mut fs = fs_of(d);
    let free1 = fs.free_bytes().unwrap();
    if fixed_root {
        assert_eq!(free1, free0);
    } else {
        // A FAT32 root that grew keeps its clusters; nothing else may leak.
        assert!(free1 <= free0 && free0 - free1 <= 4 * 4096, "{free0} -> {free1}");
    }
    assert!(fs.list("/").unwrap().is_empty());

    // Errors.
    assert!(matches!(fs.stat("/missing"), Err(Error::NotFound)));
    assert!(matches!(fs.write_file("/bad|name", &mut &b""[..], 0, false, &mut |_| true), Err(Error::InvalidName)));
    put(&mut fs, "/f", b"1");
    assert!(matches!(fs.list("/f"), Err(Error::NotADirectory)));
    assert!(matches!(fs.write_file("/x", &mut &b"ab"[..], 5, false, &mut |_| true), Err(Error::Io(_))));
    // A failed write leaves no trace.
    assert!(matches!(fs.stat("/x"), Err(Error::NotFound)));
    let mut cancelled = 0;
    let big = data(300_000, 9);
    let r = fs.write_file("/c", &mut big.as_slice(), big.len() as u64, false, &mut |_| {
        cancelled += 1;
        cancelled < 2
    });
    assert!(matches!(r, Err(Error::Cancelled)) || r.is_ok());
}

#[test]
fn fat12_full_cycle() {
    exercise(&fat_image(3 << 20), "FAT12", true);
}

#[test]
fn fat16_full_cycle() {
    exercise(&fat_image(24 << 20), "FAT16", true);
}

#[test]
fn fat32_full_cycle() {
    let size = 40 << 20;
    exercise(&image(size, format_plan_fat32(size as u64, "TEST VOL").unwrap()), "FAT32", false);
}

#[test]
fn fat32_root_grows() {
    let size = 40 << 20;
    let d = image(size, format_plan_fat32(size as u64, "").unwrap());
    let mut fs = fs_of(&d);
    for i in 0..60 {
        put(&mut fs, &format!("/root entry with a long name {i}.txt"), &[i as u8]);
    }
    drop(fs);
    let mut fs = fs_of(&d);
    assert_eq!(fs.list("/").unwrap().len(), 60);
    assert_eq!(get(&mut fs, "/root entry with a long name 59.txt"), vec![59u8]);
}

#[test]
fn fat16_fixed_root_fills_up() {
    let d = fat_image(24 << 20);
    let mut fs = fs_of(&d);
    let mut made = 0;
    loop {
        // 8.3 names: one entry each; 512 root slots minus the volume label.
        match fs.write_file(&format!("/F{made}.TXT"), &mut &b""[..], 0, false, &mut |_| true) {
            Ok(()) => made += 1,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(made, 511);
}

#[test]
fn no_space_is_reported() {
    let d = fat_image(3 << 20);
    let mut fs = fs_of(&d);
    let free = fs.free_bytes().unwrap();
    let big = vec![0u8; free as usize + 1];
    assert!(matches!(fs.write_file("/big", &mut big.as_slice(), big.len() as u64, false, &mut |_| true), Err(Error::NoSpace)));
    assert_eq!(fs.free_bytes().unwrap(), free);
}

#[test]
fn rejects_unknown_and_unsupported() {
    let d = Shared(Arc::new(Mutex::new(vec![0u8; 1 << 20])));
    assert!(matches!(mount(Box::new(d.clone()), false, 0), Err(Error::Corrupt(_))));
    let mut ntfs = vec![0u8; 1 << 20];
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    assert!(matches!(mount(Box::new(Shared(Arc::new(Mutex::new(ntfs)))), false, 0), Err(Error::Corrupt(_))));
    let mut refs = vec![0u8; 1 << 20];
    refs[3..7].copy_from_slice(b"ReFS");
    assert!(matches!(mount(Box::new(Shared(Arc::new(Mutex::new(refs)))), false, 0), Err(Error::Unsupported(_))));
}

// ------------------------------------------------------------ exFAT

/// Builds a tiny exFAT image by hand (independent of the reader).
fn exfat_image() -> Shared {
    let bps = 512usize;
    let cluster = 4096usize;
    let heap_sector = 64usize;
    let clusters = 256usize;
    let size = heap_sector * bps + clusters * cluster;
    let mut img = vec![0u8; size];
    let b = &mut img[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[72..80].copy_from_slice(&((size / bps) as u64).to_le_bytes());
    b[80..84].copy_from_slice(&24u32.to_le_bytes()); // FAT at sector 24
    b[84..88].copy_from_slice(&8u32.to_le_bytes());
    b[88..92].copy_from_slice(&(heap_sector as u32).to_le_bytes());
    b[92..96].copy_from_slice(&(clusters as u32).to_le_bytes());
    b[96..100].copy_from_slice(&4u32.to_le_bytes()); // root at cluster 4
    b[108] = 9;
    b[109] = 3;
    b[110] = 1;
    b[510] = 0x55;
    b[511] = 0xAA;
    let fat_off = 24 * bps;
    let set_fat = |img: &mut Vec<u8>, c: usize, v: u32| img[fat_off + c * 4..fat_off + c * 4 + 4].copy_from_slice(&v.to_le_bytes());
    set_fat(&mut img, 0, 0xFFFF_FFF8);
    set_fat(&mut img, 1, 0xFFFF_FFFF);
    set_fat(&mut img, 2, 0xFFFF_FFFF); // bitmap
    set_fat(&mut img, 4, 0xFFFF_FFFF); // root
    // fragmented file: clusters 6 -> 9 -> 7
    set_fat(&mut img, 6, 9);
    set_fat(&mut img, 9, 7);
    set_fat(&mut img, 7, 0xFFFF_FFFF);
    set_fat(&mut img, 10, 0xFFFF_FFFF); // subdir
    let coff = |c: usize| heap_sector * bps + (c - 2) * cluster;
    // bitmap: clusters 2..=12 used
    img[coff(2)] = 0xFF;
    img[coff(2) + 1] = 0x07;

    fn file_set(name: &str, attr: u16, first: u32, size: u64, valid: u64, contiguous: bool) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(15);
        let mut set = vec![0u8; 32 * (2 + names)];
        set[0] = 0x85;
        set[1] = (1 + names) as u8;
        set[4..6].copy_from_slice(&attr.to_le_bytes());
        // 2025-11-25 12:30:10 local, UTC+3 (12 x 15 min)
        let ts: u32 = (45 << 25) | (11 << 21) | (25 << 16) | (12 << 11) | (30 << 5) | 5;
        set[12..16].copy_from_slice(&ts.to_le_bytes());
        set[23] = 0x80 | 12;
        let s = &mut set[32..64];
        s[0] = 0xC0;
        s[1] = 0x01 | if contiguous { 0x02 } else { 0 };
        s[3] = units.len() as u8;
        s[8..16].copy_from_slice(&valid.to_le_bytes());
        s[20..24].copy_from_slice(&first.to_le_bytes());
        s[24..32].copy_from_slice(&size.to_le_bytes());
        for (k, u) in units.iter().enumerate() {
            let e = 64 + (k / 15) * 32;
            set[e] = 0xC1;
            let o = e + 2 + (k % 15) * 2;
            set[o..o + 2].copy_from_slice(&u.to_le_bytes());
        }
        let mut c: u16 = 0;
        for (i, &b) in set.iter().enumerate() {
            if i != 2 && i != 3 {
                c = (if c & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(c >> 1).wrapping_add(b as u16);
            }
        }
        set[2..4].copy_from_slice(&c.to_le_bytes());
        set
    }

    let mut root = Vec::new();
    let mut label = vec![0u8; 32];
    label[0] = 0x83;
    label[1] = 5;
    for (k, u) in "Vault".encode_utf16().enumerate() {
        label[2 + 2 * k..4 + 2 * k].copy_from_slice(&u.to_le_bytes());
    }
    root.extend(label);
    let mut bitmap = vec![0u8; 32];
    bitmap[0] = 0x81;
    bitmap[20..24].copy_from_slice(&2u32.to_le_bytes());
    bitmap[24..32].copy_from_slice(&32u64.to_le_bytes());
    root.extend(bitmap);
    root.extend(file_set("مستند طويل الاسم جداً للتجربة.txt", 0x20, 5, 3000, 3000, true));
    root.extend(file_set("fragmented.bin", 0x20, 6, 10_000, 9_000, false));
    root.extend(file_set("Sub", 0x10, 10, 4096, 4096, true));
    let deleted = {
        let mut s = file_set("deleted.txt", 0x20, 11, 10, 10, true);
        s[0] = 0x05;
        s
    };
    root.extend(deleted);
    let r = coff(4);
    img[r..r + root.len()].copy_from_slice(&root);
    let sub = file_set("inner.txt", 0x20, 12, 5, 5, true);
    img[coff(10)..coff(10) + sub.len()].copy_from_slice(&sub);
    img[coff(12)..coff(12) + 5].copy_from_slice(b"inner");

    for i in 0..3000 {
        img[coff(5) + i] = (i % 199) as u8;
    }
    let frag: Vec<usize> = vec![6, 9, 7];
    for i in 0..9000usize {
        img[coff(frag[i / cluster]) + i % cluster] = (i % 241) as u8 + 1;
    }
    Shared(Arc::new(Mutex::new(img)))
}

#[test]
fn exfat_reads() {
    let d = exfat_image();
    let mut fs = mount(Box::new(d), true, 0).unwrap();
    assert_eq!(fs.kind(), "exFAT");
    assert_eq!(fs.label(), "Vault");
    assert!(fs.read_only());
    let mut names: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec!["Sub", "fragmented.bin", "مستند طويل الاسم جداً للتجربة.txt"]);
    let long = get(&mut fs, "/مستند طويل الاسم جداً للتجربة.txt");
    assert!(long.iter().enumerate().all(|(i, &b)| b == (i % 199) as u8) && long.len() == 3000);
    let frag = get(&mut fs, "/FRAGMENTED.BIN");
    assert_eq!(frag.len(), 10_000);
    assert!(frag[..9000].iter().enumerate().all(|(i, &b)| b == (i % 241) as u8 + 1));
    assert!(frag[9000..].iter().all(|&b| b == 0), "beyond ValidDataLength reads as zeros");
    assert_eq!(get(&mut fs, "/Sub/inner.txt"), b"inner");
    let st = fs.stat("/Sub/inner.txt").unwrap();
    // 2025-11-25 12:30:10 at UTC+3 is 09:30:10 UTC.
    assert_eq!(st.modified, 1_764_063_010);
    assert_eq!(fs.free_bytes().unwrap(), (256 - 11) * 4096);
    let mut buf = [0u8; 10];
    assert_eq!(fs.read_range("/fragmented.bin", 4090, &mut buf).unwrap(), 10);
    assert_eq!(buf.to_vec(), (4090..4100).map(|i| (i % 241) as u8 + 1).collect::<Vec<u8>>());
    assert!(matches!(fs.mkdir("/x"), Err(Error::ReadOnly)));
}

#[test]
fn exfat_hand_image_writes() {
    let d = exfat_image();
    let mut fs = fs_of(&d);
    assert!(!fs.read_only());
    put(&mut fs, "/new file.txt", b"written by QsCrypt");
    fs.mkdir("/Sub/deeper").unwrap();
    put(&mut fs, "/Sub/deeper/x.bin", &data(9000, 3));
    fs.rename("/fragmented.bin", "renamed.bin").unwrap();
    drop(fs);
    let mut fs = fs_of(&d);
    assert_eq!(get(&mut fs, "/new file.txt"), b"written by QsCrypt");
    assert_eq!(get(&mut fs, "/Sub/deeper/x.bin"), data(9000, 3));
    assert_eq!(get(&mut fs, "/Sub/inner.txt"), b"inner");
    let frag = get(&mut fs, "/renamed.bin");
    assert!(frag[..9000].iter().enumerate().all(|(i, &b)| b == (i % 241) as u8 + 1));
    fs.remove("/renamed.bin").unwrap();
    assert!(matches!(fs.stat("/fragmented.bin"), Err(Error::NotFound)));
}

fn exfat_formatted(size: usize, cluster: u64) -> Shared {
    image(size, super::exfat_format::plan_with(size as u64, "TEST VOL", 0xBEEF, cluster).unwrap())
}

#[test]
fn exfat_full_cycle() {
    exercise_with(&exfat_formatted(8 << 20, 4096), "exFAT", false, false);
}

#[test]
fn exfat_small_clusters_and_growth() {
    // 512-byte clusters: directories grow cluster by cluster, files are
    // split into many runs once the volume is fragmented.
    let d = exfat_formatted(4 << 20, 512);
    let mut fs = fs_of(&d);
    let free0 = fs.free_bytes().unwrap();
    for i in 0..200 {
        put(&mut fs, &format!("/file with a fairly long name {i:03}.dat"), &data(700 + i * 3, i as u32));
    }
    for i in (0..200).step_by(2) {
        fs.remove(&format!("/file with a fairly long name {i:03}.dat")).unwrap();
    }
    let big = data(300_000, 77);
    put(&mut fs, "/big.bin", &big);
    drop(fs);
    let mut fs = fs_of(&d);
    assert_eq!(fs.list("/").unwrap().len(), 101);
    assert_eq!(get(&mut fs, "/big.bin"), big);
    for i in (1..200).step_by(2) {
        assert_eq!(get(&mut fs, &format!("/file with a fairly long name {i:03}.dat")), data(700 + i * 3, i as u32));
    }
    for e in fs.list("/").unwrap() {
        fs.remove(&format!("/{}", e.name)).unwrap();
    }
    let free1 = fs.free_bytes().unwrap();
    // Only the clusters the root directory grew by stay allocated.
    assert!(free1 < free0 && free0 - free1 <= 64 * 512, "{free0} -> {free1}");
}

#[test]
fn exfat_large_file_beyond_4gib_is_allowed() {
    let d = exfat_formatted(4 << 20, 4096);
    let fs = fs_of(&d);
    assert_eq!(fs.max_file_size(), u64::MAX);
}

#[test]
fn reserve_keeps_allocator_away() {
    for d in [fat_image(24 << 20), exfat_formatted(24 << 20, 4096)] {
        let mut fs = fs_of(&d);
        let total_free = fs.free_bytes().unwrap();
        let size = d.len();
        fs.reserve(size - (8 << 20), size);
        let free = fs.free_bytes().unwrap();
        assert!(free < total_free - (7 << 20), "{} {total_free} {free}", fs.kind());
        let too_big = vec![1u8; free as usize + 4096];
        assert!(matches!(fs.write_file("/big", &mut too_big.as_slice(), too_big.len() as u64, false, &mut |_| true), Err(Error::NoSpace)));
        let fits = vec![2u8; (free - 65536) as usize];
        put(&mut fs, "/fits", &fits);
        drop(fs);
        // Nothing landed in the reserved region.
        let img = d.0.lock().unwrap();
        assert!(img[(size - (8 << 20)) as usize..].iter().all(|&b| b != 2));
    }
}

/// An image whose unused sectors hold garbage, as a reused flash drive would.
fn dirty_image(size: usize, plan: FatPlan) -> Shared {
    let mut raw = vec![0xA5u8; size];
    // As a quick format writes it: the metadata region is zeros plus patches,
    // everything else keeps the garbage.
    raw[..plan.meta_end as usize].fill(0);
    apply_patches(&plan.patches, 0, &mut raw);
    Shared(Arc::new(Mutex::new(raw)))
}

fn tool_images() -> Vec<(&'static str, Shared)> {
    let fat16 = 24usize << 20;
    let fat32 = 40usize << 20;
    let ex = 16usize << 20;
    vec![
        ("FAT16", dirty_image(fat16, format_plan(fat16 as u64, "T", 7).unwrap())),
        ("FAT32", dirty_image(fat32, format_plan_fat32(fat32 as u64, "T").unwrap())),
        ("exFAT", dirty_image(ex, super::exfat_format::plan_with(ex as u64, "T", 7, 4096).unwrap())),
    ]
}

#[test]
fn zero_free_fills_only_free_clusters_and_resumes() {
    for (kind, d) in tool_images() {
        let mut fs = fs_of(&d);
        let a = data(300_000, 1);
        let b = data(70_000, 2);
        fs.mkdir("/dir").unwrap();
        put(&mut fs, "/dir/a.bin", &a);
        put(&mut fs, "/b.bin", &b);
        fs.remove("/b.bin").unwrap(); // a deleted file: its old bytes must go too
        put(&mut fs, "/c.bin", &b);
        // Small steps, as the app runs them, with a "restart" in the middle.
        let mut cursor = 0u64;
        let mut steps = 0;
        loop {
            let (next, done) = fs.zero_free(cursor, 256 * 1024).unwrap();
            assert!(next >= cursor, "{kind}: cursor went back");
            cursor = next;
            steps += 1;
            if steps == 3 {
                drop(fs);
                fs = fs_of(&d);
            }
            if done {
                break;
            }
        }
        assert!(steps > 3, "{kind}: should take several steps");
        assert_eq!(get(&mut fs, "/dir/a.bin"), a, "{kind}");
        assert_eq!(get(&mut fs, "/c.bin"), b, "{kind}");
        let r = fs.check(false).unwrap();
        assert!(r.clean(), "{kind}: {:?}", r.issues);
        drop(fs);
        // No garbage byte survives anywhere: free space is zero, metadata and files are intact.
        let img = d.0.lock().unwrap();
        let left = img.chunks(4096).filter(|c| c.iter().all(|&x| x == 0xA5)).count();
        assert_eq!(left, 0, "{kind}: {left} untouched 4K blocks remain");
    }
}

#[test]
fn move_keeps_data_without_copying() {
    for (kind, d) in tool_images() {
        let mut fs = fs_of(&d);
        let a = data(50_000, 3);
        fs.mkdir("/from").unwrap();
        fs.mkdir("/to").unwrap();
        fs.mkdir("/from/sub").unwrap();
        put(&mut fs, "/from/a.bin", &a);
        put(&mut fs, "/from/sub/inner.txt", b"inner");
        let free_before = fs.free_bytes().unwrap();
        fs.move_item("/from/a.bin", "/to").unwrap();
        assert_eq!(fs.free_bytes().unwrap(), free_before, "{kind}: a move must not allocate data");
        assert_eq!(get(&mut fs, "/to/a.bin"), a, "{kind}");
        assert!(fs.stat("/from/a.bin").is_err(), "{kind}");
        // A whole folder, then back to the root.
        fs.move_item("/from/sub", "/to").unwrap();
        assert_eq!(get(&mut fs, "/to/sub/inner.txt"), b"inner", "{kind}");
        fs.move_item("/to/sub", "/").unwrap();
        assert_eq!(get(&mut fs, "/sub/inner.txt"), b"inner", "{kind}");
        put(&mut fs, "/sub/more.txt", b"more");
        // Refusals.
        assert!(fs.move_item("/to", "/to").is_err(), "{kind}");
        fs.mkdir("/to/deeper").unwrap();
        assert!(fs.move_item("/to", "/to/deeper").is_err(), "{kind}");
        put(&mut fs, "/from/a.bin", b"other");
        assert!(matches!(fs.move_item("/from/a.bin", "/to"), Err(Error::AlreadyExists)), "{kind}");
        let r = fs.check(false).unwrap();
        assert!(r.clean(), "{kind}: {:?}", r.issues);
        drop(fs);
        let mut fs = fs_of(&d);
        assert_eq!(get(&mut fs, "/to/a.bin"), a, "{kind}: after remount");
        assert_eq!(get(&mut fs, "/sub/more.txt"), b"more", "{kind}");
    }
}

/// Byte offset of FAT entry `c` (FAT16/FAT32 images made by `format_plan*`).
fn fat_entry_offset(img: &[u8], c: u32) -> (usize, usize) {
    let bps = u16::from_le_bytes([img[11], img[12]]) as usize;
    let reserved = u16::from_le_bytes([img[14], img[15]]) as usize;
    let fat32 = u16::from_le_bytes([img[22], img[23]]) == 0;
    let width = if fat32 { 4 } else { 2 };
    (reserved * bps + c as usize * width, width)
}

#[test]
fn check_finds_and_repairs_lost_and_extra_clusters() {
    for (kind, d) in tool_images() {
        let mut fs = fs_of(&d);
        put(&mut fs, "/keep.bin", &data(20_000, 4));
        fs.flush().unwrap();
        assert!(fs.check(false).unwrap().clean(), "{kind}");
        drop(fs);
        {
            let mut img = d.0.lock().unwrap();
            if kind == "exFAT" {
                // Mark three free clusters used in the allocation bitmap (cluster 2 onward).
                let bps = 1usize << img[108];
                let cs = bps << img[109];
                let heap = u32::from_le_bytes(img[88..92].try_into().unwrap()) as usize * bps;
                let root = u32::from_le_bytes(img[96..100].try_into().unwrap()) as usize;
                let root_off = heap + (root - 2) * cs;
                let mut bitmap_first = 0usize;
                for e in img[root_off..root_off + cs].chunks(32) {
                    if e[0] == 0x81 {
                        bitmap_first = u32::from_le_bytes(e[20..24].try_into().unwrap()) as usize;
                    }
                }
                let bm = heap + (bitmap_first - 2) * cs;
                // Clusters far from the start are free in a fresh image.
                img[bm + 200] |= 0b0000_0111;
            } else {
                // Allocate three free clusters as a chain nobody owns.
                let eoc = if fat_entry_offset(&img, 0).1 == 4 { 0x0FFF_FFFFu32 } else { 0xFFFF };
                for (c, v) in [(1500u32, 1501u32), (1501, 1502), (1502, eoc)] {
                    let (o, w) = fat_entry_offset(&img, c);
                    if w == 4 {
                        img[o..o + 4].copy_from_slice(&v.to_le_bytes());
                    } else {
                        img[o..o + 2].copy_from_slice(&(v as u16).to_le_bytes());
                    }
                }
            }
        }
        let mut fs = fs_of(&d);
        let r = fs.check(false).unwrap();
        assert_eq!(r.lost_clusters, 3, "{kind}: {:?}", r);
        assert!(!r.clean());
        let free_before = fs.free_bytes().unwrap();
        let r = fs.check(true).unwrap();
        assert!(r.repaired > 0, "{kind}");
        assert!(fs.free_bytes().unwrap() > free_before, "{kind}: repair frees the space");
        assert!(fs.check(false).unwrap().clean(), "{kind}: clean after repair");
        drop(fs);
        let mut fs = fs_of(&d);
        assert!(fs.check(false).unwrap().clean(), "{kind}: clean after remount");
        assert_eq!(get(&mut fs, "/keep.bin"), data(20_000, 4), "{kind}");
    }
}
