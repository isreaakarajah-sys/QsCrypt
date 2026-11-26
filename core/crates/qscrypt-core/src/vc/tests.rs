use super::*;
use crate::disk::{Disk, MemDisk};
use crate::error::Error;
use crate::fs::{mount, FileSystem};
use crate::reference::RefBackend;
use crate::util::Secret;
use std::sync::atomic::AtomicBool;

const VOLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/");

fn load(name: &str) -> MemDisk {
    MemDisk { data: std::fs::read(format!("{VOLS}{name}.vol")).expect("run testdata/gen_vectors.py") }
}

/// Same deterministic pattern as gen_vectors.py's data_pattern().
fn pattern(label: &str, offset: u64, n: usize) -> Vec<u8> {
    use crate::reference::sha2::{Hash, Sha512};
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < n {
        out.extend(Sha512::digest(&[format!("{label}@{offset}/{i}").as_bytes()]));
        i += 1;
    }
    out.truncate(n);
    out
}

fn open(disk: MemDisk, password: &str, pim: u32, format: Option<Format>) -> crate::Result<(OpenedHeader, EncVolume)> {
    let b = RefBackend::new();
    let mut disk = disk;
    let mut o = OpenOptions::new(password.as_bytes());
    o.pim = pim;
    o.format = format;
    let found = detect(&b, &mut disk, &o, &AtomicBool::new(false))?;
    let chain = CipherChain::new(&b, found.ea, &found.header.master_keys)?;
    let (off, size) = (found.header.data_offset, found.header.data_size);
    let vol = EncVolume::new(Box::new(disk), chain, off, size, true)?;
    Ok((found, vol))
}

fn check_pattern(vol: &mut EncVolume, label: &str, units: u64) {
    for u in [0, 1, units / 2, units - 1] {
        let mut buf = vec![0u8; 512];
        vol.read_at(u * 512, &mut buf).unwrap();
        assert_eq!(buf, pattern(label, u * 512, 512), "{label} unit {u}");
    }
    // Unaligned read spanning units.
    let mut buf = vec![0u8; 1000];
    vol.read_at(700, &mut buf).unwrap();
    let mut expect = pattern(label, 512, 512);
    expect.extend(pattern(label, 1024, 512));
    expect.extend(pattern(label, 1536, 512));
    assert_eq!(buf, expect[188..1188]);
}

#[test]
fn opens_veracrypt_aes_sha512() {
    let (h, mut vol) = open(load("vc_aes_sha512"), "correct horse", 1, None).unwrap();
    assert_eq!((h.header.format, h.prf, h.ea, h.hidden), (Format::VeraCrypt, crate::crypto::Prf::Sha512, Ea::Aes, false));
    assert_eq!(h.header.data_offset, DATA_OFFSET);
    assert_eq!(vol.len(), 65536);
    check_pattern(&mut vol, "vc_aes_sha512/outer", 128);
}

#[test]
fn opens_veracrypt_sha256() {
    let (h, mut vol) = open(load("vc_aes_sha256"), "SHA-256 volume", 1, None).unwrap();
    assert_eq!(h.prf, crate::crypto::Prf::Sha256);
    check_pattern(&mut vol, "vc_aes_sha256/outer", 128);
}

#[test]
fn opens_hidden_and_outer() {
    let (h, mut vol) = open(load("vc_hidden"), "hidden password", 1, None).unwrap();
    assert!(h.hidden);
    assert_eq!((h.header.data_offset, h.header.data_size), (196_608, 32_768));
    check_pattern(&mut vol, "vc_hidden/hidden", 64);

    let (h, mut vol) = open(load("vc_hidden"), "outer password", 1, None).unwrap();
    assert!(!h.hidden);
    // The first 64 KiB of the outer area are untouched by the hidden volume.
    let mut buf = vec![0u8; 512];
    vol.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, pattern("vc_hidden/outer", 0, 512));
}

#[test]
fn opens_truecrypt() {
    let (h, mut vol) = open(load("tc_aes_sha512"), "truecrypt", 0, Some(Format::TrueCrypt)).unwrap();
    assert_eq!(h.header.format, Format::TrueCrypt);
    assert_eq!(h.iterations, 1000);
    check_pattern(&mut vol, "tc_aes_sha512/outer", 128);
}

#[test]
fn wrong_password_and_pim() {
    assert!(matches!(open(load("vc_aes_sha512"), "wrong", 1, None), Err(Error::WrongPassword)));
    assert!(matches!(open(load("vc_aes_sha512"), "correct horse", 2, None), Err(Error::WrongPassword)));
}

#[test]
fn cancel_stops_detection() {
    let b = RefBackend::new();
    let mut disk = load("vc_aes_sha512");
    let o = OpenOptions::new(b"anything");
    let cancel = AtomicBool::new(true);
    assert!(matches!(detect(&b, &mut disk, &o, &cancel), Err(Error::Cancelled)));
}

fn create(size: u64, password: &str, ea: Ea, format: Format, backend: &RefBackend) -> MemDisk {
    let mut disk = MemDisk::new(size as usize);
    let mut opts = CreateOptions::new(format, password.as_bytes(), ea, crate::crypto::Prf::Sha512, size);
    opts.pim = if format == Format::VeraCrypt { 1 } else { 0 };
    opts.label = "QsTest";
    let mut calls = 0;
    create_container(backend, &mut disk, &opts, &mut |d, t| {
        assert!(d <= t);
        calls += 1;
        true
    }, &AtomicBool::new(false))
    .unwrap();
    assert!(calls >= 3);
    disk
}

fn mount_rw<D: Disk + 'static>(disk: D, password: &str, format: Option<Format>) -> Box<dyn FileSystem> {
    mount_bytes(disk, password.as_bytes(), format)
}

fn mount_bytes<D: Disk + 'static>(disk: D, password: &[u8], format: Option<Format>) -> Box<dyn FileSystem> {
    let b = RefBackend::with_fakes();
    let mut disk = disk;
    let mut o = OpenOptions::new(password);
    o.pim = if format == Some(Format::TrueCrypt) { 0 } else { 1 };
    o.format = format;
    let found = detect(&b, &mut disk, &o, &AtomicBool::new(false)).unwrap();
    let chain = CipherChain::new(&b, found.ea, &found.header.master_keys).unwrap();
    let vol = EncVolume::new(Box::new(disk), chain, found.header.data_offset, found.header.data_size, false).unwrap();
    mount(Box::new(vol), false, 180).unwrap()
}

#[test]
fn create_mount_write_reopen() {
    let b = RefBackend::new();
    let disk = create(4 << 20, "s3cret", Ea::Aes, Format::VeraCrypt, &b);
    // No plaintext anywhere: the FAT boot signature must not be visible.
    assert!(!disk.data.windows(8).any(|w| w == b"MSDOS5.0"));
    let shared = SharedDisk::new(disk);
    {
        let mut fs = mount_rw(shared.clone(), "s3cret", None);
        assert_eq!(fs.kind(), "FAT12");
        assert_eq!(fs.label(), "QSTEST");
        let content: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        fs.write_file("/صورة الهوية.jpg", &mut content.as_slice(), content.len() as u64, false, &mut |_| true).unwrap();
        fs.mkdir("/عقود 2026").unwrap();
        fs.write_file("/عقود 2026/notes.txt", &mut &b"hello"[..], 5, false, &mut |_| true).unwrap();
        fs.flush().unwrap();
    }
    let mut fs = mount_rw(shared.clone(), "s3cret", None);
    let mut names: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec!["صورة الهوية.jpg", "عقود 2026"]);
    let mut out = Vec::new();
    fs.read_file("/صورة الهوية.jpg", &mut out, &mut |_| true).unwrap();
    assert_eq!(out.len(), 300_000);
    assert!(out.iter().enumerate().all(|(i, &b)| b == (i as u32 * 7 % 251) as u8));
    let mut small = Vec::new();
    fs.read_file("/عقود 2026/NOTES.TXT", &mut small, &mut |_| true).unwrap();
    assert_eq!(small, b"hello");
}

#[test]
fn create_cascade_and_truecrypt() {
    let b = RefBackend::with_fakes();
    for (ea, format) in [(Ea::AesTwofishSerpent, Format::VeraCrypt), (Ea::Aes, Format::TrueCrypt)] {
        let disk = create(2 << 20, "pw", ea, format, &b);
        let shared = SharedDisk::new(disk);
        let mut fs = mount_rw(shared.clone(), "pw", Some(format));
        fs.write_file("/a.bin", &mut &[1u8, 2, 3][..], 3, false, &mut |_| true).unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(fs.read_range("/a.bin", 0, &mut buf).unwrap(), 3);
        assert_eq!(buf, [1, 2, 3]);
    }
}

#[test]
fn header_round_trip() {
    let plain = PlainHeader {
        format: Format::VeraCrypt,
        version: 5,
        required_version: 0x010B,
        hidden_volume_size: 0,
        volume_size: 1 << 30,
        data_offset: DATA_OFFSET,
        data_size: 1 << 30,
        flags: 0,
        sector_size: 512,
        master_keys: Secret::from_slice(&[0x5A; 256]),
    };
    let ser = plain.serialize();
    let back = PlainHeader::parse(&ser).unwrap();
    assert_eq!(back.data_size, 1 << 30);
    let mut bad = ser.clone();
    bad[300] ^= 1;
    assert!(PlainHeader::parse(&bad).is_none());
}

// ------------------------------------------------------------ new in 0.2

use crate::crypto::Prf;
use crate::fs::FsChoice;

fn opts_for(password: &[u8]) -> OpenOptions<'_> {
    let mut o = OpenOptions::new(password);
    o.pim = 1;
    o.prf = Some(Prf::Sha512);
    o.format = Some(Format::VeraCrypt);
    o
}

fn new_volume(size: u64, password: &[u8], fs: FsChoice, hidden: Option<HiddenOptions>) -> SharedDisk {
    let b = RefBackend::with_fakes();
    let mut disk = MemDisk::new(size as usize);
    let mut opts = CreateOptions::new(Format::VeraCrypt, password, Ea::Aes, Prf::Sha512, size);
    opts.pim = 1;
    opts.label = "Outer";
    opts.filesystem = fs;
    opts.hidden = hidden;
    create_volume(&b, &mut disk, &opts, &mut |_, _| true, &AtomicBool::new(false)).unwrap();
    SharedDisk::new(disk)
}

#[test]
fn creates_exfat_volumes() {
    let d = new_volume(6 << 20, b"pw", FsChoice::Exfat, None);
    let mut fs = mount_rw(d.clone(), "pw", None);
    assert_eq!(fs.kind(), "exFAT");
    assert_eq!(fs.label(), "Outer");
    let big: Vec<u8> = (0..2_000_000u32).map(|i| (i % 253) as u8).collect();
    fs.write_file("/فيديو.mp4", &mut big.as_slice(), big.len() as u64, false, &mut |_| true).unwrap();
    drop(fs);
    let mut fs = mount_rw(d, "pw", None);
    let mut out = Vec::new();
    fs.read_file("/فيديو.mp4", &mut out, &mut |_| true).unwrap();
    assert_eq!(out, big);
}

#[test]
fn hidden_volume_create_open_and_protect() {
    let size: u64 = 12 << 20;
    let hsize: u64 = 4 << 20;
    let max = max_hidden_size(size, FsChoice::Fat).unwrap();
    assert!(max > hsize && max < size);
    let hidden = HiddenOptions { password: b"hidden pw", pim: 1, prf: Prf::Sha512, ea: Ea::Serpent, size: hsize, filesystem: FsChoice::Exfat, label: "Secret" };
    let d = new_volume(size, b"outer pw", FsChoice::Fat, Some(hidden));
    let b = RefBackend::with_fakes();

    // The hidden volume: VeraCrypt's layout.
    let found = detect(&b, &mut d.clone(), &opts_for(b"hidden pw"), &AtomicBool::new(false)).unwrap();
    assert!(found.hidden);
    assert_eq!(found.ea, Ea::Serpent);
    assert_eq!(found.header.data_offset, size - HEADER_GROUP - hsize);
    assert_eq!(found.header.data_size, hsize - HEADER_GROUP);
    assert_eq!(found.header.hidden_volume_size, hsize - HEADER_GROUP);
    {
        let mut fs = mount_rw(d.clone(), "hidden pw", None);
        assert_eq!((fs.kind(), fs.label()), ("exFAT", "Secret".to_string()));
        fs.write_file("/secret.txt", &mut &b"the real data"[..], 13, false, &mut |_| true).unwrap();
    }

    // The outer volume with protection: free space excludes the hidden
    // area and nothing can be written into it.
    let range = hidden_range(&b, &mut d.clone(), &opts_for(b"hidden pw"), &AtomicBool::new(false)).unwrap();
    assert_eq!(range, (size - HEADER_GROUP - hsize, size - 2 * HEADER_GROUP));
    let outer = detect(&b, &mut d.clone(), &opts_for(b"outer pw"), &AtomicBool::new(false)).unwrap();
    assert!(!outer.hidden);
    let chain = CipherChain::new(&b, outer.ea, &outer.header.master_keys).unwrap();
    let mut vol = EncVolume::new(Box::new(d.clone()), chain, outer.header.data_offset, outer.header.data_size, false).unwrap();
    vol.protect(range.0, range.1);
    let (rs, re) = vol.protected_range().unwrap();
    assert_eq!(re - rs, hsize - HEADER_GROUP);
    let mut fs = mount(Box::new(vol), false, 0).unwrap();
    let before = fs.free_bytes().unwrap();
    fs.reserve(rs, re);
    let after = fs.free_bytes().unwrap();
    assert!(after <= before - (hsize - HEADER_GROUP) + 65536, "{before} {after}");
    let decoy: Vec<u8> = vec![7u8; (after - 32768) as usize];
    fs.write_file("/decoy.bin", &mut decoy.as_slice(), decoy.len() as u64, false, &mut |_| true).unwrap();
    let more = vec![8u8; 100_000];
    assert!(matches!(fs.write_file("/more.bin", &mut more.as_slice(), more.len() as u64, false, &mut |_| true), Err(Error::NoSpace)));
    drop(fs);

    // A raw write into the hidden area trips the protection for good.
    let chain = CipherChain::new(&b, outer.ea, &outer.header.master_keys).unwrap();
    let mut vol = EncVolume::new(Box::new(d.clone()), chain, outer.header.data_offset, outer.header.data_size, false).unwrap();
    vol.protect(range.0, range.1);
    assert!(matches!(vol.write_at(rs + 512, &[0u8; 512]), Err(Error::HiddenProtected)));
    assert!(vol.protection_tripped());
    assert!(matches!(vol.write_at(0, &[0u8; 512]), Err(Error::HiddenProtected)));
    drop(vol);

    // The hidden data survived.
    let mut fs = mount_rw(d.clone(), "hidden pw", None);
    let mut out = Vec::new();
    fs.read_file("/secret.txt", &mut out, &mut |_| true).unwrap();
    assert_eq!(out, b"the real data");
    let mut fs = mount_rw(d, "outer pw", None);
    assert_eq!(fs.stat("/decoy.bin").unwrap().size, decoy.len() as u64);
}

#[test]
fn hidden_volume_limits() {
    let b = RefBackend::with_fakes();
    let size: u64 = 4 << 20;
    let max = max_hidden_size(size, FsChoice::Fat).unwrap();
    let mut disk = MemDisk::new(size as usize);
    let mut opts = CreateOptions::new(Format::VeraCrypt, b"a", Ea::Aes, Prf::Sha512, size);
    opts.pim = 1;
    opts.hidden = Some(HiddenOptions { password: b"b", pim: 0, prf: Prf::Sha512, ea: Ea::Aes, size: max + 4096, filesystem: FsChoice::Fat, label: "" });
    assert!(create_volume(&b, &mut disk, &opts, &mut |_, _| true, &AtomicBool::new(false)).is_err());
    opts.hidden = Some(HiddenOptions { password: b"a", pim: 0, prf: Prf::Sha512, ea: Ea::Aes, size: max, filesystem: FsChoice::Fat, label: "" });
    assert!(create_volume(&b, &mut disk, &opts, &mut |_, _| true, &AtomicBool::new(false)).is_err(), "same password");
    opts.hidden = None;
    opts.quick = true;
    create_volume(&b, &mut disk, &opts, &mut |_, _| true, &AtomicBool::new(false)).unwrap();
    // Quick format leaves most of the data area untouched (zeros here).
    let zeros = disk.data[DATA_OFFSET as usize..(size - HEADER_GROUP) as usize].chunks(4096).filter(|c| c.iter().all(|&x| x == 0)).count();
    assert!(zeros > 500, "{zeros}");
    let mut fs = mount_bytes(SharedDisk::new(disk), b"a", Some(Format::VeraCrypt));
    fs.write_file("/q", &mut &b"quick"[..], 5, false, &mut |_| true).unwrap();
}

#[test]
fn keyfiles_change_the_key() {
    let kf1 = b"keyfile one contents".to_vec();
    let kf2: Vec<u8> = (0..5000u32).map(|i| (i * 13) as u8).collect();
    let mixed = apply_keyfiles(b"pw", &[&kf1, &kf2]).unwrap();
    let d = new_volume(2 << 20, &mixed, FsChoice::Fat, None);
    let b = RefBackend::with_fakes();
    assert!(detect(&b, &mut d.clone(), &opts_for(&mixed), &AtomicBool::new(false)).is_ok());
    assert!(matches!(detect(&b, &mut d.clone(), &opts_for(b"pw"), &AtomicBool::new(false)), Err(Error::WrongPassword)));
    let one = apply_keyfiles(b"pw", &[&kf1]).unwrap();
    assert!(matches!(detect(&b, &mut d.clone(), &opts_for(&one), &AtomicBool::new(false)), Err(Error::WrongPassword)));
    // Keyfiles only, no password.
    let only = apply_keyfiles(b"", &[&kf2]).unwrap();
    let d = new_volume(2 << 20, &only, FsChoice::Fat, None);
    assert!(detect(&b, &mut d.clone(), &opts_for(&only), &AtomicBool::new(false)).is_ok());
}

#[test]
fn password_change_backup_restore_repair() {
    let b = RefBackend::with_fakes();
    let no = AtomicBool::new(false);
    let size: u64 = 2 << 20;
    let mut d = new_volume(size, b"old", FsChoice::Fat, None);
    {
        let mut fs = mount_rw(d.clone(), "old", None);
        fs.write_file("/keep.txt", &mut &b"keep me"[..], 7, false, &mut |_| true).unwrap();
    }
    change_password(&b, &mut d, &opts_for(b"old"), &Credentials { password: b"new", pim: 1, prf: Prf::Sha256 }, &no).unwrap();
    assert!(matches!(detect(&b, &mut d.clone(), &opts_for(b"old"), &no), Err(Error::WrongPassword)));
    let mut o = OpenOptions::new(b"new");
    o.pim = 1;
    let found = detect(&b, &mut d.clone(), &o, &no).unwrap();
    assert_eq!(found.prf, Prf::Sha256);
    let mut bo = OpenOptions::new(b"new");
    bo.pim = 1;
    bo.backup_only = true;
    assert!(detect(&b, &mut d.clone(), &bo, &no).unwrap().backup, "the embedded backup changed too");

    // External backup, then destroy the primary header and restore it.
    let backup = backup_headers(&b, &mut d.clone(), &o, None, &no).unwrap();
    assert_eq!(backup.len(), HEADER_GROUP as usize);
    d.write_at(0, &[0xA5; 512]).unwrap();
    assert!(matches!(detect(&b, &mut d.clone(), &o, &no), Err(Error::WrongPassword)));
    restore_from_file(&b, &mut d, &backup, &o, &no).unwrap();
    assert!(detect(&b, &mut d.clone(), &o, &no).is_ok());

    // Or repair it from the embedded backup.
    d.write_at(0, &[0x5A; 512]).unwrap();
    repair_from_embedded(&b, &mut d, &o, &no).unwrap();
    let mut fs = mount_bytes(d.clone(), b"new", None);
    let mut out = Vec::new();
    fs.read_file("/keep.txt", &mut out, &mut |_| true).unwrap();
    assert_eq!(out, b"keep me");
}

// ------------------------------------------------------------ test helpers

use std::sync::{Arc, Mutex};

/// In-memory disk whose clones share the same bytes, so a test can mount,
/// unmount and mount again.
#[derive(Clone)]
struct SharedDisk(Arc<Mutex<Vec<u8>>>);

impl SharedDisk {
    fn new(d: MemDisk) -> SharedDisk {
        SharedDisk(Arc::new(Mutex::new(d.data)))
    }
}

impl Disk for SharedDisk {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> crate::Result<()> {
        let d = self.0.lock().unwrap();
        let o = offset as usize;
        buf.copy_from_slice(&d[o..o + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> crate::Result<()> {
        let mut d = self.0.lock().unwrap();
        let o = offset as usize;
        d[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }
}
