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
    let opts = CreateOptions { format, password: password.as_bytes(), pim: if format == Format::VeraCrypt { 1 } else { 0 }, prf: crate::crypto::Prf::Sha512, ea, size, label: "QsTest" };
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
    let b = RefBackend::with_fakes();
    let mut disk = disk;
    let mut o = OpenOptions::new(password.as_bytes());
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
