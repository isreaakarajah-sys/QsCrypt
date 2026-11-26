use super::*;
use crate::disk::MemDisk;
use crate::fs::FsChoice;
use crate::part::{DiskView, SharedDisk};
use crate::reference::RefBackend;
use std::sync::{Arc, Mutex};

fn shared(size: usize) -> SharedDisk {
    Arc::new(Mutex::new(Box::new(MemDisk::new(size))))
}

fn view(s: &SharedDisk) -> Box<dyn Disk> {
    Box::new(DiskView::whole(s.clone(), false).unwrap())
}

#[test]
fn recovery_passwords() {
    let b = RefBackend::new();
    let (s, k) = create::generate_recovery_password(&b).unwrap();
    assert_eq!(s.len(), 55);
    assert_eq!(parse_recovery(&s), Some(k));
    // Arabic-Indic digits and no dashes.
    let arabic: String = s.chars().filter(|c| *c != '-').map(|c| char::from_u32(c as u32 - '0' as u32 + 0x0660).unwrap()).collect();
    assert_eq!(parse_recovery(&arabic), Some(k));
    assert_eq!(parse_recovery("123456-123456"), None);
    // Valid-looking but a group not divisible by 11.
    let bad = format!("000001{}", &s[6..]);
    assert_eq!(parse_recovery(&bad), None);
    // libbde's documented example.
    assert!(parse_recovery("471207-278498-422125-177177-561902-537405-468006-693451").is_some());
}

#[test]
fn engines_round_trip() {
    let b = RefBackend::new();
    let key: Vec<u8> = (0..64u8).collect();
    for m in [Method::Xts128, Method::Xts256, Method::Cbc128, Method::Cbc256, Method::Cbc128Diffuser, Method::Cbc256Diffuser] {
        let e = Engine::new(&b, m, &key).unwrap();
        for ss in [512usize, 4096] {
            let orig: Vec<u8> = (0..2 * ss as u32).map(|i| (i * 7 % 256) as u8).collect();
            let mut buf = orig.clone();
            e.encrypt(&mut buf, ss, 8 * ss as u64);
            assert_ne!(buf, orig, "{m:?}");
            // Position matters.
            let mut other = orig.clone();
            e.encrypt(&mut other, ss, 9 * ss as u64);
            assert_ne!(other[..ss], buf[..ss]);
            e.decrypt(&mut buf, ss, 8 * ss as u64);
            assert_eq!(buf, orig, "{m:?} {ss}");
        }
    }
}

fn make(fs: FsChoice, method: Method) -> (SharedDisk, String) {
    let b = RefBackend::new();
    let s = shared(64 << 20);
    let opts = BdeCreateOptions { password: "كلمة سر قوية 123", recovery_key: None, method, filesystem: fs, label: "QsBit", description: "QsCrypt test 2026-11-26", quick: true, hidden_sectors: 0 };
    let rp = create_bitlocker(&b, view(&s), &opts, &mut |_, _| true, &AtomicBool::new(false)).unwrap();
    (s, rp)
}

#[test]
fn create_open_write_reopen() {
    let b = RefBackend::new();
    let no = AtomicBool::new(false);
    let (s, rp) = make(FsChoice::Exfat, Method::Xts128);
    {
        let mut d = view(&s);
        let info = read_info(&b, d.as_mut()).unwrap();
        assert!(!info.togo && !info.eow);
        assert_eq!(info.method, Method::Xts128);
        assert_eq!(info.description, "QsCrypt test 2026-11-26");
        assert_eq!(info.protectors.len(), 2);
        assert_eq!(info.header_size, 8192);
        assert!(info.validation.is_some());
    }
    let (_, keys, vol) = open(&b, view(&s), &Credential::Password("كلمة سر قوية 123"), false, &no).unwrap();
    assert_eq!(keys.protection, Protection::Password);
    let regions = vol.reserved_regions();
    let mut fs = crate::fs::mount(Box::new(vol), false, 0).unwrap();
    assert_eq!(fs.kind(), "exFAT");
    assert_eq!(fs.label(), "QsBit");
    for (a, z) in regions {
        fs.reserve(a, z);
    }
    let names: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["System Volume Information"]);
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    fs.write_file("/تقرير.pdf", &mut data.as_slice(), data.len() as u64, false, &mut |_| true).unwrap();
    fs.flush().unwrap();
    drop(fs);

    // The recovery password opens it too; a wrong password does not.
    let (_, keys, vol) = open(&b, view(&s), &Credential::Recovery(&rp), false, &no).unwrap();
    assert_eq!(keys.protection, Protection::Recovery);
    let mut fs = crate::fs::mount(Box::new(vol), false, 0).unwrap();
    let mut out = Vec::new();
    fs.read_file("/تقرير.pdf", &mut out, &mut |_| true).unwrap();
    assert_eq!(out, data);
    // A recovery password typed into the password field works as well.
    assert!(open(&b, view(&s), &Credential::Password(&rp), true, &no).is_ok());
    assert!(matches!(open(&b, view(&s), &Credential::Password("wrong password"), true, &no), Err(Error::WrongPassword)));

    // The placeholders hide the metadata: reads of them are zeros, and
    // the boot sector on disk is BitLocker's, not exFAT's.
    let mut raw = [0u8; 512];
    s.lock().unwrap().read_at(0, &mut raw).unwrap();
    assert!(is_bitlocker(&raw));
}

#[test]
fn metadata_copies_and_tampering() {
    let b = RefBackend::new();
    let no = AtomicBool::new(false);
    let (s, _) = make(FsChoice::Fat, Method::Cbc128);
    let info = read_info(&b, view(&s).as_mut()).unwrap();
    let [m1, m2, m3] = info.metadata;
    // Damage copy 1: copy 2 is used.
    s.lock().unwrap().write_at(m1 + 200, &[0xFF; 16]).unwrap();
    let info2 = read_info(&b, view(&s).as_mut()).unwrap();
    assert_eq!(info2.method, Method::Cbc128);
    let (_, _, vol) = open(&b, view(&s), &Credential::Password("كلمة سر قوية 123"), true, &no).unwrap();
    let fs = crate::fs::mount(Box::new(vol), true, 0).unwrap();
    assert!(fs.kind().starts_with("FAT"));
    drop(fs);

    // Change a description byte in all copies and fix their CRCs: the CRC
    // passes, the VMK-sealed hash does not.
    let mut a = vec![0u8; META_AREA as usize];
    s.lock().unwrap().read_at(m2, &mut a).unwrap();
    let real = (le16(&a, 8) as usize) << 4;
    a[120] ^= 1;
    let crc = crc32(&a[..real]);
    a[real + 4..real + 8].copy_from_slice(&crc.to_le_bytes());
    for m in [m1, m2, m3] {
        s.lock().unwrap().write_at(m, &a).unwrap();
    }
    assert!(matches!(open(&b, view(&s), &Credential::Password("كلمة سر قوية 123"), true, &no), Err(Error::Tampered)));
}

#[test]
fn rejects_short_passwords_and_small_volumes() {
    let b = RefBackend::new();
    let opts = BdeCreateOptions { password: "short", recovery_key: None, method: Method::Xts128, filesystem: FsChoice::Exfat, label: "", description: "", quick: true, hidden_sectors: 2048 };
    assert!(create_bitlocker(&b, view(&shared(64 << 20)), &opts, &mut |_, _| true, &AtomicBool::new(false)).is_err());
    let opts = BdeCreateOptions { password: "long enough", ..opts };
    assert!(create_bitlocker(&b, view(&shared(8 << 20)), &opts, &mut |_, _| true, &AtomicBool::new(false)).is_err());
}
