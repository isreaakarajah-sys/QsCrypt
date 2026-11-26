//! BitLocker probe for the compatibility job (see .github/workflows).
//!
//!   bdeprobe sum <image> <password or recovery password>   SHA-256 of the decrypted volume
//!   bdeprobe info <image>
//!   bdeprobe explain <image> <password> <recovery password>
//!   bdeprobe create <image> <bytes> <exfat|fat> <password> <xts128|xts256|cbc128|cbc256>
//!   bdeprobe check <image> <password>                       list the root and print /hello.txt

use qscrypt_core::bde::{self, BdeCreateOptions, Credential, Method};
use qscrypt_core::disk::{Disk, FileDisk};
use qscrypt_core::fs::{self, FsChoice};
use qscrypt_crypto::RustCrypto;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::sync::atomic::AtomicBool;

fn disk(path: &str, writable: bool) -> Box<dyn Disk> {
    let f = File::options().read(true).write(writable).open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    Box::new(FileDisk::new(f, !writable).unwrap())
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = RustCrypto;
    let no = AtomicBool::new(false);
    match a.get(1).map(String::as_str) {
        Some("sum") => {
            let cred = if bde::parse_recovery(&a[3]).is_some() { Credential::Recovery(&a[3]) } else { Credential::Password(&a[3]) };
            let (info, keys, mut vol) = bde::open(&b, disk(&a[2], false), &cred, true, &no).unwrap_or_else(|e| panic!("open: {e}"));
            eprintln!("method {} via {:?}, togo {}, eow {}, sector {}", info.method.name(), keys.protection, info.togo, info.eow, info.sector_size);
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            let mut pos = 0u64;
            while pos < vol.len() {
                let n = ((vol.len() - pos) as usize).min(buf.len());
                vol.read_at(pos, &mut buf[..n]).unwrap();
                h.update(&buf[..n]);
                pos += n as u64;
            }
            println!("{}", h.finalize().iter().map(|x| format!("{x:02x}")).collect::<String>());
        }
        Some("info") => {
            let info = bde::read_info(&b, disk(&a[2], false).as_mut()).unwrap();
            println!("method {} togo {} eow {} sector {} size {} header {}+{} desc {:?}", info.method.name(), info.togo, info.eow, info.sector_size, info.volume_size, info.header_offset, info.header_size, info.description);
            for p in &info.protectors {
                println!("  protector {} {:?}", p.guid, p.protection);
            }
        }
        Some("explain") => println!("{}", bde::research::explain(&b, disk(&a[2], false).as_mut(), &a[3], &a[4]).unwrap()),
        Some("create") => {
            let size: u64 = a[3].parse().unwrap();
            let f = File::options().read(true).write(true).create(true).truncate(true).open(&a[2]).unwrap();
            let mut d = FileDisk::new(f, false).unwrap();
            d.set_len(size).unwrap();
            let method = match a[6].as_str() {
                "xts128" => Method::Xts128,
                "xts256" => Method::Xts256,
                "cbc128" => Method::Cbc128,
                _ => Method::Cbc256,
            };
            let fsc = if a[4] == "fat" { FsChoice::Fat } else { FsChoice::Exfat };
            let opts = BdeCreateOptions { password: &a[5], recovery_key: None, method, filesystem: fsc, label: "QSBITLOCKR", description: "QsCrypt CI 2026-11-26", quick: false };
            let rp = bde::create_bitlocker(&b, Box::new(d), &opts, &mut |_, _| true, &no).unwrap();
            let (info, _, vol) = bde::open(&b, disk(&a[2], true), &Credential::Password(&a[5]), false, &no).unwrap();
            let mut f = fs::mount(Box::new(vol), false, 0).unwrap();
            let _ = info;
            f.write_file("/hello.txt", &mut &b"QsCrypt BitLocker"[..], 17, false, &mut |_| true).unwrap();
            f.mkdir("/مجلد").unwrap();
            let big: Vec<u8> = (0..5_000_000u32).map(|i| (i % 253) as u8).collect();
            f.write_file("/مجلد/big.bin", &mut big.as_slice(), big.len() as u64, false, &mut |_| true).unwrap();
            f.flush().unwrap();
            println!("{rp}");
        }
        Some("check") => {
            let (_, _, vol) = bde::open(&b, disk(&a[2], false), &Credential::Password(&a[3]), true, &no).unwrap();
            let mut f = fs::mount(Box::new(vol), true, 0).unwrap();
            for e in f.list("/").unwrap() {
                println!("{} {} {}", if e.is_dir { "d" } else { "f" }, e.size, e.name);
            }
            let mut out = Vec::new();
            if f.read_file("/hello.txt", &mut out, &mut |_| true).is_ok() {
                println!("hello: {}", String::from_utf8_lossy(&out));
            }
        }
        _ => eprintln!("usage: see the source"),
    }
}
