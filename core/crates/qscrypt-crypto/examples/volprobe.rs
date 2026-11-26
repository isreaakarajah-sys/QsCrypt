//! VeraCrypt probe for the compatibility job: volumes made here are opened
//! by cryptsetup (an independent implementation) and mounted by Linux.
//!
//!   volprobe create <file> <bytes> <fat|exfat> <password> <ea> [keyfile|-] [hidden-bytes hidden-password]
//!   volprobe open <file> <password> [keyfile|-] [hidden-password-for-protection]

use qscrypt_core::crypto::Prf;
use qscrypt_core::disk::FileDisk;
use qscrypt_core::fs::{self, FsChoice};
use qscrypt_core::vc::{self, CipherChain, CreateOptions, EncVolume, Ea, Format, HiddenOptions, OpenOptions};
use qscrypt_crypto::RustCrypto;
use std::fs::File;
use std::sync::atomic::AtomicBool;

fn password(pw: &str, keyfile: Option<&String>) -> Vec<u8> {
    match keyfile.filter(|k| k.as_str() != "-") {
        Some(k) => {
            let data = std::fs::read(k).unwrap();
            vc::apply_keyfiles(pw.as_bytes(), &[&data]).unwrap().to_vec()
        }
        None => pw.as_bytes().to_vec(),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = RustCrypto;
    let no = AtomicBool::new(false);
    match a.get(1).map(String::as_str) {
        Some("create") => {
            let size: u64 = a[3].parse().unwrap();
            let fsc = if a[4] == "fat" { FsChoice::Fat } else { FsChoice::Exfat };
            let ea = Ea::ALL.into_iter().find(|e| e.name() == a[6]).expect("ea");
            let pw = password(&a[5], a.get(7));
            let hidden_pw = a.get(9).map(|s| s.as_bytes().to_vec());
            let f = File::options().read(true).write(true).create(true).truncate(true).open(&a[2]).unwrap();
            let mut d = FileDisk::new(f, false).unwrap();
            d.set_len(size).unwrap();
            let mut opts = CreateOptions::new(Format::VeraCrypt, &pw, ea, Prf::Sha512, size);
            opts.filesystem = fsc;
            opts.label = "QSCRYPT";
            if let (Some(hs), Some(hp)) = (a.get(8), hidden_pw.as_ref()) {
                opts.hidden = Some(HiddenOptions { password: hp, pim: 0, prf: Prf::Sha512, ea, size: hs.parse().unwrap(), filesystem: fsc, label: "HIDDEN" });
            }
            vc::create_volume(&b, &mut d, &opts, &mut |_, _| true, &no).unwrap();
            drop(d);
            write_file(&a[2], &pw, "/hello.txt", b"QsCrypt VeraCrypt");
            if let Some(hp) = hidden_pw {
                write_file(&a[2], &hp, "/secret.txt", b"hidden data");
            }
            println!("created");
        }
        Some("open") => {
            let pw = password(&a[3], a.get(4));
            let f = File::options().read(true).open(&a[2]).unwrap();
            let mut d = FileDisk::new(f, true).unwrap();
            let found = vc::detect(&b, &mut d, &OpenOptions::new(&pw), &no).unwrap();
            println!("{} {} {} hidden={}", found.header.format.name(), found.ea.name(), found.prf.name(), found.hidden);
        }
        _ => eprintln!("usage: see the source"),
    }
}

fn write_file(path: &str, pw: &[u8], name: &str, data: &[u8]) {
    let b = RustCrypto;
    let f = File::options().read(true).write(true).open(path).unwrap();
    let mut d = FileDisk::new(f, false).unwrap();
    let found = vc::detect(&b, &mut d, &OpenOptions::new(pw), &AtomicBool::new(false)).unwrap();
    let chain = CipherChain::new(&b, found.ea, &found.header.master_keys).unwrap();
    let vol = EncVolume::new(Box::new(d), chain, found.header.data_offset, found.header.data_size, false).unwrap();
    let mut f = fs::mount(Box::new(vol), false, 0).unwrap();
    f.write_file(name, &mut &data[..], data.len() as u64, false, &mut |_| true).unwrap();
    f.flush().unwrap();
}
