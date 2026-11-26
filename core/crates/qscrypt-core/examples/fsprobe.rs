//! File-system probe for compatibility tests against Linux's own tools
//! (see testdata/fs_compat.sh). Build with `--features reference`.
//!
//!   fsprobe manifest <image>                  list every dir/file with size and SHA-256
//!   fsprobe write <image> <host dir> <dest>   copy a host directory tree into the image
//!   fsprobe format <image> <bytes> <fat|exfat> <label>
//!   fsprobe churn <image> <dest>              create, rename and delete many entries

use qscrypt_core::disk::{Disk, FileDisk};
use qscrypt_core::fs::{self, FileSystem};
use qscrypt_core::reference::sha2::{Hash, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn open(path: &str, writable: bool) -> Box<dyn FileSystem> {
    let f = File::options().read(true).write(writable).open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let disk = FileDisk::new(f, !writable).expect("disk");
    fs::mount(Box::new(disk), !writable, 0).unwrap_or_else(|e| panic!("mount {path}: {e}"))
}

struct Hasher(Sha256, u64);

impl Write for Hasher {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        self.1 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn child(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn walk(fs: &mut dyn FileSystem, dir: &str, out: &mut Vec<String>) {
    for e in fs.list(dir).unwrap_or_else(|e| panic!("list {dir}: {e}")) {
        let p = child(dir, &e.name);
        if e.is_dir {
            out.push(format!("{p}/"));
            walk(fs, &p, out);
        } else {
            let mut h = Hasher(Sha256::new(), 0);
            fs.read_file(&p, &mut h, &mut |_| true).unwrap_or_else(|e| panic!("read {p}: {e}"));
            assert_eq!(h.1, e.size, "{p}: listed size {} but read {} bytes", e.size, h.1);
            let digest = h.0.finalize();
            out.push(format!("{p}\t{}\t{}", e.size, hex(&digest)));
        }
    }
}

fn copy_in(fs: &mut dyn FileSystem, host: &Path, dest: &str) {
    if dest != "/" && fs.stat(dest).is_err() {
        fs.mkdir(dest).unwrap_or_else(|e| panic!("mkdir {dest}: {e}"));
    }
    let mut entries: Vec<_> = std::fs::read_dir(host).unwrap().map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().into_string().unwrap();
        let target = child(dest, &name);
        let meta = e.metadata().unwrap();
        if meta.is_dir() {
            copy_in(fs, &e.path(), &target);
        } else {
            let mut f = File::open(e.path()).unwrap();
            fs.write_file(&target, &mut f, meta.len(), false, &mut |_| true).unwrap_or_else(|err| panic!("write {target}: {err}"));
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("manifest") => {
            let mut fs = open(&a[2], false);
            let mut lines = Vec::new();
            walk(fs.as_mut(), "/", &mut lines);
            lines.sort();
            for l in lines {
                println!("{l}");
            }
            eprintln!("{}: label={:?} total={} free={}", fs.kind(), fs.label(), fs.total_bytes(), fs.free_bytes().unwrap_or(0));
        }
        Some("write") => {
            let mut fs = open(&a[2], true);
            copy_in(fs.as_mut(), Path::new(&a[3]), &a[4]);
            fs.flush().unwrap();
        }
        Some("format") => {
            let size: u64 = a[3].parse().unwrap();
            let mut disk = FileDisk::new(File::options().read(true).write(true).create(true).truncate(true).open(&a[2]).unwrap(), false).unwrap();
            disk.set_len(size).unwrap();
            let patches = match a[4].as_str() {
                "fat" => fs::format_plan(size, &a[5], 0x1234_5678).unwrap().patches,
                "exfat" => fs::exfat_format_plan(size, &a[5], 0x1234_5678).unwrap().patches,
                other => panic!("unknown file system {other}"),
            };
            for (off, bytes) in patches {
                disk.write_at(off, &bytes).unwrap();
            }
            disk.flush().unwrap();
        }
        Some("churn") => {
            let mut fs = open(&a[2], true);
            let dest = a[3].as_str();
            fs.mkdir(dest).unwrap();
            for i in 0..120 {
                let p = child(dest, &format!("churn file {i:03} – ملف.txt"));
                let body = format!("churn {i}\n").repeat(i * 7 + 1);
                fs.write_file(&p, &mut body.as_bytes(), body.len() as u64, false, &mut |_| true).unwrap();
            }
            for i in (0..120).step_by(3) {
                fs.remove(&child(dest, &format!("churn file {i:03} – ملف.txt"))).unwrap();
            }
            for i in (1..120).step_by(3) {
                fs.rename(&child(dest, &format!("churn file {i:03} – ملف.txt")), &format!("renamed {i:03}.txt")).unwrap();
            }
            fs.flush().unwrap();
        }
        _ => {
            eprintln!("usage: fsprobe manifest|write|format|churn ...");
            std::process::exit(2);
        }
    }
}
