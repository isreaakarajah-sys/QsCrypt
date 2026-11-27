//! File-system probe for compatibility tests against Linux's own tools
//! (see testdata/fs_compat.sh). Build with `--features reference`.
//!
//!   fsprobe manifest <image>                  list every dir/file with size and SHA-256
//!   fsprobe write <image> <host dir> <dest>   copy a host directory tree into the image
//!   fsprobe format <image> <bytes> <fat|exfat> <label>
//!   fsprobe churn <image> <dest>              create, rename and delete many entries
//!   fsprobe stress <image> <dest> [n] [seed]  thousands of random changes, checked
//!                                             against a model after every phase
//!   fsprobe fuzz <image> <ops> [seed]          random interleaved changes in a few
//!                                             folders, checked and remounted as it goes
//!   fsprobe check <image>                     the file system's own check
//!
//! `<image>` may be `file@offset` for a partition inside a disk image, or
//! `file@1` (a number below 64) for that partition of its table. `stress`
//! with a sixth argument `keep` leaves its files in place for other tools.

use qscrypt_core::disk::{Disk, FileDisk};
use qscrypt_core::fs::{self, FileSystem};
use qscrypt_core::part::{DiskView, SharedDisk};
use qscrypt_core::reference::sha2::{Hash, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn open(spec: &str, writable: bool) -> Box<dyn FileSystem> {
    let (path, at) = match spec.rsplit_once('@') {
        Some((p, o)) => (p, o.parse::<u64>().expect("offset")),
        None => (spec, 0),
    };
    let f = File::options().read(true).write(writable).open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let mut disk = FileDisk::new(f, !writable).expect("disk");
    let offset = if (1..64).contains(&at) {
        let parts = qscrypt_core::part::read_table(&mut disk, 512).expect("partition table");
        parts.iter().find(|p| p.index as u64 == at).unwrap_or_else(|| panic!("{path} has no partition {at}")).start
    } else {
        at
    };
    let disk: Box<dyn Disk> = if offset == 0 {
        Box::new(disk)
    } else {
        let len = disk.len();
        let shared: SharedDisk = Arc::new(Mutex::new(Box::new(disk)));
        Box::new(DiskView::new(shared, offset, len - offset, !writable).expect("view"))
    };
    let fs = fs::mount(disk, !writable, 0).unwrap_or_else(|e| panic!("mount {path}: {e}"));
    if writable && fs.read_only() {
        panic!("{path} opened read-only: {}", fs.read_only_reason().unwrap_or_default());
    }
    fs
}

/// xorshift64*: reproducible runs from a seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..len).map(|_| r.next() as u8).collect()
}

/// Every path under `dir` with its kind and content digest, from the file system.
fn snapshot(fs: &mut dyn FileSystem, dir: &str, out: &mut BTreeMap<String, String>) {
    for e in fs.list(dir).unwrap_or_else(|e| panic!("list {dir}: {e}")) {
        let p = child(dir, &e.name);
        if e.is_dir {
            out.insert(p.clone(), "dir".into());
            snapshot(fs, &p, out);
        } else {
            let mut h = Hasher(Sha256::new(), 0);
            fs.read_file(&p, &mut h, &mut |_| true).unwrap_or_else(|e| panic!("read {p}: {e}"));
            assert_eq!(h.1, e.size, "{p}: listed size {} but read {} bytes", e.size, h.1);
            let st = fs.stat(&p).unwrap_or_else(|e| panic!("stat {p}: {e}"));
            assert_eq!(st.size, e.size, "{p}: stat and list disagree");
            out.insert(p, format!("{} {}", e.size, hex(&h.0.finalize())));
        }
    }
}

fn digest(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{} {}", data.len(), hex(&h.finalize()))
}

fn verify(fs: &mut dyn FileSystem, root: &str, model: &BTreeMap<String, String>, phase: &str) {
    let mut got = BTreeMap::new();
    got.insert(root.to_string(), "dir".to_string());
    snapshot(fs, root, &mut got);
    if &got != model {
        for (k, v) in model {
            match got.get(k) {
                None => eprintln!("missing {k}"),
                Some(g) if g != v => eprintln!("differs {k}: {g} vs {v}"),
                _ => {}
            }
        }
        for k in got.keys() {
            if !model.contains_key(k) {
                eprintln!("unexpected {k}");
            }
        }
        panic!("{phase}: contents differ from the model");
    }
    let report = fs.check(false).unwrap_or_else(|e| panic!("{phase}: check: {e}"));
    if !report.clean() {
        panic!("{phase}: check found problems: {:#?}", report);
    }
    eprintln!("{phase}: {} entries match, check clean (files {}, dirs {}), free {}", model.len(), report.files, report.dirs, fs.free_bytes().unwrap_or(0));
}

fn fuzz(spec: &str, ops: usize, seed: u64) {
    let mut r = Rng(seed.max(1));
    let mut fs = open(spec, true);
    let root = "/fuzz";
    fs.mkdir(root).unwrap();
    let mut model: BTreeMap<String, String> = BTreeMap::new();
    model.insert(root.into(), "dir".into());
    let mut dirs: Vec<String> = vec![root.into()];
    let names = ["a", "B", "c d", "ملف", "Zz", "x.txt", "long name with spaces and more words", "ÄÖÜ", "日本語", "~tmp"];
    for step in 0..ops {
        let dir = dirs[r.below(dirs.len() as u64) as usize].clone();
        let name = format!("{} {}", names[r.below(names.len() as u64) as usize], r.below(400));
        let p = child(&dir, &name);
        let exists = model.keys().any(|k| k.to_lowercase() == p.to_lowercase());
        match r.below(100) {
            0..=44 => {
                let len = match r.below(8) { 0 => 0, 1..=4 => r.below(1200) as usize, 5 | 6 => r.below(20_000) as usize, _ => r.below(300_000) as usize };
                let data = content(r.next(), len);
                let res = fs.write_file(&p, &mut &data[..], len as u64, exists, &mut |_| true);
                match res {
                    Ok(()) => { model.retain(|k, _| k.to_lowercase() != p.to_lowercase()); model.insert(p.clone(), digest(&data)); }
                    Err(e) if exists => { assert!(model.iter().any(|(k, v)| k.to_lowercase() == p.to_lowercase() && v == "dir"), "step {step}: overwrite {p}: {e}"); }
                    Err(e) => panic!("step {step}: write {p}: {e}"),
                }
            }
            45..=54 => {
                if !exists && dirs.len() < 40 {
                    fs.mkdir(&p).unwrap_or_else(|e| panic!("step {step}: mkdir {p}: {e}"));
                    model.insert(p.clone(), "dir".into());
                    dirs.push(p);
                }
            }
            55..=79 => {
                let files: Vec<String> = model.keys().filter(|k| k.starts_with(&format!("{dir}/")) && !k[dir.len() + 1..].contains('/')).cloned().collect();
                if let Some(victim) = files.get(r.below(files.len().max(1) as u64) as usize) {
                    if victim == root { continue; }
                    fs.remove(victim).unwrap_or_else(|e| panic!("step {step}: remove {victim}: {e}"));
                    let gone: Vec<String> = model.keys().filter(|k| *k == victim || k.starts_with(&format!("{victim}/"))).cloned().collect();
                    for g in gone { model.remove(&g); }
                    dirs.retain(|d| d != victim && !d.starts_with(&format!("{victim}/")));
                }
            }
            80..=89 => {
                let items: Vec<String> = model.keys().filter(|k| k.starts_with(&format!("{dir}/")) && !k[dir.len() + 1..].contains('/')).cloned().collect();
                if let Some(it) = items.get(r.below(items.len().max(1) as u64) as usize).cloned() {
                    let new = if r.below(3) == 0 { it.rsplit('/').next().unwrap().to_uppercase() } else { name.clone() };
                    let target = child(&dir, &new);
                    let clash = model.keys().any(|k| k.to_lowercase() == target.to_lowercase() && k.to_lowercase() != it.to_lowercase());
                    let res = fs.rename(&it, &new);
                    if clash { assert!(res.is_err(), "step {step}: rename onto an existing name"); continue; }
                    res.unwrap_or_else(|e| panic!("step {step}: rename {it} -> {new}: {e}"));
                    let moved: Vec<(String, String)> = model.iter().filter(|(k, _)| *k == &it || k.starts_with(&format!("{it}/"))).map(|(k, v)| (k.clone(), v.clone())).collect();
                    for (k, v) in moved { model.remove(&k); model.insert(format!("{target}{}", &k[it.len()..]), v); }
                    for d in dirs.iter_mut() { if *d == it || d.starts_with(&format!("{it}/")) { *d = format!("{target}{}", &d[it.len()..]); } }
                }
            }
            _ => {
                let items: Vec<String> = model.keys().filter(|k| k.starts_with(&format!("{dir}/")) && !k[dir.len() + 1..].contains('/')).cloned().collect();
                let dest = dirs[r.below(dirs.len() as u64) as usize].clone();
                if let Some(it) = items.get(r.below(items.len().max(1) as u64) as usize).cloned() {
                    let leaf = it.rsplit('/').next().unwrap().to_string();
                    let target = child(&dest, &leaf);
                    let res = fs.move_item(&it, &dest);
                    let bad = dest == it || dest.starts_with(&format!("{it}/"));
                    let clash = dest != dir && model.keys().any(|k| k.to_lowercase() == target.to_lowercase());
                    if bad || clash { assert!(res.is_err(), "step {step}: move {it} -> {dest} should fail"); continue; }
                    res.unwrap_or_else(|e| panic!("step {step}: move {it} -> {dest}: {e}"));
                    if dest == dir { continue; }
                    let moved: Vec<(String, String)> = model.iter().filter(|(k, _)| *k == &it || k.starts_with(&format!("{it}/"))).map(|(k, v)| (k.clone(), v.clone())).collect();
                    for (k, v) in moved { model.remove(&k); model.insert(format!("{target}{}", &k[it.len()..]), v); }
                    for d in dirs.iter_mut() { if *d == it || d.starts_with(&format!("{it}/")) { *d = format!("{target}{}", &d[it.len()..]); } }
                }
            }
        }
        if step % 250 == 249 {
            verify(fs.as_mut(), root, &model, &format!("step {}", step + 1));
        }
        if step % 1000 == 999 {
            fs.flush().unwrap();
            drop(fs);
            fs = open(spec, true);
        }
    }
    verify(fs.as_mut(), root, &model, "end");
    fs.flush().unwrap();
}

fn stress(fs: &mut dyn FileSystem, root: &str, n: usize, seed: u64, keep: bool) {
    let mut r = Rng(seed.max(1));
    let mut model: BTreeMap<String, String> = BTreeMap::new();
    let free0 = fs.free_bytes().unwrap();
    let mut mk = |fs: &mut dyn FileSystem, model: &mut BTreeMap<String, String>, p: &str| {
        fs.mkdir(p).unwrap_or_else(|e| panic!("mkdir {p}: {e}"));
        model.insert(p.to_string(), "dir".into());
    };
    let put = |fs: &mut dyn FileSystem, model: &mut BTreeMap<String, String>, p: &str, data: &[u8], overwrite: bool| {
        fs.write_file(p, &mut &data[..], data.len() as u64, overwrite, &mut |_| true).unwrap_or_else(|e| panic!("write {p}: {e}"));
        model.insert(p.to_string(), digest(data));
    };
    mk(fs, &mut model, root);
    let many = child(root, "many");
    mk(fs, &mut model, &many);
    let nest = child(root, "nest");
    mk(fs, &mut model, &nest);
    let mut deep = nest.clone();
    for d in ["a", "b", "مجلد", "Mixed Case"] {
        deep = child(&deep, d);
        mk(fs, &mut model, &deep);
    }
    // Many files in one folder, created in random order.
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, r.below(i as u64 + 1) as usize);
    }
    for &i in &order {
        let len = match r.below(10) {
            0 => 0,
            1..=5 => r.below(900) as usize,
            6..=8 => 900 + r.below(6000) as usize,
            _ => 20_000 + r.below(200_000) as usize,
        };
        let name = format!("file {i:05} ملف {}.txt", r.below(1000));
        put(fs, &mut model, &child(&many, &name), &content(r.next(), len), false);
    }
    let long: String = "ط".repeat(120) + &"L".repeat(130) + ".bin";
    put(fs, &mut model, &child(root, &long), b"long name", false);
    let longdir: String = "D".repeat(200);
    mk(fs, &mut model, &child(root, &longdir));
    put(fs, &mut model, &child(&child(root, &longdir), "inside.txt"), b"in a long-named folder", false);
    put(fs, &mut model, &child(&deep, "deep.txt"), &content(7, 5000), false);
    assert!(matches!(fs.write_file(&child(&many, &order.first().map(|_| "X").unwrap_or("X")), &mut &b""[..], 0, false, &mut |_| true), Ok(())));
    model.insert(child(&many, "X"), digest(b""));
    assert!(fs.write_file(&child(&many, "x"), &mut &b"dup"[..], 3, false, &mut |_| true).is_err(), "case-insensitive duplicate accepted");
    verify(fs, root, &model, "created");

    // Delete about two thirds at random.
    let names: Vec<String> = model.keys().filter(|k| k.starts_with(&format!("{many}/"))).cloned().collect();
    for p in &names {
        if r.below(3) != 0 {
            fs.remove(p).unwrap_or_else(|e| panic!("remove {p}: {e}"));
            model.remove(p);
        }
    }
    verify(fs, root, &model, "deleted");

    // Renames (some only in case), moves, overwrites.
    let names: Vec<String> = model.keys().filter(|k| k.starts_with(&format!("{many}/"))).cloned().collect();
    for (k, p) in names.iter().enumerate() {
        match r.below(6) {
            0 => {
                let leaf = p.rsplit('/').next().unwrap();
                let new = if k % 2 == 0 { leaf.to_uppercase() } else { format!("renamed {k} {leaf}") };
                if new == leaf {
                    continue;
                }
                fs.rename(p, &new).unwrap_or_else(|e| panic!("rename {p} -> {new}: {e}"));
                let v = model.remove(p).unwrap();
                model.insert(child(&many, &new), v);
            }
            1 => {
                fs.move_item(p, &deep).unwrap_or_else(|e| panic!("move {p}: {e}"));
                let v = model.remove(p).unwrap();
                model.insert(child(&deep, p.rsplit('/').next().unwrap()), v);
            }
            2 => {
                let len = r.below(30_000) as usize;
                put(fs, &mut model, p, &content(r.next(), len), true);
            }
            _ => {}
        }
    }
    // Move a whole folder up, then rename it.
    let b = child(&child(&nest, "a"), "b");
    fs.move_item(&b, root).unwrap_or_else(|e| panic!("move folder: {e}"));
    let moved: Vec<(String, String)> = model.iter().filter(|(k, _)| k.starts_with(&b)).map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in moved {
        model.remove(&k);
        model.insert(format!("{root}/b{}", &k[b.len()..]), v);
    }
    fs.rename(&child(root, "b"), "B moved").unwrap();
    let moved: Vec<(String, String)> = model.iter().filter(|(k, _)| k.starts_with(&format!("{root}/b"))).map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in moved {
        model.remove(&k);
        model.insert(format!("{root}/B moved{}", &k[root.len() + 2..]), v);
    }
    // A big file.
    let big = content(99, 6_000_000);
    put(fs, &mut model, &child(root, "big.bin"), &big, false);
    verify(fs, root, &model, "changed");

    if keep {
        fs.flush().unwrap();
        return;
    }
    // Delete everything again.
    fs.remove(root).unwrap_or_else(|e| panic!("remove {root}: {e}"));
    fs.flush().unwrap();
    assert!(fs.stat(root).is_err());
    let report = fs.check(false).unwrap();
    assert!(report.clean(), "after removal: {report:#?}");
    let free1 = fs.free_bytes().unwrap();
    eprintln!("removed: check clean; free before {free0}, after {free1}");
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
        Some("stress") => {
            let mut fs = open(&a[2], true);
            let n = a.get(4).map_or(2000, |v| v.parse().unwrap());
            let seed = a.get(5).map_or(1, |v| v.parse().unwrap());
            stress(fs.as_mut(), &a[3], n, seed, a.get(6).is_some_and(|k| k == "keep"));
            fs.flush().unwrap();
        }
        Some("fuzz") => {
            let ops = a.get(3).map_or(3000, |v| v.parse().unwrap());
            let seed = a.get(4).map_or(1, |v| v.parse().unwrap());
            fuzz(&a[2], ops, seed);
        }
        Some("check") => {
            let mut fs = open(&a[2], false);
            let r = fs.check(false).unwrap_or_else(|e| panic!("check: {e}"));
            println!("{r:#?}");
            if !r.clean() {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: fsprobe manifest|write|format|churn|stress|check ...");
            std::process::exit(2);
        }
    }
}
