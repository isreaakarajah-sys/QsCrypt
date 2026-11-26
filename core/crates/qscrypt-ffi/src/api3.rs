//! Engine API, tools: plain (unencrypted) volumes, background filling of
//! free space, moving and copying between volumes, checks, the speed test,
//! pictures that carry an encrypted file, and secret messages.
//!
//! Same calling convention as `api2` (JSON args, secrets as blobs, files as
//! descriptors); `api2::call` hands over the methods it does not know.

use crate::api::{self, backend, file_from_fd, ok, register, Vault};
use crate::api2::{self, Call};
use qscrypt_core::crypto::Prf;
use qscrypt_core::disguise;
use qscrypt_core::fs::{self, CheckReport, FileSystem};
use qscrypt_core::identity::PublicIdentity;
use qscrypt_core::json::{array, escape, Obj};
use qscrypt_core::qsc::{Meta, Params};
use qscrypt_core::qsc2::{self, Options, Policy, Verdict};
use qscrypt_core::util::{base45_decode, base45_encode, wipe};
use qscrypt_core::vc::{CipherChain, Ea};
use qscrypt_core::{Error, Result};
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const MESSAGE_PREFIX: &str = "QSMSG1:";
/// Sealed messages up to this size fit one QR code (version 40, level M,
/// alphanumeric: 3391 characters of base45).
pub const MAX_MESSAGE_BYTES: usize = 2250;

/// Methods of this module; `None` if the method is not one of them.
pub fn call(method: &str, c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Option<Result<String>> {
    Some(match method {
        "volume.openPlain" => open_plain(c),
        "vault.zeroFree" => zero_free(c),
        "vault.check" => check(c, progress),
        "fs.move" => {
            let h = c.args.get("handle").i64_or(0);
            api::with_vault(h, |v| v.fs.move_item(c.args.get("path").str_or(""), c.args.get("dest").str_or("/")).map(|_| ok()))
        }
        "fs.copy" => copy(c, progress),
        "fs.tree" => tree(c),
        "bench.run" => bench(progress),
        "disguise.wrap" => disguise_wrap(c, progress),
        "disguise.unwrap" => disguise_unwrap(c, progress),
        "disguise.probe" => disguise_probe(c),
        "msg.seal" => msg_seal(c),
        "msg.open" => msg_open(c),
        _ => return None,
    })
}

// ------------------------------------------------------------ plain volumes

/// An unencrypted FAT, exFAT or NTFS partition (a flash drive), opened like
/// a vault so files can be copied to and from encrypted volumes.
fn open_plain(c: &Call) -> Result<String> {
    let want_ro = c.args.get("readOnly").bool_or(false);
    let tz = c.args.get("tz").i64_or(0) as i32;
    let (disk, ro) = api2::source(c, want_ro)?;
    let f = fs::mount(disk, ro, tz)?;
    let v = Vault { kind: "Plain".into(), cipher: String::new(), prf: String::new(), hidden: false, protected: false, extra: "{}".into(), fs: f };
    Ok(register(v).1)
}

// ------------------------------------------------------------ free space

/// One step of filling free space with encrypted zeros (resumable: the app
/// keeps the cursor and continues later, even after a restart).
fn zero_free(c: &Call) -> Result<String> {
    let h = c.args.get("handle").i64_or(0);
    let cursor = c.args.get("cursor").u64_or(0);
    let max = c.args.get("max").u64_or(64 << 20).clamp(1 << 20, 1 << 30);
    api::with_vault(h, |v| {
        if v.protected {
            // Free space of the outer volume holds the hidden one.
            return Err(Error::HiddenProtected);
        }
        let total = v.fs.total_bytes();
        let (next, done) = v.fs.zero_free(cursor, max)?;
        Ok(Obj::new().bool("ok", true).uint("cursor", next).bool("done", done).uint("total", total).end())
    })
}

// ------------------------------------------------------------ checks

fn report_json(r: &CheckReport, unreadable: u64) -> String {
    Obj::new()
        .bool("ok", true)
        .bool("clean", r.clean() && unreadable == 0)
        .uint("files", r.files)
        .uint("dirs", r.dirs)
        .uint("usedBytes", r.used_bytes)
        .uint("lostClusters", r.lost_clusters)
        .uint("crossLinked", r.cross_linked)
        .uint("badChains", r.bad_chains)
        .uint("sizeMismatches", r.size_mismatches)
        .uint("bitmapErrors", r.bitmap_errors)
        .uint("checksumErrors", r.checksum_errors)
        .bool("freeCountWrong", r.free_count_wrong)
        .uint("repaired", r.repaired)
        .uint("unreadable", unreadable)
        .raw("issues", &array(r.issues.iter().map(|s| escape(s))))
        .end()
}

/// Everything under `dir`, depth first: (path, is_dir, size).
fn walk(fs: &mut dyn FileSystem, dir: &str, out: &mut Vec<(String, bool, u64)>) -> Result<()> {
    for e in fs.list(dir)? {
        let p = join(dir, &e.name);
        out.push((p.clone(), e.is_dir, e.size));
        if e.is_dir && out.len() < 2_000_000 {
            walk(fs, &p, out)?;
        }
    }
    Ok(())
}

fn check(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let h = c.args.get("handle").i64_or(0);
    let repair = c.args.get("repair").bool_or(false);
    let deep = c.args.get("deep").bool_or(false);
    api::with_vault(h, |v| {
        if repair && v.fs.read_only() {
            return Err(Error::ReadOnly);
        }
        if repair && v.protected {
            return Err(Error::invalid("repairs are not available while the hidden volume is protected"));
        }
        let mut r = v.fs.check(repair)?;
        let mut unreadable = 0u64;
        if deep {
            // Read every file to the end: finds sectors the drive cannot read.
            let mut items = Vec::new();
            walk(v.fs.as_mut(), "/", &mut items)?;
            let total: u64 = items.iter().filter(|i| !i.1).map(|i| i.2).sum();
            let mut done = 0u64;
            for (path, is_dir, size) in items {
                if is_dir {
                    continue;
                }
                let start = done;
                match v.fs.read_file(&path, &mut std::io::sink(), &mut |n| progress(start + n, total)) {
                    Ok(_) => {}
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(e) => {
                        unreadable += 1;
                        if r.issues.len() < 50 {
                            r.issues.push(format!("{path}: {e}"));
                        }
                    }
                }
                done = start + size;
                if !progress(done, total) {
                    return Err(Error::Cancelled);
                }
            }
        }
        Ok(report_json(&r, unreadable))
    })
}

// ------------------------------------------------------------ moving and copying

fn join(dir: &str, name: &str) -> String {
    let d = dir.trim_end_matches('/');
    format!("{d}/{name}")
}

fn leaf(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

/// Files and folders under a path, with the total size of the files.
fn tree(c: &Call) -> Result<String> {
    let h = c.args.get("handle").i64_or(0);
    let path = c.args.get("path").str_or("/").to_string();
    api::with_vault(h, |v| {
        let mut items = Vec::new();
        if path.trim_end_matches('/').is_empty() {
            walk(v.fs.as_mut(), "/", &mut items)?;
        } else {
            let st = v.fs.stat(&path)?;
            items.push((path.clone(), st.is_dir, st.size));
            if st.is_dir {
                walk(v.fs.as_mut(), &path, &mut items)?;
            }
        }
        let total: u64 = items.iter().filter(|i| !i.1).map(|i| i.2).sum();
        let files = items.iter().filter(|i| !i.1).count() as u64;
        Ok(Obj::new().bool("ok", true).uint("total", total).uint("files", files).uint("items", items.len() as u64).end())
    })
}

/// Hands 1 MiB blocks to the thread that writes them.
struct ChanWriter {
    tx: SyncSender<std::io::Result<Vec<u8>>>,
    buf: Vec<u8>,
}

impl ChanWriter {
    fn send(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let block = std::mem::replace(&mut self.buf, Vec::with_capacity(1 << 20));
        self.tx.send(Ok(block)).map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the copy stopped"))
    }
}

impl Write for ChanWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 1 << 20 {
            self.send()?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.send()
    }
}

struct ChanReader {
    rx: Receiver<std::io::Result<Vec<u8>>>,
    cur: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.cur.len() {
            match self.rx.recv() {
                Ok(Ok(block)) => {
                    wipe(&mut self.cur);
                    self.cur = block;
                    self.pos = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.cur.len() - self.pos);
        out[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Drop for ChanReader {
    fn drop(&mut self) {
        wipe(&mut self.cur);
    }
}

const SPOOL_CHUNK: usize = 1 << 20;

/// A temporary file encrypted with a key that only lives in memory, for
/// copies inside one volume (it cannot be read and written at once).
struct Spool {
    file: std::fs::File,
    path: std::path::PathBuf,
    key: [u8; 32],
    salt: [u8; 16],
    chunks: u64,
    buf: Vec<u8>,
}

impl Spool {
    fn new(dir: &str) -> Result<Spool> {
        let mut id = [0u8; 8];
        backend().fill_random(&mut id)?;
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::path::Path::new(dir).join(format!("copy-{name}.tmp"));
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        backend().fill_random(&mut key)?;
        backend().fill_random(&mut salt)?;
        Ok(Spool { file, path, key, salt, chunks: 0, buf: Vec::with_capacity(SPOOL_CHUNK) })
    }

    fn nonce(&self, i: u64) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[..16].copy_from_slice(&self.salt);
        n[16..].copy_from_slice(&i.to_le_bytes());
        n
    }

    fn seal(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let n = self.nonce(self.chunks);
        let tag = backend().xchacha_seal(&self.key, &n, &[], &mut self.buf).map_err(|e| std::io::Error::other(e.to_string()))?;
        self.file.write_all(&(self.buf.len() as u32).to_le_bytes())?;
        self.file.write_all(&self.buf)?;
        self.file.write_all(&tag)?;
        self.chunks += 1;
        self.buf.clear();
        Ok(())
    }

    /// Ends writing; the spool is then read from the start.
    fn rewind(&mut self) -> Result<SpoolReader<'_>> {
        self.seal()?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(SpoolReader { s: self, index: 0, cur: Vec::new(), pos: 0 })
    }
}

impl Write for Spool {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(SPOOL_CHUNK - self.buf.len());
            self.buf.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            if self.buf.len() == SPOOL_CHUNK {
                self.seal()?;
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.buf);
        let _ = std::fs::remove_file(&self.path);
    }
}

struct SpoolReader<'a> {
    s: &'a mut Spool,
    index: u64,
    cur: Vec<u8>,
    pos: usize,
}

impl Read for SpoolReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.cur.len() {
            if self.index >= self.s.chunks {
                return Ok(0);
            }
            let mut len = [0u8; 4];
            self.s.file.read_exact(&mut len)?;
            let len = u32::from_le_bytes(len) as usize;
            if len > SPOOL_CHUNK {
                return Err(std::io::Error::other("damaged copy buffer"));
            }
            let mut data = vec![0u8; len];
            self.s.file.read_exact(&mut data)?;
            let mut tag = [0u8; 16];
            self.s.file.read_exact(&mut tag)?;
            let n = self.s.nonce(self.index);
            backend().xchacha_open(&self.s.key, &n, &[], &mut data, &tag).map_err(|_| std::io::Error::other("the copy buffer was modified"))?;
            wipe(&mut self.cur);
            self.cur = data;
            self.pos = 0;
            self.index += 1;
        }
        let n = out.len().min(self.cur.len() - self.pos);
        out[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Drop for SpoolReader<'_> {
    fn drop(&mut self) {
        wipe(&mut self.cur);
    }
}

/// What to do when the destination already has an item of that name.
#[derive(Clone, Copy, PartialEq)]
enum Existing {
    Fail,
    Overwrite,
    /// Skip files of the same size (copied by an earlier, interrupted run).
    Resume,
}

/// Copies between two volumes hold both of them; one copy at a time keeps
/// two copies in opposite directions from waiting on each other.
static COPY: Mutex<()> = Mutex::new(());

fn lock(v: &Arc<Mutex<Vault>>) -> std::sync::MutexGuard<'_, Vault> {
    v.lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(clippy::too_many_arguments)]
fn copy_file(
    src: &Arc<Mutex<Vault>>,
    dst: &Arc<Mutex<Vault>>,
    same: bool,
    from: &str,
    to: &str,
    size: u64,
    existing: Existing,
    spool_dir: &str,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<bool> {
    {
        let mut d = lock(dst);
        if size > d.fs.max_file_size() {
            return Err(Error::unsupported(format!("{from}: files over 4 GB on {}", d.fs.kind())));
        }
        if let Ok(st) = d.fs.stat(to) {
            match existing {
                Existing::Fail => return Err(Error::AlreadyExists),
                Existing::Resume if !st.is_dir && st.size == size => return Ok(false),
                _ if st.is_dir => return Err(Error::IsADirectory),
                _ => {}
            }
        }
    }
    let overwrite = existing != Existing::Fail;
    if same {
        // Through an encrypted spool: read it all, then write it back.
        let mut spool = Spool::new(spool_dir)?;
        lock(src).fs.read_file(from, &mut spool, &mut |n| progress(n / 2))?;
        let mut r = spool.rewind()?;
        lock(dst).fs.write_file(to, &mut r, size, overwrite, &mut |n| progress(size / 2 + n - n / 2))?;
        return Ok(true);
    }
    // Two volumes: one thread reads and decrypts while this one encrypts and writes.
    let (tx, rx) = sync_channel::<std::io::Result<Vec<u8>>>(3);
    let src2 = Arc::clone(src);
    let from2 = from.to_string();
    let reader = std::thread::spawn(move || {
        let mut v = lock(&src2);
        let mut w = ChanWriter { tx: tx.clone(), buf: Vec::with_capacity(1 << 20) };
        let r = v.fs.read_file(&from2, &mut w, &mut |_| true).and_then(|_| w.flush().map_err(Error::from));
        wipe(&mut w.buf);
        if let Err(e) = r {
            let _ = tx.send(Err(std::io::Error::other(e.to_string())));
        }
    });
    let result = {
        let mut r = ChanReader { rx, cur: Vec::new(), pos: 0 };
        let mut d = lock(dst);
        d.fs.write_file(to, &mut r, size, overwrite, progress)
        // `r` is dropped here, which stops a reader that is still sending.
    };
    let _ = reader.join();
    result.map(|_| true)
}

/// Copies a file or a folder (with everything in it) into a folder of the
/// same or another open volume.
fn copy(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let from = c.args.get("from").i64_or(0);
    let to = c.args.get("to").i64_or(0);
    let path = c.args.get("path").str_or("").trim_end_matches('/').to_string();
    let dest = c.args.get("dest").str_or("/").to_string();
    let spool_dir = c.args.get("spool").str_or("").to_string();
    let existing = match c.args.get("existing").str_or("fail") {
        "overwrite" => Existing::Overwrite,
        "resume" => Existing::Resume,
        _ => Existing::Fail,
    };
    if path.is_empty() {
        return Err(Error::invalid("choose the files or folders to copy"));
    }
    let src = api::vault(from)?;
    let dst = api::vault(to)?;
    let same = from == to;
    if same && spool_dir.is_empty() {
        return Err(Error::invalid("a spool folder is needed to copy inside one volume"));
    }
    if same && (dest.trim_end_matches('/') == path || dest.starts_with(&format!("{path}/"))) {
        return Err(Error::invalid("cannot copy a folder into itself"));
    }
    let _one_at_a_time = COPY.lock().unwrap_or_else(|e| e.into_inner());
    let mut items = Vec::new();
    {
        let mut v = lock(&src);
        let st = v.fs.stat(&path)?;
        items.push((path.clone(), st.is_dir, st.size));
        if st.is_dir {
            walk(v.fs.as_mut(), &path, &mut items)?;
        }
    }
    let total: u64 = items.iter().filter(|i| !i.1).map(|i| i.2).sum();
    let name = match c.args.get("name").str_or("") {
        "" => leaf(&path).to_string(),
        n => n.to_string(),
    };
    let base = join(&dest, &name);
    {
        let mut d = lock(&dst);
        if d.fs.read_only() {
            return Err(Error::ReadOnly);
        }
        if existing == Existing::Fail && d.fs.stat(&base).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if existing != Existing::Resume && d.fs.free_bytes()? < total {
            return Err(Error::NoSpace);
        }
    }
    let mut done = 0u64;
    let (mut files, mut skipped) = (0u64, 0u64);
    for (p, is_dir, size) in items {
        let target = format!("{base}{}", &p[path.len()..]);
        if is_dir {
            match lock(&dst).fs.mkdir(&target) {
                Ok(()) | Err(Error::AlreadyExists) => {}
                Err(e) => return Err(e),
            }
            continue;
        }
        let start = done;
        if !progress(start, total) {
            return Err(Error::Cancelled);
        }
        let copied = copy_file(&src, &dst, same, &p, &target, size, existing, &spool_dir, &mut |n| progress(start + n, total))?;
        if copied {
            files += 1;
        } else {
            skipped += 1;
        }
        done += size;
    }
    lock(&dst).fs.flush()?;
    progress(total, total);
    Ok(Obj::new().bool("ok", true).uint("files", files).uint("skipped", skipped).uint("bytes", done).str("path", &base).end())
}

// ------------------------------------------------------------ speed test

/// Speeds of the ciphers on this device and the time key derivation takes.
fn bench(progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let b = backend();
    let mut key = [0u8; 192];
    b.fill_random(&mut key)?;
    let mut buf = vec![0u8; 1 << 20];
    b.fill_random(&mut buf)?;
    let steps = Ea::ALL.len() as u64 + 3;
    let mut ciphers = Vec::new();
    for (i, ea) in Ea::ALL.iter().enumerate() {
        if !progress(i as u64, steps) {
            return Err(Error::Cancelled);
        }
        let chain = CipherChain::new(b, *ea, &key)?;
        let start = Instant::now();
        let mut bytes = 0u64;
        let mut unit = 0u64;
        while start.elapsed().as_millis() < 350 {
            chain.encrypt(&mut buf, 512, unit);
            unit += (buf.len() / 512) as u64;
            bytes += buf.len() as u64;
        }
        let secs = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let mut dbytes = 0u64;
        while start.elapsed().as_millis() < 150 {
            chain.decrypt(&mut buf, 512, 0);
            dbytes += buf.len() as u64;
        }
        let enc = bytes as f64 / secs / 1e6;
        let dec = dbytes as f64 / start.elapsed().as_secs_f64() / 1e6;
        ciphers.push(Obj::new().str("name", ea.name()).raw("encrypt", &format!("{enc:.1}")).raw("decrypt", &format!("{dec:.1}")).end());
    }
    // QsCrypt files: AES and Twofish streams, then XChaCha20-Poly1305.
    if !progress(Ea::ALL.len() as u64, steps) {
        return Err(Error::Cancelled);
    }
    let data = vec![7u8; 24 << 20];
    let opts = Options {
        password: Some(b"speed test"),
        duress: None,
        recovery: None,
        recipients: &[],
        signer: None,
        policy: Policy::default(),
        params: Params { memory_kib: 64, iterations: 1, lanes: 1, ..Params::default() },
    };
    let meta = Meta { name: "speed".into(), modified: 0, size: data.len() as u64 };
    let start = Instant::now();
    qsc2::encrypt(b, &opts, &meta, 0, &mut &data[..], &mut std::io::sink(), &mut |_, _| true)?;
    let qsc = data.len() as f64 / start.elapsed().as_secs_f64() / 1e6;
    // Key derivation when opening: QsCrypt (Argon2id) and VeraCrypt (PBKDF2).
    if !progress(Ea::ALL.len() as u64 + 1, steps) {
        return Err(Error::Cancelled);
    }
    let start = Instant::now();
    let mut out = [0u8; 32];
    let p = Params::default();
    b.argon2id(b"speed test", &[1u8; 16], p.memory_kib, p.iterations, p.lanes, &mut out)?;
    let argon = start.elapsed().as_millis() as u64;
    if !progress(Ea::ALL.len() as u64 + 2, steps) {
        return Err(Error::Cancelled);
    }
    let start = Instant::now();
    let mut header_key = [0u8; 192];
    qscrypt_core::kdf::pbkdf2(b, Prf::Sha512, b"speed test", &[2u8; 64], 500_000, &mut header_key, &AtomicBool::new(false))?;
    let pbkdf2 = start.elapsed().as_millis() as u64;
    wipe(&mut header_key);
    progress(steps, steps);
    Ok(Obj::new()
        .bool("ok", true)
        .raw("ciphers", &array(ciphers))
        .raw("qscrypt", &format!("{qsc:.1}"))
        .uint("argon2Ms", argon)
        .uint("pbkdf2Ms", pbkdf2)
        .uint("threads", std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(1))
        .str("backend", b.name())
        .end())
}

// ------------------------------------------------------------ pictures

/// A picture that opens normally and carries an encrypted file after its end.
fn disguise_wrap(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let pw = c.blob("password").unwrap_or(&[]);
    let mut cover = Vec::new();
    api2::reader(c, "cover")?.take(disguise::MAX_COVER + 1).read_to_end(&mut cover)?;
    if cover.len() as u64 > disguise::MAX_COVER {
        return Err(Error::invalid("the cover picture is too large"));
    }
    let mut input = api2::reader(c, "in")?;
    let len = match c.args.get("size").u64_or(0) {
        0 => input.get_ref().metadata().map(|m| m.len()).unwrap_or(0),
        n => n,
    };
    let out_fd = c.fd("out").ok_or_else(|| Error::invalid("missing output"))?;
    let out_file = file_from_fd(out_fd)?;
    let _ = out_file.set_len(0);
    let mut out = BufWriter::with_capacity(1 << 20, out_file);
    let kind = disguise::wrap(backend(), &cover, &mut input, len, &mut out, pw, progress)?;
    out.flush()?;
    let _ = out.get_ref().sync_all();
    Ok(Obj::new().bool("ok", true).str("kind", kind.name()).end())
}

fn disguise_unwrap(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let pw = c.blob("password").unwrap_or(&[]);
    let fd = c.fd("in").ok_or_else(|| Error::invalid("missing input"))?;
    let mut input = file_from_fd(fd)?;
    let out_fd = c.fd("out").ok_or_else(|| Error::invalid("missing output"))?;
    let out_file = file_from_fd(out_fd)?;
    let _ = out_file.set_len(0);
    let mut out = BufWriter::with_capacity(1 << 20, out_file);
    let n = disguise::unwrap(backend(), &mut input, &mut out, pw, progress)?;
    out.flush()?;
    let _ = out.get_ref().sync_all();
    Ok(Obj::new().bool("ok", true).uint("bytes", n).end())
}

/// Whether a file is a picture with data after its end (not proof of a
/// hidden file: some cameras append data too).
fn disguise_probe(c: &Call) -> Result<String> {
    let fd = c.fd("in").ok_or_else(|| Error::invalid("missing input"))?;
    let mut input = file_from_fd(fd)?;
    let (kind, end, trailing) = match disguise::probe(&mut input)? {
        Some((k, end, trailing)) => (k.name(), end, trailing),
        None => ("", 0, 0),
    };
    Ok(Obj::new().bool("ok", true).str("kind", kind).uint("end", end).uint("trailing", trailing).end())
}

// ------------------------------------------------------------ messages

/// Seals a short text for contacts (their cards) and/or with a password, as
/// "QSMSG1:" + base45 of a QsCrypt file: it fits one QR code.
fn msg_seal(c: &Call) -> Result<String> {
    let text = c.blob("text").unwrap_or(&[]);
    if text.is_empty() {
        return Err(Error::invalid("the message is empty"));
    }
    let mut recipients = Vec::new();
    for v in c.args.get("recipients").as_arr() {
        recipients.push(PublicIdentity::parse_card(v.str_or(""))?);
    }
    let pw = c.blob("password").filter(|p| !p.is_empty());
    if pw.is_none() && recipients.is_empty() {
        return Err(Error::invalid("a password or a contact is needed"));
    }
    let signer = if c.args.get("sign").bool_or(false) { Some(api2::identity(c)?) } else { None };
    let opts = Options {
        password: pw,
        duress: None,
        recovery: None,
        recipients: &recipients,
        signer: signer.as_ref(),
        policy: Policy::default(),
        params: Params { chunk_size: 4096, ..Params::default() },
    };
    let meta = Meta { name: String::new(), modified: 0, size: text.len() as u64 };
    let mut out = Vec::new();
    qsc2::encrypt(backend(), &opts, &meta, 0, &mut &text[..], &mut out, &mut |_, _| true)?;
    if out.len() > MAX_MESSAGE_BYTES {
        let over = out.len() - MAX_MESSAGE_BYTES;
        return Ok(Obj::new().bool("ok", false).str("code", "too_long").str("message", "the message does not fit one QR code").uint("over", over as u64).end());
    }
    let s = format!("{MESSAGE_PREFIX}{}", base45_encode(&out));
    Ok(Obj::new().bool("ok", true).str("text", &s).uint("bytes", out.len() as u64).end())
}

/// The base45 text after the prefix, wherever the prefix is in `raw`.
fn message_body(raw: &str) -> Option<String> {
    let i = raw.find(MESSAGE_PREFIX)?;
    let mut body = String::new();
    for ch in raw[i + MESSAGE_PREFIX.len()..].chars() {
        match ch {
            '\r' | '\n' | '\t' => continue,
            '0'..='9' | 'A'..='Z' | ' ' | '$' | '%' | '*' | '+' | '-' | '.' | '/' | ':' => body.push(ch),
            _ => break,
        }
    }
    Some(body)
}

fn msg_open(c: &Call) -> Result<String> {
    let body = message_body(c.args.get("text").str_or("")).ok_or_else(|| Error::invalid("not a QsCrypt message"))?;
    let bytes = base45_decode(&body).ok_or_else(|| Error::corrupt("damaged message"))?;
    let mut input = Cursor::new(&bytes[..]);
    let h = qsc2::read_header(&mut input)?;
    if h.flags & qsc2::FLAG_CONTAINER != 0 {
        return Err(Error::corrupt("not a QsCrypt message"));
    }
    if !matches!(h.evaluate(&api2::context(c)), Verdict::Allow) {
        return Err(Error::invalid("this message cannot be opened here"));
    }
    let u = api2::unlock_and(c, |how| qsc2::unlock(backend(), &h, how))?;
    if u.duress {
        return Err(Error::WrongPassword);
    }
    let mut out = Vec::new();
    let d = qsc2::decrypt(backend(), &h, &u.file_key, &mut input, Some(&mut out), &mut |_, _| true)?;
    let text = String::from_utf8(out).map_err(|e| {
        let mut b = e.into_bytes();
        wipe(&mut b);
        Error::corrupt("the message is not text")
    })?;
    let signer = d.signer.map(|k| k.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_default();
    let json = Obj::new()
        .bool("ok", true)
        .str("text", &text)
        .bool("password", h.password_slots > 0)
        .uint("recipients", h.recipients as u64)
        .bool("signed", h.signed())
        .bool("signatureValid", d.signature_valid)
        .str("signer", &signer)
        .int("sealed", h.created)
        .end();
    let mut t = text.into_bytes();
    wipe(&mut t);
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qscrypt_core::util::Secret;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qscrypt-api3-{}-{name}", std::process::id()));
        p
    }

    fn handle(json: &str) -> i64 {
        json.split("\"handle\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap()
    }

    fn field<'a>(json: &'a str, key: &str) -> &'a str {
        let k = format!("\"{key}\":");
        let rest = json.split(&k).nth(1).unwrap_or_else(|| panic!("{key} missing in {json}"));
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        rest.split(['"', ',', '}']).next().unwrap()
    }

    /// A VeraCrypt volume file, opened; returns (path, handle).
    fn volume(name: &str, mib: u64, fs: &str) -> (std::path::PathBuf, i64) {
        let path = tmp(name);
        let f = File::options().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let blobs = [Secret::from_slice(b"pw")];
        let args = format!("{{\"src\":{{\"fd\":0}},\"format\":\"veracrypt\",\"size\":{},\"password\":0,\"ea\":1,\"prf\":1,\"fs\":\"{fs}\",\"quick\":true}}", mib << 20);
        let r = api2::call("volume.create", &args, &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let r = api2::call("volume.open", "{\"src\":{\"fd\":0},\"password\":0}", &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        (path, handle(&r))
    }

    fn put(h: i64, path: &str, data: &[u8]) {
        api::with_vault(h, |v| v.fs.write_file(path, &mut &data[..], data.len() as u64, false, &mut |_| true)).unwrap();
    }

    fn get(h: i64, path: &str) -> Vec<u8> {
        api::read_file(h, path, 1 << 30).unwrap()
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32) as u8 ^ seed).collect()
    }

    #[test]
    fn copy_between_volumes_and_inside_one() {
        let (pa, a) = volume("a.hc", 24, "fat");
        let (pb, b) = volume("b.hc", 24, "exfat");
        let big = pattern(3 << 20 | 12345, 7);
        api::with_vault(a, |v| v.fs.mkdir("/docs")).unwrap();
        api::with_vault(a, |v| v.fs.mkdir("/docs/sub")).unwrap();
        put(a, "/docs/big.bin", &big);
        put(a, "/docs/sub/note.txt", "ملاحظة".as_bytes());
        put(a, "/docs/empty", b"");

        // Between two volumes, a whole folder.
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs\",\"to\":{b},\"dest\":\"/\"}}"), &[], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(field(&r, "files"), "3");
        assert_eq!(get(b, "/docs/big.bin"), big);
        assert_eq!(get(b, "/docs/sub/note.txt"), "ملاحظة".as_bytes());
        assert_eq!(get(b, "/docs/empty"), b"");

        // Again: refused, then resumed (everything skipped), then overwritten.
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs\",\"to\":{b},\"dest\":\"/\"}}"), &[], &[], &mut |_, _| true);
        assert!(r.contains("\"code\":\"exists\""), "{r}");
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs\",\"to\":{b},\"dest\":\"/\",\"existing\":\"resume\"}}"), &[], &[], &mut |_, _| true);
        assert_eq!(field(&r, "skipped"), "3", "{r}");
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs/big.bin\",\"to\":{b},\"dest\":\"/docs\",\"existing\":\"overwrite\"}}"), &[], &[], &mut |_, _| true);
        assert_eq!(field(&r, "files"), "1", "{r}");
        assert_eq!(get(b, "/docs/big.bin"), big);

        // Cancelled midway: no partial file is left.
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs/big.bin\",\"to\":{b},\"dest\":\"/\"}}"), &[], &[], &mut |d, _| d < (1 << 20));
        assert!(r.contains("\"code\":\"cancelled\""), "{r}");
        assert!(api::with_vault(b, |v| v.fs.stat("/big.bin")).is_err());

        // Inside one volume, through the encrypted spool.
        let spool = std::env::temp_dir();
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs\",\"to\":{a},\"dest\":\"/\",\"name\":\"docs copy\",\"spool\":{}}}", escape(spool.to_str().unwrap())), &[], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(get(a, "/docs copy/big.bin"), big);
        assert_eq!(get(a, "/docs copy/sub/note.txt"), "ملاحظة".as_bytes());
        let r = api2::call("fs.copy", &format!("{{\"from\":{a},\"path\":\"/docs\",\"to\":{a},\"dest\":\"/docs/sub\",\"spool\":{}}}", escape(spool.to_str().unwrap())), &[], &[], &mut |_, _| true);
        assert!(r.contains("into itself"), "{r}");
        let leftovers = std::fs::read_dir(&spool).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("copy-")).count();
        assert_eq!(leftovers, 0);

        // Move inside a volume, then check both volumes.
        let r = api2::call("fs.move", &format!("{{\"handle\":{a},\"path\":\"/docs copy/sub\",\"dest\":\"/\"}}"), &[], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(get(a, "/sub/note.txt"), "ملاحظة".as_bytes());
        for h in [a, b] {
            let r = api2::call("vault.check", &format!("{{\"handle\":{h},\"deep\":true}}"), &[], &[], &mut |_, _| true);
            assert!(r.contains("\"clean\":true"), "{r}");
        }
        let r = api2::call("fs.tree", &format!("{{\"handle\":{b},\"path\":\"/\"}}"), &[], &[], &mut |_, _| true);
        assert_eq!(field(&r, "files"), "3", "{r}");
        api::close_volume(a);
        api::close_volume(b);
        let _ = std::fs::remove_file(pa);
        let _ = std::fs::remove_file(pb);
    }

    #[test]
    fn zero_free_steps_until_done() {
        let (p, h) = volume("z.hc", 12, "exfat");
        put(h, "/keep.bin", &pattern(200_000, 3));
        let mut cursor = 0u64;
        let mut steps = 0;
        loop {
            let r = api2::call("vault.zeroFree", &format!("{{\"handle\":{h},\"cursor\":{cursor},\"max\":1048576}}"), &[], &[], &mut |_, _| true);
            assert!(r.contains("\"ok\":true"), "{r}");
            cursor = field(&r, "cursor").parse().unwrap();
            steps += 1;
            if field(&r, "done") == "true" {
                break;
            }
            assert!(steps < 100, "{r}");
        }
        assert!(steps > 3);
        assert_eq!(get(h, "/keep.bin"), pattern(200_000, 3));
        api::close_volume(h);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn messages_for_a_password_and_for_contacts() {
        let pw = Secret::from_slice(b"meet at 5");
        let text = Secret::from_slice("السلام عليكم — the plan is on".as_bytes());
        let r = api2::call("msg.seal", "{\"text\":0,\"password\":1}", &[text.clone(), pw.clone()], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let sealed = field(&r, "text").to_string();
        assert!(sealed.starts_with(MESSAGE_PREFIX));
        assert!(sealed.len() < 600, "{}", sealed.len());
        // Pasted with a newline and surrounding words.
        let pasted = format!("look: {}\n", sealed);
        let r = api2::call("msg.open", &format!("{{\"text\":{},\"password\":0}}", escape(&pasted)), &[pw.clone()], &[], &mut |_, _| true);
        assert!(r.contains("السلام عليكم"), "{r}");
        let r = api2::call("msg.open", &format!("{{\"text\":{},\"password\":0}}", escape(&sealed)), &[Secret::from_slice(b"wrong")], &[], &mut |_, _| true);
        assert!(r.contains("wrong_password"), "{r}");

        // For a contact, signed by the sender.
        let sender = api2::call_bytes("id.generate", "{\"name\":\"S\"}", &[], &[]).unwrap();
        let friend = api2::call_bytes("id.generate", "{\"name\":\"F\"}", &[], &[]).unwrap();
        let card = field(&api2::call("id.public", "{\"identity\":0}", &[Secret::from_slice(&friend)], &[], &mut |_, _| true), "card").to_string();
        let r = api2::call("msg.seal", &format!("{{\"text\":0,\"recipients\":[{}],\"sign\":true,\"identity\":1}}", escape(&card)), &[text.clone(), Secret::from_slice(&sender)], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let sealed = field(&r, "text").to_string();
        eprintln!("message for one contact: {} bytes, {} characters", field(&r, "bytes"), sealed.len());
        let r = api2::call("msg.open", &format!("{{\"text\":{},\"unlock\":\"identity\",\"identity\":0}}", escape(&sealed)), &[Secret::from_slice(&friend)], &[], &mut |_, _| true);
        assert!(r.contains("the plan is on") && r.contains("\"signatureValid\":true"), "{r}");
        let r = api2::call("msg.open", &format!("{{\"text\":{},\"unlock\":\"identity\",\"identity\":0}}", escape(&sealed)), &[Secret::from_slice(&sender)], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":false"), "{r}");

        // Too long for one QR code.
        let long = Secret::from_slice(&vec![b'x'; 3000]);
        let r = api2::call("msg.seal", "{\"text\":0,\"password\":1}", &[long, pw], &[], &mut |_, _| true);
        assert!(r.contains("too_long"), "{r}");
    }

    #[test]
    fn pictures_carry_files() {
        // A real (tiny) PNG made by hand: signature, IHDR, IDAT, IEND.
        let png = {
            let mut p = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
            for (ty, data) in [(&b"IHDR"[..], &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0][..]), (&b"IDAT"[..], &[0x78, 0x9C, 0x63, 0, 0, 0, 1, 0, 1][..]), (&b"IEND"[..], &[][..])] {
                p.extend_from_slice(&(data.len() as u32).to_be_bytes());
                p.extend_from_slice(ty);
                p.extend_from_slice(data);
                p.extend_from_slice(&[0, 0, 0, 0]);
            }
            p
        };
        let (cover, plain, out, back) = (tmp("cover.png"), tmp("plain.bin"), tmp("out.png"), tmp("back.bin"));
        std::fs::write(&cover, &png).unwrap();
        let data = pattern(2_500_000, 9);
        std::fs::write(&plain, &data).unwrap();
        let (fc, fp, fo) = (File::open(&cover).unwrap(), File::open(&plain).unwrap(), File::create(&out).unwrap());
        let pw = Secret::from_slice(b"picture pw");
        let r = api2::call("disguise.wrap", "{\"cover\":0,\"in\":1,\"out\":2,\"password\":0}", &[pw.clone()], &[fc.as_raw_fd(), fp.as_raw_fd(), fo.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"kind\":\"png\""), "{r}");
        let wrapped = std::fs::read(&out).unwrap();
        assert_eq!(&wrapped[..png.len()], &png[..]);
        let fo = File::open(&out).unwrap();
        let r = api2::call("disguise.probe", "{\"in\":0}", &[], &[fo.as_raw_fd()], &mut |_, _| true);
        assert_eq!(field(&r, "end"), png.len().to_string(), "{r}");
        let (fo, fb) = (File::open(&out).unwrap(), File::create(&back).unwrap());
        let r = api2::call("disguise.unwrap", "{\"in\":0,\"out\":1,\"password\":0}", &[pw], &[fo.as_raw_fd(), fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(std::fs::read(&back).unwrap(), data);
        let (fo, fb) = (File::open(&out).unwrap(), File::create(&back).unwrap());
        let r = api2::call("disguise.unwrap", "{\"in\":0,\"out\":1,\"password\":0}", &[Secret::from_slice(b"nope")], &[fo.as_raw_fd(), fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("wrong_password"), "{r}");
        for p in [cover, plain, out, back] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn bench_reports_every_cipher() {
        let r = api2::call("bench.run", "{}", &[], &[], &mut |_, _| true);
        assert!(r.contains("\"ok\":true") && r.contains("Serpent-Twofish-AES") && r.contains("pbkdf2Ms"), "{r}");
        eprintln!("{r}");
    }
}
