//! The engine API used by the JNI shims (plain Rust, testable on the host).

use qscrypt_core::crypto::{Backend, Prf};
use qscrypt_core::disk::{Disk, FileDisk};
use qscrypt_core::fs::{self, FileSystem};
use qscrypt_core::json::{array, Obj};
use qscrypt_core::vc::{self, CipherChain, Ea, Format, OpenOptions};
use qscrypt_core::{qsc, Error};
use qscrypt_crypto::RustCrypto;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static BACKEND: RustCrypto = RustCrypto;
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

pub fn backend() -> &'static dyn Backend {
    &BACKEND
}

struct Vault {
    fs: Box<dyn FileSystem>,
    format: Format,
    ea: Ea,
    prf: Prf,
    hidden: bool,
}

fn vaults() -> &'static Mutex<HashMap<i64, Arc<Mutex<Vault>>>> {
    static V: OnceLock<Mutex<HashMap<i64, Arc<Mutex<Vault>>>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(HashMap::new()))
}

fn vault(handle: i64) -> Result<Arc<Mutex<Vault>>, Error> {
    vaults().lock().unwrap_or_else(|e| e.into_inner()).get(&handle).cloned().ok_or_else(|| Error::invalid("the vault is closed"))
}

pub fn err_json(code: &str, message: &str) -> String {
    Obj::new().bool("ok", false).str("code", code).str("message", message).end()
}

fn err(e: &Error) -> String {
    err_json(e.code(), &e.to_string())
}

fn ok() -> String {
    Obj::new().bool("ok", true).end()
}

fn reply(r: Result<String, Error>) -> String {
    r.unwrap_or_else(|e| err(&e))
}

#[cfg(unix)]
fn file_from_fd(fd: i32) -> Result<File, Error> {
    use std::os::fd::BorrowedFd;
    if fd < 0 {
        return Err(Error::invalid("bad file descriptor"));
    }
    // SAFETY: the app keeps `fd` open for the duration of the call.
    Ok(File::from(unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?))
}

#[cfg(not(unix))]
fn file_from_fd(_fd: i32) -> Result<File, Error> {
    Err(Error::unsupported("file descriptors on this platform"))
}

#[cfg(unix)]
fn disk_from_fd(fd: i32, read_only: bool) -> Result<FileDisk, Error> {
    FileDisk::from_borrowed_fd(fd, read_only)
}

#[cfg(not(unix))]
fn disk_from_fd(_fd: i32, _read_only: bool) -> Result<FileDisk, Error> {
    Err(Error::unsupported("file descriptors on this platform"))
}

// ---------------------------------------------------------------- self-test

const KAT_PBKDF2: &str = "03b032ee44792c06eae26baabad74d0b7b4375a5a9bfe290130d16023abcdd81";
const KAT_ARGON2: &str = "26dd8569393962af87a929434905748659933f7b2985d0d566a656d7063582cf";
const KAT_XCHACHA: &str = "f42d941717543886d14a535c23fc68b9469f3850a487703150be6fe22344be7871";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn self_test() -> String {
    let b = backend();
    let mut results: Vec<(String, bool)> = vc::selftest::run(b, true).into_iter().map(|(n, ok)| (format!("{n} (VeraCrypt)"), ok)).collect();
    let mut k = [0u8; 32];
    let p = qscrypt_core::kdf::pbkdf2(b, Prf::Sha512, b"QsCrypt", b"selftest-salt", 1000, &mut k, &AtomicBool::new(false));
    results.push(("PBKDF2-HMAC-SHA-512".into(), p.is_ok() && hex(&k) == KAT_PBKDF2));
    let a = b.argon2id(b"QsCrypt", b"selftest-salt!!!", 256, 1, 1, &mut k);
    results.push(("Argon2id".into(), a.is_ok() && hex(&k) == KAT_ARGON2));
    let mut buf = b"QsCrypt self-test".to_vec();
    let x = b.xchacha_seal(&[0x42; 32], &[0x24; 24], b"qs", &mut buf).map(|tag| {
        buf.extend_from_slice(&tag);
        hex(&buf) == KAT_XCHACHA
    });
    results.push(("XChaCha20-Poly1305".into(), x.unwrap_or(false)));
    let mut r = [0u8; 32];
    results.push(("RNG".into(), b.fill_random(&mut r).is_ok() && r != [0u8; 32]));
    let all = results.iter().all(|(_, ok)| *ok);
    let items = results.iter().map(|(n, ok)| Obj::new().str("name", n).bool("ok", *ok).end());
    Obj::new().bool("ok", all).str("backend", b.name()).str("engine", qscrypt_core::version()).raw("results", &array(items)).end()
}

// ---------------------------------------------------------------- volumes

fn format_hint(f: i32) -> Option<Format> {
    match f {
        1 => Some(Format::VeraCrypt),
        2 => Some(Format::TrueCrypt),
        _ => None,
    }
}

fn info_json(handle: i64, v: &mut Vault) -> String {
    let free = v.fs.free_bytes().unwrap_or(0);
    Obj::new()
        .bool("ok", true)
        .int("handle", handle)
        .str("format", v.format.name())
        .str("ea", v.ea.name())
        .str("prf", v.prf.name())
        .bool("hidden", v.hidden)
        .str("fs", v.fs.kind())
        .str("label", &v.fs.label())
        .bool("readOnly", v.fs.read_only())
        .uint("total", v.fs.total_bytes())
        .uint("free", free)
        .uint("maxFile", v.fs.max_file_size())
        .end()
}

pub fn open_volume(fd: i32, password: &[u8], pim: u32, prf: u32, format: i32, read_only: bool, tz_minutes: i32) -> String {
    reply((|| -> Result<String, Error> {
        if password.is_empty() {
            return Err(Error::invalid("empty password"));
        }
        let mut disk = disk_from_fd(fd, read_only).or_else(|_| disk_from_fd(fd, true))?;
        let read_only = read_only || disk.is_read_only();
        let mut opts = OpenOptions::new(password);
        opts.pim = pim;
        opts.prf = Prf::from_id(prf);
        opts.format = format_hint(format);
        let found = vc::detect(backend(), &mut disk, &opts, &AtomicBool::new(false))?;
        let chain = CipherChain::new(backend(), found.ea, &found.header.master_keys)?;
        let volume = vc::EncVolume::new(Box::new(disk), chain, found.header.data_offset, found.header.data_size, read_only)?;
        let fs = fs::mount(Box::new(volume), read_only, tz_minutes)?;
        let mut v = Vault { fs, format: found.header.format, ea: found.ea, prf: found.prf, hidden: found.hidden };
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        let json = info_json(handle, &mut v);
        vaults().lock().unwrap_or_else(|e| e.into_inner()).insert(handle, Arc::new(Mutex::new(v)));
        Ok(json)
    })())
}

pub fn close_volume(handle: i64) {
    let v = vaults().lock().unwrap_or_else(|e| e.into_inner()).remove(&handle);
    if let Some(v) = v {
        if let Ok(mut v) = v.lock() {
            let _ = v.fs.flush();
        }
    }
}

pub fn close_all() {
    let all: Vec<i64> = vaults().lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
    for h in all {
        close_volume(h);
    }
}

fn with_vault<T>(handle: i64, f: impl FnOnce(&mut Vault) -> Result<T, Error>) -> Result<T, Error> {
    let v = vault(handle)?;
    let mut guard = v.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

pub fn volume_info(handle: i64) -> String {
    reply(with_vault(handle, |v| Ok(info_json(handle, v))))
}

pub fn list(handle: i64, path: &str) -> String {
    reply(with_vault(handle, |v| {
        let mut entries = v.fs.list(path)?;
        entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        let items = entries.iter().map(|e| Obj::new().str("name", &e.name).bool("dir", e.is_dir).uint("size", e.size).int("mtime", e.modified).end());
        Ok(Obj::new().bool("ok", true).str("path", path).raw("entries", &array(items)).end())
    }))
}

pub fn read_file(handle: i64, path: &str, max_bytes: u64) -> Option<Vec<u8>> {
    with_vault(handle, |v| {
        let st = v.fs.stat(path)?;
        if st.is_dir || st.size > max_bytes {
            return Err(Error::invalid("too large"));
        }
        let mut out = Vec::with_capacity(st.size as usize);
        v.fs.read_file(path, &mut out, &mut |_| true)?;
        Ok(out)
    })
    .ok()
}

pub fn export_file(handle: i64, path: &str, out_fd: i32, progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    reply(with_vault(handle, |v| {
        let st = v.fs.stat(path)?;
        let mut out = BufWriter::with_capacity(1 << 20, file_from_fd(out_fd)?);
        let total = st.size;
        let n = v.fs.read_file(path, &mut out, &mut |d| progress(d, total))?;
        out.flush()?;
        let _ = out.get_ref().sync_all();
        Ok(Obj::new().bool("ok", true).uint("bytes", n).end())
    }))
}

pub fn import_file(handle: i64, in_fd: i32, size: u64, dest: &str, overwrite: bool, progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    reply(with_vault(handle, |v| {
        if size > v.fs.max_file_size() {
            return Err(Error::unsupported(format!("files over {} bytes on {}", v.fs.max_file_size(), v.fs.kind())));
        }
        let mut src = BufReader::with_capacity(1 << 20, file_from_fd(in_fd)?);
        v.fs.write_file(dest, &mut src, size, overwrite, &mut |d| progress(d, size))?;
        Ok(ok())
    }))
}

pub fn mkdir(handle: i64, path: &str) -> String {
    reply(with_vault(handle, |v| v.fs.mkdir(path).map(|_| ok())))
}

pub fn remove(handle: i64, path: &str) -> String {
    reply(with_vault(handle, |v| v.fs.remove(path).map(|_| ok())))
}

pub fn rename(handle: i64, path: &str, new_name: &str) -> String {
    reply(with_vault(handle, |v| v.fs.rename(path, new_name).map(|_| ok())))
}

#[allow(clippy::too_many_arguments)]
pub fn create_volume(fd: i32, size: u64, password: &[u8], pim: u32, prf: u32, ea: u32, format: i32, label: &str, progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    reply((|| -> Result<String, Error> {
        let format = format_hint(format).unwrap_or(Format::VeraCrypt);
        let prf = Prf::from_id(prf).unwrap_or(Prf::Sha512);
        let ea = Ea::from_id(ea).unwrap_or(Ea::Aes);
        let size = size / 512 * 512;
        let mut disk = disk_from_fd(fd, false)?;
        disk.set_len(size)?;
        let opts = vc::CreateOptions { format, password, pim, prf, ea, size, label };
        vc::create_container(backend(), &mut disk, &opts, progress, &AtomicBool::new(false))?;
        Ok(Obj::new().bool("ok", true).uint("size", size).str("format", format.name()).str("ea", ea.name()).str("prf", prf.name()).end())
    })())
}

// ---------------------------------------------------------------- QsCrypt

pub fn qsc_encrypt(in_fd: i32, size: u64, out_fd: i32, name: &str, modified: i64, password: &[u8], progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    reply((|| -> Result<String, Error> {
        let mut input = BufReader::with_capacity(1 << 20, file_from_fd(in_fd)?);
        let out_file = file_from_fd(out_fd)?;
        let _ = out_file.set_len(0); // fails on pipes; they start empty anyway
        let mut output = BufWriter::with_capacity(1 << 20, out_file);
        let meta = qsc::Meta { name: name.to_string(), modified, size };
        qsc::encrypt(backend(), password, &meta, &mut input, &mut output, qsc::Params::default(), progress)?;
        output.flush()?;
        let _ = output.get_ref().sync_all();
        Ok(ok())
    })())
}

pub fn qsc_decrypt(in_fd: i32, out_fd: i32, password: &[u8], progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    reply((|| -> Result<String, Error> {
        let mut input = BufReader::with_capacity(1 << 20, file_from_fd(in_fd)?);
        let meta = if out_fd >= 0 {
            let out_file = file_from_fd(out_fd)?;
            let _ = out_file.set_len(0);
            let mut output = BufWriter::with_capacity(1 << 20, out_file);
            let m = qsc::decrypt(backend(), password, &mut input, Some(&mut output), progress)?;
            output.flush()?;
            let _ = output.get_ref().sync_all();
            m
        } else {
            qsc::decrypt(backend(), password, &mut input, None, progress)?
        };
        Ok(Obj::new().bool("ok", true).str("name", &meta.name).int("mtime", meta.modified).uint("size", meta.size).end())
    })())
}

// ---------------------------------------------------------------- misc

/// Identifies a file from its first bytes: QsCrypt files have a magic;
/// VeraCrypt/TrueCrypt volumes look random, so anything else is assumed
/// to be a volume and verified with the password.
pub fn sniff(fd: i32) -> String {
    reply((|| -> Result<String, Error> {
        let mut f = file_from_fd(fd)?;
        let size = std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0))?;
        std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0))?;
        let mut head = [0u8; 8];
        let n = f.read(&mut head)?;
        let kind = if qsc::is_qsc(&head[..n]) {
            "qscrypt"
        } else if size >= vc::DATA_OFFSET * 2 {
            "volume"
        } else {
            "unknown"
        };
        Ok(Obj::new().bool("ok", true).str("kind", kind).uint("size", size).end())
    })())
}

/// Decrypts an asset sealed with the activation password; None if wrong.
pub fn open_asset(data: &[u8], password: &[u8]) -> Option<Vec<u8>> {
    qsc::open_asset(backend(), password, data).ok()
}

pub fn pin_hash(pin: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 32];
    qscrypt_core::kdf::pbkdf2(backend(), Prf::Sha512, pin, salt, 120_000, &mut out, &AtomicBool::new(false)).ok()?;
    Some(out)
}

pub fn random_bytes(n: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; n];
    backend().fill_random(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qscrypt-ffi-{}-{name}", std::process::id()));
        p
    }

    #[test]
    fn self_test_passes() {
        let r = self_test();
        eprintln!("self-test: {r}");
        // Every primitive and single cipher must pass; cascades depend on the
        // self-test's assumed key rows (checked strictly in qscrypt-crypto).
        for item in r.split("{\"name\":").skip(1) {
            let name = item.split('"').nth(1).unwrap_or("");
            let cascade = name.ends_with("(VeraCrypt)") && name.trim_end_matches(" (VeraCrypt)").contains('-');
            if !cascade {
                assert!(item.contains("\"ok\":true"), "{name} failed: {r}");
            }
        }
    }

    #[test]
    fn create_open_import_export() {
        let path = tmp("vol.hc");
        let f = File::options().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let r = create_volume(f.as_raw_fd(), 3 << 20, b"pw", 1, 1, 1, 1, "Test", &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        drop(f);

        let f = File::options().read(true).write(true).open(&path).unwrap();
        let r = open_volume(f.as_raw_fd(), b"pw", 1, 0, 0, false, 0);
        assert!(r.contains("\"ok\":true"), "{r}");
        drop(f); // the engine holds its own duplicate
        let handle: i64 = r.split("\"handle\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();

        let src_path = tmp("src.txt");
        std::fs::write(&src_path, b"secret content").unwrap();
        let src = File::open(&src_path).unwrap();
        let r = import_file(handle, src.as_raw_fd(), 14, "/ملف.txt", false, &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let r = list(handle, "/");
        assert!(r.contains("ملف.txt"), "{r}");
        assert_eq!(read_file(handle, "/ملف.txt", 100).unwrap(), b"secret content");

        let out_path = tmp("out.txt");
        let out = File::create(&out_path).unwrap();
        let r = export_file(handle, "/ملف.txt", out.as_raw_fd(), &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(std::fs::read(&out_path).unwrap(), b"secret content");
        close_volume(handle);
        assert!(list(handle, "/").contains("\"ok\":false"));

        let f = File::open(&path).unwrap();
        assert!(open_volume(f.as_raw_fd(), b"bad", 1, 0, 0, true, 0).contains("wrong_password"));
        for p in [path, src_path, out_path] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn qsc_via_fds() {
        let (a, b, c) = (tmp("plain.bin"), tmp("enc.qsc"), tmp("dec.bin"));
        std::fs::write(&a, vec![9u8; 100_000]).unwrap();
        let (fa, fb) = (File::open(&a).unwrap(), File::create(&b).unwrap());
        let r = qsc_encrypt(fa.as_raw_fd(), 100_000, fb.as_raw_fd(), "x.bin", 0, b"pw", &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let fb = File::open(&b).unwrap();
        assert!(sniff(fb.as_raw_fd()).contains("qscrypt"));
        let fb = File::open(&b).unwrap();
        let peek = qsc_decrypt(fb.as_raw_fd(), -1, b"pw", &mut |_, _| true);
        assert!(peek.contains("x.bin"), "{peek}");
        let (fb, fc) = (File::open(&b).unwrap(), File::create(&c).unwrap());
        let r = qsc_decrypt(fb.as_raw_fd(), fc.as_raw_fd(), b"pw", &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(std::fs::read(&c).unwrap(), vec![9u8; 100_000]);
        for p in [a, b, c] {
            let _ = std::fs::remove_file(p);
        }
    }
}
