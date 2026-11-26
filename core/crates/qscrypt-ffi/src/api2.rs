//! The engine API, second generation: one entry point,
//! `call(method, args JSON, blobs, fds, progress)`.
//!
//! - `args` carries everything that is not secret;
//! - secrets (passwords, keyfiles, identities) travel in `blobs`, referred
//!   to by index from `args` (`"password": 0`), so they never become Java
//!   strings;
//! - file descriptors travel in `fds`, also by index (`"fd": 0`).

use crate::api::{self, backend, disk_from_fd, file_from_fd, ok, register, reply, Vault};
use qscrypt_core::bde::{self, BdeCreateOptions, Credential};
use qscrypt_core::crypto::Prf;
use qscrypt_core::disk::Disk;
use qscrypt_core::fs::{self, FsChoice};
use qscrypt_core::identity::{PublicIdentity, SecretIdentity};
use qscrypt_core::json::{self, array, Obj, Value};
use qscrypt_core::part::{self, DiskView, SharedDisk};
use qscrypt_core::qsc::{self, Meta, Params};
use qscrypt_core::qsc2::{self, Action, Context, Header, Policy, Unlock, Verdict};
use qscrypt_core::qvol;
use qscrypt_core::usb::{DriveInfo, UsbDisk};
use qscrypt_core::util::{now_unix, Secret};
use qscrypt_core::vc::{self, keyfile, CipherChain, CreateOptions, Ea, EncVolume, Format, HiddenOptions, OpenOptions};
use qscrypt_core::vhd;
use qscrypt_core::{Error, Result};
use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub struct Call<'a> {
    pub args: Value,
    pub blobs: &'a [Secret],
    pub fds: &'a [i32],
}

impl Call<'_> {
    pub(crate) fn blob_at(&self, v: &Value) -> Option<&[u8]> {
        let i = v.as_i64()?;
        if i < 0 {
            return None;
        }
        self.blobs.get(i as usize).map(|s| &s[..])
    }

    pub(crate) fn blob(&self, key: &str) -> Option<&[u8]> {
        self.blob_at(self.args.get(key))
    }

    pub(crate) fn fd(&self, key: &str) -> Option<i32> {
        let i = self.args.get(key).as_i64()?;
        if i < 0 {
            return None;
        }
        self.fds.get(i as usize).copied().filter(|&f| f >= 0)
    }
}

pub fn call(method: &str, args: &str, blobs: &[Secret], fds: &[i32], progress: &mut dyn FnMut(u64, u64) -> bool) -> String {
    let args = match json::parse(if args.is_empty() { "{}" } else { args }) {
        Ok(v) => v,
        Err(e) => return api::err_json("invalid_argument", &e),
    };
    let c = Call { args, blobs, fds };
    reply(match method {
        "volume.open" => volume_open(&c),
        "volume.create" => volume_create(&c, progress),
        "volume.maxHidden" => {
            let fsc = fs_choice(c.args.get("fs").str_or("fat"));
            vc::max_hidden_size(c.args.get("size").u64_or(0), fsc).map(|m| Obj::new().bool("ok", true).uint("max", m).end())
        }
        "volume.changePassword" => change_password(&c),
        "volume.backupHeader" => backup_header(&c),
        "volume.restoreHeader" => restore_header(&c),
        "volume.probe" => probe(&c),
        "usb.open" => usb_open(&c),
        "usb.close" => {
            usb().lock().unwrap_or_else(|e| e.into_inner()).remove(&c.args.get("handle").i64_or(0));
            Ok(ok())
        }
        "usb.partition" => usb_partition(&c),
        "usb.info" => usb_info(&c),
        "qsc.inspect" => qsc_inspect(&c),
        "qsc.encrypt" => qsc_encrypt(&c, progress),
        "qsc.decrypt" => qsc_decrypt(&c, progress),
        "qsc.check" => qsc_check(&c),
        "qsc.destroy" => qsc_destroy(&c),
        "qsc.recoveryKey" => qsc2::generate_recovery_key(backend()).map(|k| Obj::new().bool("ok", true).str("key", &k).end()),
        "id.public" => identity(&c).map(|id| public_json(&id.public)),
        "id.parseCard" => PublicIdentity::parse_card(c.args.get("card").str_or("")).map(|p| public_json(&p)),
        "stego.capacity" => Ok(Obj::new().bool("ok", true).uint("bytes", qscrypt_core::stego::capacity(c.args.get("w").u64_or(0) as usize, c.args.get("h").u64_or(0) as usize) as u64).end()),
        _ => match crate::api3::call(method, &c, progress) {
            Some(r) => r,
            None => Err(Error::invalid(format!("unknown method {method}"))),
        },
    })
}

/// Methods that return bytes (None on any error).
pub fn call_bytes(method: &str, args: &str, blobs: &[Secret], fds: &[i32]) -> Option<Vec<u8>> {
    let args = json::parse(if args.is_empty() { "{}" } else { args }).ok()?;
    let c = Call { args, blobs, fds };
    match method {
        "id.generate" => SecretIdentity::generate(backend(), c.args.get("name").str_or("")).ok().map(|id| id.to_bytes().to_vec()),
        "id.rename" => {
            let mut id = identity(&c).ok()?;
            id.rename(c.args.get("name").str_or(""));
            Some(id.to_bytes().to_vec())
        }
        "volume.readRange" => api::read_range(c.args.get("handle").i64_or(0), c.args.get("path").str_or("/"), c.args.get("offset").u64_or(0), c.args.get("len").u64_or(0) as usize),
        _ => None,
    }
}

// ---------------------------------------------------------------- sources

struct Usb {
    disk: SharedDisk,
    info: DriveInfo,
}

fn usb() -> &'static Mutex<HashMap<i64, Usb>> {
    static U: OnceLock<Mutex<HashMap<i64, Usb>>> = OnceLock::new();
    U.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_USB: AtomicI64 = AtomicI64::new(1);

/// The disk a call is about: a file descriptor, or a USB drive (or a
/// partition of it). Returns it with the effective read-only flag.
pub(crate) fn source(c: &Call, want_read_only: bool) -> Result<(Box<dyn Disk>, bool)> {
    let s = c.args.get("src");
    if let Some(h) = s.get("usb").as_i64() {
        let reg = usb().lock().unwrap_or_else(|e| e.into_inner());
        let dev = reg.get(&h).ok_or_else(|| Error::invalid("the USB drive was disconnected"))?;
        let total = dev.disk.lock().map(|d| d.len()).unwrap_or(0);
        let start = s.get("start").u64_or(0);
        let size = s.get("size").u64_or(total.saturating_sub(start));
        let ro = want_read_only || dev.info.write_protected;
        return Ok((Box::new(DiskView::new(dev.disk.clone(), start, size, ro)?), ro));
    }
    let i = s.get("fd").i64_or(0);
    let fd = *c.fds.get(i.max(0) as usize).ok_or_else(|| Error::invalid("missing file descriptor"))?;
    match disk_from_fd(fd, want_read_only) {
        Ok(d) => Ok((Box::new(d), want_read_only)),
        Err(_) if !want_read_only => Ok((Box::new(disk_from_fd(fd, true)?), true)),
        Err(e) => Err(e),
    }
}

fn fs_choice(s: &str) -> FsChoice {
    if s == "exfat" {
        FsChoice::Exfat
    } else {
        FsChoice::Fat
    }
}

/// Password bytes combined with keyfiles (packed as [u32 length][bytes]...).
fn password(c: &Call, pw_key: &str, kf_key: &str) -> Result<Secret> {
    let pw = c.blob(pw_key).unwrap_or(&[]);
    match c.blob(kf_key) {
        Some(packed) if !packed.is_empty() => {
            let files = keyfile::unpack(packed)?;
            vc::apply_keyfiles(pw, &files)
        }
        _ => Ok(Secret::from_slice(pw)),
    }
}

pub(crate) fn context(c: &Call) -> Context {
    let x = c.args.get("context");
    let now = x.get("now").i64_or(now_unix());
    Context { now, max_seen: x.get("maxSeen").i64_or(now), online: x.get("online").bool_or(false) }
}

pub(crate) fn identity(c: &Call) -> Result<SecretIdentity> {
    SecretIdentity::from_bytes(c.blob("identity").ok_or_else(|| Error::invalid("no identity"))?)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn public_json(p: &PublicIdentity) -> String {
    Obj::new()
        .bool("ok", true)
        .str("name", &p.name)
        .str("card", &p.card())
        .str("safety", &p.safety_number(backend()))
        .str("fingerprint", &hex(&p.fingerprint(backend())))
        .str("signKey", &hex(&p.ed25519))
        .end()
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Refuse => "refuse",
        Action::Destroy => "destroy",
    }
}

fn policy_json(h: &Header) -> String {
    let p = &h.policy;
    let mut o = Obj::new()
        .str("fileId", &hex(&h.file_id))
        .int("created", h.created)
        .bool("signed", h.signed())
        .uint("passwordSlots", h.password_slots as u64)
        .bool("recovery", h.has_recovery)
        .uint("recipients", h.recipients as u64)
        .bool("openOnce", p.open_once)
        .bool("autoOpen", p.auto_open);
    if let Some(a) = p.offline_only {
        o = o.str("offlineOnly", action_str(a));
    }
    if let Some((t, a)) = p.expires {
        o = o.int("expires", t).str("expiresAction", action_str(a));
    }
    if let Some((n, a)) = p.max_attempts {
        o = o.uint("maxAttempts", n as u64).str("attemptsAction", action_str(a));
    }
    o.end()
}

fn parse_action(v: &Value) -> Option<Action> {
    match v.as_str()? {
        "refuse" => Some(Action::Refuse),
        "destroy" => Some(Action::Destroy),
        _ => None,
    }
}

fn parse_policy(v: &Value) -> Policy {
    Policy {
        offline_only: parse_action(v.get("offlineOnly")),
        expires: v.get("expires").as_i64().filter(|t| *t > 0).map(|t| (t, parse_action(v.get("expiresAction")).unwrap_or(Action::Destroy))),
        open_once: v.get("openOnce").bool_or(false),
        max_attempts: v.get("maxAttempts").as_i64().filter(|n| (1..=255).contains(n)).map(|n| (n as u8, parse_action(v.get("attemptsAction")).unwrap_or(Action::Destroy))),
        auto_open: v.get("autoOpen").bool_or(false),
    }
}

fn verdict_json(v: &Verdict, h: &Header) -> Option<String> {
    let (action, why) = match v {
        Verdict::Allow => return None,
        Verdict::Refuse(w) => ("refuse", *w),
        Verdict::Destroy(w) => ("destroy", *w),
    };
    Some(Obj::new().bool("ok", false).str("code", "policy").str("action", action).str("reason", why).str("message", why).raw("policy", &policy_json(h)).end())
}

fn wrong_password_json(h: &Header) -> String {
    Obj::new().bool("ok", false).str("code", "wrong_password").str("message", "wrong password").raw("policy", &policy_json(h)).end()
}

// ---------------------------------------------------------------- volumes

/// What a source holds, from its first sector.
fn kind_of(boot: &[u8]) -> &'static str {
    if bde::is_bitlocker(boot) {
        "bitlocker"
    } else if qvol::is_container(boot) {
        "qscrypt"
    } else if &boot[3..11] == b"EXFAT   " {
        "exfat"
    } else if &boot[3..11] == b"NTFS    " {
        "ntfs"
    } else if fs::fat::looks_like_fat(boot) {
        "fat"
    } else if boot.iter().all(|&b| b == 0) {
        "empty"
    } else {
        // Random-looking: a VeraCrypt/TrueCrypt volume, or unknown data.
        "encrypted"
    }
}

fn probe(c: &Call) -> Result<String> {
    let (d, _) = source(c, true)?;
    let mut d = vhd::unwrap(d, true)?;
    let mut boot = [0u8; 512];
    d.read_at(0, &mut boot)?;
    Ok(Obj::new().bool("ok", true).str("kind", kind_of(&boot)).uint("size", d.len()).end())
}

fn volume_open(c: &Call) -> Result<String> {
    let want_ro = c.args.get("readOnly").bool_or(false);
    let tz = c.args.get("tz").i64_or(0) as i32;
    let (disk, ro) = source(c, want_ro)?;
    let mut disk = vhd::unwrap(disk, ro)?;
    let mut boot = [0u8; 512];
    disk.read_at(0, &mut boot)?;
    let format = c.args.get("format").str_or("auto");
    if bde::is_bitlocker(&boot) && matches!(format, "auto" | "bitlocker") {
        return open_bitlocker(c, disk, ro, tz);
    }
    if qvol::is_container(&boot) && matches!(format, "auto" | "qscrypt") {
        return open_qvol(c, disk, ro, tz);
    }
    open_veracrypt(c, disk, ro, tz)
}

fn open_veracrypt(c: &Call, mut disk: Box<dyn Disk>, ro: bool, tz: i32) -> Result<String> {
    let pw = password(c, "password", "keyfiles")?;
    if pw.is_empty() {
        return Err(Error::invalid("empty password"));
    }
    let mut opts = OpenOptions::new(&pw);
    opts.pim = c.args.get("pim").u64_or(0) as u32;
    opts.prf = Prf::from_id(c.args.get("prf").u64_or(0) as u32);
    opts.format = match c.args.get("format").str_or("auto") {
        "veracrypt" => Some(Format::VeraCrypt),
        "truecrypt" => Some(Format::TrueCrypt),
        _ => None,
    };
    opts.use_backup = c.args.get("useBackup").bool_or(false);
    let cancel = AtomicBool::new(false);
    let found = vc::detect(backend(), disk.as_mut(), &opts, &cancel)?;

    let mut protect = None;
    if c.args.get("protectHidden").bool_or(false) && !found.hidden && !ro {
        let hpw = password(c, "hiddenPassword", "hiddenKeyfiles")?;
        let mut ho = OpenOptions::new(&hpw);
        ho.pim = c.args.get("hiddenPim").u64_or(0) as u32;
        ho.format = Some(found.header.format);
        let range = vc::hidden_range(backend(), disk.as_mut(), &ho, &cancel).map_err(|e| match e {
            Error::WrongPassword => Error::invalid("the hidden volume password is wrong, so it cannot be protected"),
            other => other,
        })?;
        protect = Some(range);
    }
    let chain = CipherChain::new(backend(), found.ea, &found.header.master_keys)?;
    let mut vol = EncVolume::new(disk, chain, found.header.data_offset, found.header.data_size, ro)?;
    let mut rel = None;
    if let Some((a, b)) = protect {
        vol.protect(a, b);
        rel = vol.protected_range();
    }
    let mut f = fs::mount(Box::new(vol), ro, tz)?;
    if let Some((a, b)) = rel {
        f.reserve(a, b);
    }
    let v = Vault {
        fs: f,
        kind: found.header.format.name().into(),
        cipher: found.ea.name().into(),
        prf: found.prf.name().into(),
        hidden: found.hidden,
        protected: protect.is_some(),
        extra: Obj::new().bool("backupHeader", found.backup).uint("pim", found.pim as u64).end(),
    };
    Ok(register(v).1)
}

fn open_bitlocker(c: &Call, disk: Box<dyn Disk>, ro: bool, tz: i32) -> Result<String> {
    let pw = std::str::from_utf8(c.blob("password").unwrap_or(&[])).map_err(|_| Error::invalid("password is not UTF-8"))?.to_string();
    let cred = if pw.is_empty() {
        Credential::None
    } else if bde::parse_recovery(&pw).is_some() {
        Credential::Recovery(&pw)
    } else {
        Credential::Password(&pw)
    };
    let (info, keys, vol) = bde::open(backend(), disk, &cred, ro, &AtomicBool::new(false))?;
    let regions = vol.reserved_regions();
    let vro = vol.is_read_only();
    let mut f = fs::mount(Box::new(vol), vro, tz)?;
    for (a, b) in regions {
        f.reserve(a, b);
    }
    let v = Vault {
        fs: f,
        kind: "BitLocker".into(),
        cipher: info.method.name().into(),
        prf: keys.protection.code().into(),
        hidden: false,
        protected: false,
        extra: Obj::new().bool("togo", info.togo).bool("eow", info.eow).str("description", &info.description).end(),
    };
    Ok(register(v).1)
}

pub(crate) fn unlock_and<T>(c: &Call, f: impl FnOnce(&Unlock) -> Result<T>) -> Result<T> {
    match c.args.get("unlock").str_or("password") {
        "recovery" => {
            let s = std::str::from_utf8(c.blob("password").unwrap_or(&[])).map_err(|_| Error::invalid("bad recovery key"))?.to_string();
            f(&Unlock::Recovery(&s))
        }
        "identity" => {
            let id = identity(c)?;
            f(&Unlock::Identity(&id))
        }
        "filekey" => {
            let k: [u8; 32] = c.blob("fileKey").and_then(|b| b.try_into().ok()).ok_or_else(|| Error::invalid("bad file key"))?;
            f(&Unlock::FileKey(&k))
        }
        _ => {
            let pw = c.blob("password").unwrap_or(&[]);
            if pw.is_empty() {
                return Err(Error::invalid("empty password"));
            }
            f(&Unlock::Password(pw))
        }
    }
}

fn open_qvol(c: &Call, mut disk: Box<dyn Disk>, ro: bool, tz: i32) -> Result<String> {
    let header = qvol::read_header(disk.as_mut())?;
    let verdict = header.evaluate(&context(c));
    if let Some(j) = verdict_json(&verdict, &header) {
        if matches!(verdict, Verdict::Destroy(_)) {
            if !ro {
                qvol::destroy(backend(), disk.as_mut())?;
            } else if let Ok((mut d, false)) = source(c, false) {
                // Opened read-only: the policy still applies.
                qvol::destroy(backend(), d.as_mut())?;
            }
        }
        return Ok(j);
    }
    let h2 = header.clone();
    let opened = match unlock_and(c, |how| qvol::open(backend(), disk, header, how, ro)) {
        Ok(o) => o,
        Err(Error::WrongPassword) => return Ok(wrong_password_json(&h2)),
        Err(e) => return Err(e),
    };
    if opened.duress {
        if let Ok((mut d, false)) = source(c, false) {
            let _ = qvol::destroy(backend(), d.as_mut());
        }
        return Ok(api::err_json("wrong_password", "wrong password"));
    }
    let vol = opened.volume.ok_or_else(|| Error::corrupt("container"))?;
    let f = fs::mount(Box::new(vol), ro, tz)?;
    let mut extra = Obj::new().raw("policy", &policy_json(&opened.header));
    if opened.header.policy.auto_open {
        if let Some(k) = &opened.file_key {
            extra = extra.str("fileKey", &hex(k));
        }
    }
    let v = Vault { fs: f, kind: "QsCrypt".into(), cipher: "AES-Twofish-Serpent".into(), prf: "Argon2id".into(), hidden: false, protected: false, extra: extra.end() };
    Ok(register(v).1)
}

fn file_target(c: &Call, size: u64) -> Result<Box<dyn Disk>> {
    let s = c.args.get("src");
    if s.get("usb").as_i64().is_some() {
        return Ok(source(c, false)?.0);
    }
    let i = s.get("fd").i64_or(0);
    let fd = *c.fds.get(i.max(0) as usize).ok_or_else(|| Error::invalid("missing file descriptor"))?;
    let mut d = disk_from_fd(fd, false)?;
    if size > 0 {
        d.set_len(size / 512 * 512)?;
    }
    Ok(Box::new(d))
}

fn volume_create(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let a = &c.args;
    let on_usb = a.get("src").get("usb").as_i64().is_some();
    // BitLocker in a file: a fixed VHD (whole MiB of disk, then the footer).
    let vhd_image = a.get("format").str_or("") == "bitlocker" && a.get("vhd").bool_or(false) && !on_usb;
    let mut size = a.get("size").u64_or(0);
    if vhd_image {
        size = vhd::image_size(size);
    }
    let mut disk = file_target(c, size)?;
    let fsc = fs_choice(a.get("fs").str_or("fat"));
    let label = a.get("label").str_or("").to_string();
    let quick = a.get("quick").bool_or(false);
    let cancel = AtomicBool::new(false);
    match a.get("format").str_or("veracrypt") {
        f @ ("veracrypt" | "truecrypt") => {
            let format = if f == "truecrypt" { Format::TrueCrypt } else { Format::VeraCrypt };
            let pw = password(c, "password", "keyfiles")?;
            let ea = Ea::from_id(a.get("ea").u64_or(1) as u32).unwrap_or(Ea::Aes);
            let prf = Prf::from_id(a.get("prf").u64_or(1) as u32).unwrap_or(Prf::Sha512);
            let size = disk.len() / 512 * 512;
            let mut o = CreateOptions::new(format, &pw, ea, prf, size);
            o.pim = a.get("pim").u64_or(0) as u32;
            o.label = &label;
            o.filesystem = fsc;
            o.quick = quick;
            let h = a.get("hidden");
            let hpw;
            let hlabel = h.get("label").str_or("").to_string();
            if h.get("size").u64_or(0) > 0 {
                hpw = {
                    let pw = c.blob_at(h.get("password")).unwrap_or(&[]);
                    match c.blob_at(h.get("keyfiles")) {
                        Some(p) if !p.is_empty() => vc::apply_keyfiles(pw, &keyfile::unpack(p)?)?,
                        _ => Secret::from_slice(pw),
                    }
                };
                o.hidden = Some(HiddenOptions {
                    password: &hpw,
                    pim: h.get("pim").u64_or(0) as u32,
                    prf,
                    ea: Ea::from_id(h.get("ea").u64_or(a.get("ea").u64_or(1)) as u32).unwrap_or(ea),
                    size: h.get("size").u64_or(0),
                    filesystem: fs_choice(h.get("fs").str_or("fat")),
                    label: &hlabel,
                });
            }
            vc::create_volume(backend(), disk.as_mut(), &o, progress, &cancel)?;
            Ok(Obj::new().bool("ok", true).str("format", format.name()).str("ea", ea.name()).str("prf", prf.name()).end())
        }
        "bitlocker" => {
            let pw = std::str::from_utf8(c.blob("password").unwrap_or(&[])).map_err(|_| Error::invalid("password is not UTF-8"))?.to_string();
            let method = match a.get("method").str_or("xts128") {
                "xts256" => bde::Method::Xts256,
                "cbc128" => bde::Method::Cbc128,
                "cbc256" => bde::Method::Cbc256,
                _ => bde::Method::Xts128,
            };
            let description = a.get("description").str_or("QsCrypt").to_string();
            let start = if on_usb { a.get("src").get("start").u64_or(0) } else { 0 };
            let o = BdeCreateOptions {
                password: &pw,
                recovery_key: None,
                method,
                filesystem: fsc,
                label: &label,
                description: &description,
                quick,
                hidden_sectors: (start / 512).min(u32::MAX as u64) as u32,
            };
            let rp = if vhd_image {
                vhd::create_bitlocker_vhd(backend(), disk, &o, progress, &cancel)?
            } else {
                bde::create_bitlocker(backend(), disk, &o, progress, &cancel)?
            };
            Ok(Obj::new().bool("ok", true).str("format", "BitLocker").str("ea", method.name()).str("recovery", &rp).bool("vhd", vhd_image).end())
        }
        "qscrypt" => {
            let (recipients, recovery) = qsc_recipients(c)?;
            let pw = c.blob("password").map(Secret::from_slice);
            let duress = c.blob("duress").map(Secret::from_slice);
            let signer = None;
            let o = qsc2::Options {
                password: pw.as_deref(),
                duress: duress.as_deref(),
                recovery: recovery.as_deref(),
                recipients: &recipients,
                signer,
                policy: parse_policy(a.get("policy")),
                params: Params::default(),
            };
            qvol::create(backend(), disk.as_mut(), &o, fsc, &label, quick, progress, &cancel)?;
            let mut out = Obj::new().bool("ok", true).str("format", "QsCrypt").str("ea", "AES-Twofish-Serpent");
            if let Some(r) = &recovery {
                out = out.str("recovery", r);
            }
            Ok(out.end())
        }
        other => Err(Error::invalid(format!("unknown format {other}"))),
    }
}

fn qsc_recipients(c: &Call) -> Result<(Vec<PublicIdentity>, Option<String>)> {
    let mut list = Vec::new();
    for v in c.args.get("recipients").as_arr() {
        list.push(PublicIdentity::parse_card(v.str_or(""))?);
    }
    // A recovery key given by the caller (one key for a batch of files), or a fresh one.
    let recovery = match c.blob("recoveryKey").filter(|b| !b.is_empty()) {
        Some(b) => {
            let s = std::str::from_utf8(b).map_err(|_| Error::invalid("bad recovery key"))?;
            qsc2::parse_recovery_key(s).ok_or_else(|| Error::invalid("bad recovery key"))?;
            Some(s.to_string())
        }
        None if c.args.get("recovery").bool_or(false) => Some(qsc2::generate_recovery_key(backend())?),
        None => None,
    };
    Ok((list, recovery))
}

fn change_password(c: &Call) -> Result<String> {
    let (mut disk, ro) = source(c, false)?;
    if ro {
        return Err(Error::ReadOnly);
    }
    let pw = password(c, "password", "keyfiles")?;
    let mut o = OpenOptions::new(&pw);
    o.pim = c.args.get("pim").u64_or(0) as u32;
    o.prf = Prf::from_id(c.args.get("prf").u64_or(0) as u32);
    let np = password(c, "newPassword", "newKeyfiles")?;
    let prf = Prf::from_id(c.args.get("newPrf").u64_or(1) as u32).unwrap_or(Prf::Sha512);
    let creds = vc::Credentials { password: &np, pim: c.args.get("newPim").u64_or(0) as u32, prf };
    let found = vc::change_password(backend(), disk.as_mut(), &o, &creds, &AtomicBool::new(false))?;
    Ok(Obj::new().bool("ok", true).bool("hidden", found.hidden).end())
}

fn backup_header(c: &Call) -> Result<String> {
    let (mut disk, _) = source(c, true)?;
    let pw = password(c, "password", "keyfiles")?;
    let mut o = OpenOptions::new(&pw);
    o.pim = c.args.get("pim").u64_or(0) as u32;
    let hpw;
    let mut ho = None;
    if c.blob("hiddenPassword").is_some_and(|b| !b.is_empty()) {
        hpw = password(c, "hiddenPassword", "hiddenKeyfiles")?;
        let mut h = OpenOptions::new(&hpw);
        h.pim = c.args.get("hiddenPim").u64_or(0) as u32;
        ho = Some(h);
    }
    let bytes = vc::backup_headers(backend(), disk.as_mut(), &o, ho.as_ref(), &AtomicBool::new(false))?;
    let out_fd = c.fd("out").ok_or_else(|| Error::invalid("missing output"))?;
    let mut f = file_from_fd(out_fd)?;
    let _ = f.set_len(0);
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(ok())
}

fn restore_header(c: &Call) -> Result<String> {
    let (mut disk, ro) = source(c, false)?;
    if ro {
        return Err(Error::ReadOnly);
    }
    let pw = password(c, "password", "keyfiles")?;
    let mut o = OpenOptions::new(&pw);
    o.pim = c.args.get("pim").u64_or(0) as u32;
    let found = if c.args.get("embedded").bool_or(true) {
        vc::repair_from_embedded(backend(), disk.as_mut(), &o, &AtomicBool::new(false))?
    } else {
        let in_fd = c.fd("in").ok_or_else(|| Error::invalid("missing backup file"))?;
        let mut f = file_from_fd(in_fd)?;
        let mut b = Vec::new();
        f.read_to_end(&mut b)?;
        vc::restore_from_file(backend(), disk.as_mut(), &b, &o, &AtomicBool::new(false))?
    };
    Ok(Obj::new().bool("ok", true).bool("hidden", found.hidden).end())
}

// ---------------------------------------------------------------- USB drives

fn usb_open(c: &Call) -> Result<String> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let a = &c.args;
        let fd = c.fd("fd").ok_or_else(|| Error::invalid("missing USB descriptor"))?;
        let t = crate::usbfs::Usbfs::new(fd, a.get("epIn").u64_or(0) as u8, a.get("epOut").u64_or(0) as u8, a.get("iface").u64_or(0) as u16)?;
        let d = UsbDisk::open(t, a.get("lun").u64_or(0) as u8, a.get("readOnly").bool_or(false))?;
        let info = d.info().clone();
        let shared: SharedDisk = Arc::new(Mutex::new(Box::new(d)));
        let handle = NEXT_USB.fetch_add(1, Ordering::Relaxed);
        usb().lock().unwrap_or_else(|e| e.into_inner()).insert(handle, Usb { disk: shared.clone(), info: info.clone() });
        let json = drive_json(handle, &shared, &info)?;
        Ok(json)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = c;
        Err(Error::unsupported("USB drives on this platform"))
    }
}

fn drive_json(handle: i64, shared: &SharedDisk, info: &DriveInfo) -> Result<String> {
    let mut whole = DiskView::whole(shared.clone(), true)?;
    let size = whole.len();
    let mut boot = [0u8; 512];
    whole.read_at(0, &mut boot)?;
    let parts = part::read_table(&mut whole, info.block_size)?;
    let mut items = Vec::new();
    for p in &parts {
        let mut b = [0u8; 512];
        let kind = DiskView::new(shared.clone(), p.start, p.size, true).and_then(|mut v| v.read_at(0, &mut b)).map(|_| kind_of(&b)).unwrap_or("unknown");
        items.push(Obj::new().uint("index", p.index as u64).uint("start", p.start).uint("size", p.size).str("scheme", p.scheme).str("type", &p.type_id).str("name", &p.name).str("kind", kind).end());
    }
    let whole_kind = if parts.is_empty() { kind_of(&boot) } else { "partitioned" };
    Ok(Obj::new()
        .bool("ok", true)
        .int("handle", handle)
        .str("vendor", &info.vendor)
        .str("product", &info.product)
        .str("revision", &info.revision)
        .uint("size", size)
        .uint("blockSize", info.block_size as u64)
        .bool("writeProtected", info.write_protected)
        .str("kind", whole_kind)
        .raw("partitions", &array(items.into_iter()))
        .end())
}

/// The drive again (after creating a volume on it, its partitions changed kind).
fn usb_info(c: &Call) -> Result<String> {
    let h = c.args.get("handle").i64_or(0);
    let (shared, info) = {
        let reg = usb().lock().unwrap_or_else(|e| e.into_inner());
        let d = reg.get(&h).ok_or_else(|| Error::invalid("the USB drive was disconnected"))?;
        (d.disk.clone(), d.info.clone())
    };
    drive_json(h, &shared, &info)
}

fn usb_partition(c: &Call) -> Result<String> {
    let h = c.args.get("handle").i64_or(0);
    let (shared, info) = {
        let reg = usb().lock().unwrap_or_else(|e| e.into_inner());
        let d = reg.get(&h).ok_or_else(|| Error::invalid("the USB drive was disconnected"))?;
        (d.disk.clone(), d.info.clone())
    };
    let mut whole = DiskView::whole(shared.clone(), false)?;
    part::write_single_partition_mbr(&mut whole, info.block_size, c.args.get("type").u64_or(0x07) as u8)?;
    drive_json(h, &shared, &info)
}

// ---------------------------------------------------------------- QsCrypt files

pub(crate) fn reader(c: &Call, key: &str) -> Result<BufReader<std::fs::File>> {
    let fd = c.fd(key).ok_or_else(|| Error::invalid("missing input"))?;
    Ok(BufReader::with_capacity(1 << 20, file_from_fd(fd)?))
}

fn qsc_inspect(c: &Call) -> Result<String> {
    let mut input = reader(c, "in")?;
    let mut head = [0u8; 16];
    let n = input.read(&mut head)?;
    input.seek(SeekFrom::Start(0))?;
    if !qsc::is_qsc(&head[..n]) {
        return Err(Error::corrupt("not a QsCrypt file"));
    }
    if !qsc2::is_v2(&head[..n]) {
        return Ok(Obj::new().bool("ok", true).uint("version", 1).end());
    }
    let h = qsc2::read_header(&mut input)?;
    Ok(Obj::new().bool("ok", true).uint("version", 2).bool("container", h.flags & qsc2::FLAG_CONTAINER != 0).raw("policy", &policy_json(&h)).end())
}

fn qsc_encrypt(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let a = &c.args;
    let mut input = reader(c, "in")?;
    let out_fd = c.fd("out").ok_or_else(|| Error::invalid("missing output"))?;
    let out_file = file_from_fd(out_fd)?;
    let _ = out_file.set_len(0);
    let mut output = BufWriter::with_capacity(1 << 20, out_file);
    let (recipients, recovery) = qsc_recipients(c)?;
    let pw = c.blob("password").filter(|b| !b.is_empty()).map(Secret::from_slice);
    let duress = c.blob("duress").filter(|b| !b.is_empty()).map(Secret::from_slice);
    let signer = if a.get("sign").bool_or(false) { Some(identity(c)?) } else { None };
    let o = qsc2::Options {
        password: pw.as_deref(),
        duress: duress.as_deref(),
        recovery: recovery.as_deref(),
        recipients: &recipients,
        signer: signer.as_ref(),
        policy: parse_policy(a.get("policy")),
        params: Params::default(),
    };
    let meta = Meta { name: a.get("name").str_or("file").to_string(), modified: a.get("mtime").i64_or(0), size: a.get("size").u64_or(0) };
    let id = qsc2::encrypt(backend(), &o, &meta, a.get("now").i64_or(now_unix()), &mut input, &mut output, progress)?;
    output.flush()?;
    let _ = output.get_ref().sync_all();
    let mut out = Obj::new().bool("ok", true).str("fileId", &hex(&id));
    if let Some(r) = &recovery {
        out = out.str("recovery", r);
    }
    Ok(out.end())
}

/// Checks the policy and the password (or other unlock) without decrypting
/// the content, so the app can ask where to save only once it is right.
fn qsc_check(c: &Call) -> Result<String> {
    let mut input = reader(c, "in")?;
    let mut head = [0u8; 16];
    let n = input.read(&mut head)?;
    input.seek(SeekFrom::Start(0))?;
    if !qsc2::is_v2(&head[..n]) {
        return Ok(Obj::new().bool("ok", true).uint("version", 1).end());
    }
    let h = qsc2::read_header(&mut input)?;
    let verdict = h.evaluate(&context(c));
    if let Some(j) = verdict_json(&verdict, &h) {
        return Ok(j);
    }
    let u = match unlock_and(c, |how| qsc2::unlock(backend(), &h, how)) {
        Ok(u) => u,
        Err(Error::WrongPassword) => return Ok(wrong_password_json(&h)),
        Err(e) => return Err(e),
    };
    if u.duress {
        return Ok(Obj::new().bool("ok", false).str("code", "duress").str("message", "wrong password").raw("policy", &policy_json(&h)).end());
    }
    Ok(Obj::new().bool("ok", true).uint("version", 2).raw("policy", &policy_json(&h)).end())
}

fn qsc_decrypt(c: &Call, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<String> {
    let mut input = reader(c, "in")?;
    let mut head = [0u8; 16];
    let n = input.read(&mut head)?;
    input.seek(SeekFrom::Start(0))?;
    let out_fd = c.fd("out");
    if !qsc2::is_v2(&head[..n]) {
        // Version 1: password only.
        let pw = c.blob("password").unwrap_or(&[]);
        let meta = match out_fd {
            Some(fd) => {
                let f = file_from_fd(fd)?;
                let _ = f.set_len(0);
                let mut w = BufWriter::with_capacity(1 << 20, f);
                let m = qsc::decrypt(backend(), pw, &mut input, Some(&mut w), progress)?;
                w.flush()?;
                m
            }
            None => qsc::decrypt(backend(), pw, &mut input, None, progress)?,
        };
        return Ok(Obj::new().bool("ok", true).uint("version", 1).str("name", &meta.name).int("mtime", meta.modified).uint("size", meta.size).end());
    }
    let h = qsc2::read_header(&mut input)?;
    let verdict = h.evaluate(&context(c));
    if let Some(j) = verdict_json(&verdict, &h) {
        return Ok(j);
    }
    let u = match unlock_and(c, |how| qsc2::unlock(backend(), &h, how)) {
        Ok(u) => u,
        Err(Error::WrongPassword) => return Ok(wrong_password_json(&h)),
        Err(e) => return Err(e),
    };
    if u.duress {
        return Ok(Obj::new().bool("ok", false).str("code", "duress").str("message", "wrong password").raw("policy", &policy_json(&h)).end());
    }
    let d = match out_fd {
        Some(fd) => {
            let f = file_from_fd(fd)?;
            let _ = f.set_len(0);
            let mut w = BufWriter::with_capacity(1 << 20, f);
            let d = qsc2::decrypt(backend(), &h, &u.file_key, &mut input, Some(&mut w), progress)?;
            w.flush()?;
            let _ = w.get_ref().sync_all();
            d
        }
        None => qsc2::decrypt(backend(), &h, &u.file_key, &mut input, None, progress)?,
    };
    let mut out = Obj::new()
        .bool("ok", true)
        .uint("version", 2)
        .str("name", &d.meta.name)
        .int("mtime", d.meta.modified)
        .uint("size", d.meta.size)
        .bool("signatureValid", d.signature_valid)
        .raw("policy", &policy_json(&h));
    if let Some(s) = d.signer {
        out = out.str("signer", &hex(&s));
    }
    if h.policy.auto_open {
        out = out.str("fileKey", &hex(&u.file_key));
    }
    Ok(out.end())
}

/// Overwrites what makes a QsCrypt file or container decryptable.
fn qsc_destroy(c: &Call) -> Result<String> {
    let mut d: Box<dyn Disk> = if c.args.get("src").get("usb").as_i64().is_some() {
        let (d, ro) = source(c, false)?;
        if ro {
            return Err(Error::ReadOnly);
        }
        d
    } else {
        let fd = c.fd("fd").ok_or_else(|| Error::invalid("missing file"))?;
        Box::new(disk_from_fd(fd, false)?)
    };
    let mut head = [0u8; 16];
    let n = (d.len() as usize).min(16);
    d.read_at(0, &mut head[..n])?;
    if qvol::is_container(&head) {
        qvol::destroy(backend(), d.as_mut())?;
    } else {
        let hl = if qsc2::is_v2(&head) { u32::from_le_bytes(head[12..16].try_into().unwrap()) as u64 } else { 4096 };
        let span = hl.max(4096).min(d.len());
        let mut junk = vec![0u8; span as usize];
        backend().fill_random(&mut junk)?;
        d.write_at(0, &junk)?;
        d.flush()?;
    }
    Ok(ok())
}

// ---------------------------------------------------------------- stego

pub fn stego_hide(pixels: &mut [u32], password: &[u8], payload: &[u8]) -> Result<()> {
    qscrypt_core::stego::hide(backend(), pixels, password, payload)
}

pub fn stego_reveal(pixels: &[u32], password: &[u8]) -> Result<Vec<u8>> {
    qscrypt_core::stego::reveal(backend(), pixels, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qscrypt_core::json::escape;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qscrypt-api2-{}-{name}", std::process::id()));
        p
    }

    fn s(b: &[u8]) -> Secret {
        Secret::from_slice(b)
    }

    #[test]
    fn veracrypt_with_keyfile_and_hidden_protection() {
        let path = tmp("vc.hc");
        let f = File::options().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let mut kf = Vec::new();
        kf.extend_from_slice(&5u32.to_le_bytes());
        kf.extend_from_slice(b"KEYFL");
        let blobs = [s(b"outer"), s(&kf), s(b"hidden")];
        let args = r#"{"src":{"fd":0},"format":"veracrypt","size":12582912,"fs":"fat","ea":1,"prf":1,"pim":1,"password":0,"keyfiles":1,"hidden":{"size":4194304,"password":2,"pim":1,"fs":"exfat"}}"#;
        let r = call("volume.create", args, &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        let r = call("volume.open", r#"{"src":{"fd":0},"pim":1,"prf":1,"password":0,"keyfiles":1,"protectHidden":true,"hiddenPassword":2,"hiddenPim":1}"#, &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"protected\":true"), "{r}");
        let handle: i64 = r.split("\"handle\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();
        api::close_volume(handle);
        let r = call("volume.open", r#"{"src":{"fd":0},"pim":1,"prf":1,"password":2}"#, &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"hidden\":true"), "{r}");
        let r = call("volume.open", r#"{"src":{"fd":0},"pim":1,"prf":1,"password":0}"#, &blobs, &[f.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("wrong_password"), "keyfile is needed: {r}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn qscrypt_files_with_policies() {
        let (a, b, c) = (tmp("p.bin"), tmp("e.qsc"), tmp("d.bin"));
        std::fs::write(&a, b"policy test").unwrap();
        let (fa, fb) = (File::open(&a).unwrap(), File::create(&b).unwrap());
        let blobs = [s(b"pw"), s(b"panic")];
        let r = call("qsc.encrypt", r#"{"in":0,"out":1,"size":11,"name":"x.txt","password":0,"duress":1,"recovery":true,"policy":{"offlineOnly":"destroy","maxAttempts":3}}"#, &blobs, &[fa.as_raw_fd(), fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"recovery\":"), "{r}");
        let fb = File::open(&b).unwrap();
        let r = call("qsc.inspect", r#"{"in":0}"#, &[], &[fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"maxAttempts\":3") && r.contains("\"offlineOnly\":\"destroy\""), "{r}");
        let fb = File::open(&b).unwrap();
        let r = call("qsc.decrypt", r#"{"in":0,"password":0,"context":{"online":true}}"#, &blobs, &[fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"action\":\"destroy\""), "{r}");
        let fb = File::open(&b).unwrap();
        let r = call("qsc.decrypt", r#"{"in":0,"password":1,"context":{"online":false}}"#, &blobs, &[fb.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"duress\""), "{r}");
        let (fb, fc) = (File::open(&b).unwrap(), File::create(&c).unwrap());
        let r = call("qsc.decrypt", r#"{"in":0,"out":1,"password":0,"context":{"online":false}}"#, &blobs, &[fb.as_raw_fd(), fc.as_raw_fd()], &mut |_, _| true);
        assert!(r.contains("\"ok\":true"), "{r}");
        assert_eq!(std::fs::read(&c).unwrap(), b"policy test");
        let fb = File::options().read(true).write(true).open(&b).unwrap();
        assert!(call("qsc.destroy", r#"{"fd":0}"#, &[], &[fb.as_raw_fd()], &mut |_, _| true).contains("\"ok\":true"));
        let fb = File::open(&b).unwrap();
        assert!(call("qsc.decrypt", r#"{"in":0,"password":0}"#, &blobs, &[fb.as_raw_fd()], &mut |_, _| true).contains("\"ok\":false"));
        for p in [a, b, c] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn identities_and_contacts() {
        let secret = call_bytes("id.generate", r#"{"name":"سارة"}"#, &[], &[]).unwrap();
        let blobs = [Secret::from_slice(&secret)];
        let r = call("id.public", r#"{"identity":0}"#, &blobs, &[], &mut |_, _| true);
        assert!(r.contains("QSID1:"), "{r}");
        let card = r.split("\"card\":\"").nth(1).unwrap().split('"').next().unwrap();
        let p = call("id.parseCard", &format!("{{\"card\":{}}}", escape(card)), &[], &[], &mut |_, _| true);
        assert!(p.contains("سارة"), "{p}");
    }
}
