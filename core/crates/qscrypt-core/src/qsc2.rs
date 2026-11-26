//! The QsCrypt file format, version 2: one random file key wrapped in key
//! slots (password, duress password, recovery key, contacts), optional
//! policies the app enforces, and an optional signature by the sender.
//!
//! ```text
//! 0    8   "QSCRYPT\0"
//! 8    2   version (2)
//! 10   2   flags: bit 0 signed, bit 1 container (see qvol)
//! 12   4   header length H, including the trailing MAC
//! 16   1   KDF id (1 = Argon2id v1.3)  17 1 lanes  18 2 reserved
//! 20   4   Argon2 memory (KiB)         24 4 passes
//! 28   32  Argon2 salt (password slots)
//! 60   16  nonce prefix (data chunks)
//! 76   4   chunk size                  80 8 stream length
//! 88   16  file id (random)            104 8 creation time (Unix)
//! 112  4   policy length P, then P bytes of policy TLVs
//! ..   2   slot count, then slots: type u8 | length u16 | body
//! H-32 32  HMAC-SHA-512(MAC key, bytes 0..H-32), truncated
//! ```
//!
//! Slots wrap `kind || key` (33 bytes) with XChaCha20-Poly1305: kind 1 is
//! the file key, kind 2 marks a duress password (the app then destroys the
//! file). Password slots always come in pairs (a decoy when there is no
//! duress password) and in random order, so neither the count nor the
//! position tells whether a duress password exists. Recipient slots carry
//! an ephemeral X25519 key and an ML-KEM-768 ciphertext; the wrapping key
//! comes from both shared secrets, and nothing names the recipient.
//!
//! Data: like version 1 (AES-256-CTR, Twofish-256-CTR, XChaCha20-Poly1305
//! per chunk), keyed from the file key. The plaintext stream is
//! `meta block | data | [signer key 32 | Ed25519 signature 64]`; the
//! signature covers a hash chain over the stream's chunks, so it is
//! verified as the file streams by.

use crate::crypto::{ctr_xor, Backend, BlockCipher, CipherKind};
use crate::error::{Error, Result};
use crate::identity::{PublicIdentity, SecretIdentity, X25519_BASE};
use crate::kdf::hkdf_sha512;
use crate::qsc::{Meta, Params};
use crate::util::{base32_decode, base32_encode, ct_eq, le16, le32, le64, put_le16, put_le32, put_le64, Secret};
use std::io::{Read, Write};

pub const MAGIC: [u8; 8] = *b"QSCRYPT\0";
pub const VERSION: u16 = 2;
pub const FLAG_SIGNED: u16 = 1;
pub const FLAG_CONTAINER: u16 = 2;
const FIXED: usize = 116;
const MAC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SIG_BLOCK: usize = 96;
const MAX_HEADER: usize = 64 * 1024;
const MAX_CHUNK: u32 = 1 << 20;
const MIN_CHUNK: u32 = 4096;
const KDF_ARGON2ID: u8 = 1;
const SLOT_PASSWORD: u8 = 1;
const SLOT_RECOVERY: u8 = 2;
const SLOT_RECIPIENT: u8 = 3;
const KIND_FILE_KEY: u8 = 1;
const KIND_DURESS: u8 = 2;
const WRAP_LEN: usize = 24 + 33 + 16;
/// Bytes in a recovery key (shown as 32 characters).
pub const RECOVERY_BYTES: usize = 20;
/// Clock rollback tolerated before an expiry policy treats the clock as tampered.
const CLOCK_SLACK: i64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Refuse,
    Destroy,
}

impl Action {
    fn byte(self) -> u8 {
        match self {
            Action::Refuse => 1,
            Action::Destroy => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Action> {
        match b {
            1 => Some(Action::Refuse),
            2 => Some(Action::Destroy),
            _ => None,
        }
    }
}

/// Every policy is off by default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// What happens if the phone is online when the file is opened.
    pub offline_only: Option<Action>,
    /// Not usable after this time; the clock being set back counts as expired.
    pub expires: Option<(i64, Action)>,
    /// The app destroys the file after the first successful opening.
    pub open_once: bool,
    /// Destroyed (or refused) after this many wrong passwords on a phone.
    pub max_attempts: Option<(u8, Action)>,
    /// After the first opening, the recipient's phone opens it without a password.
    pub auto_open: bool,
}

impl Policy {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut tlv = |tag: u8, v: &[u8]| {
            out.push(tag);
            out.extend_from_slice(&(v.len() as u16).to_le_bytes());
            out.extend_from_slice(v);
        };
        if let Some(a) = self.offline_only {
            tlv(0x01, &[a.byte()]);
        }
        if let Some((t, a)) = self.expires {
            let mut v = t.to_le_bytes().to_vec();
            v.push(a.byte());
            tlv(0x02, &v);
        }
        if self.open_once {
            tlv(0x03, &[]);
        }
        if let Some((n, a)) = self.max_attempts {
            tlv(0x04, &[n, a.byte()]);
        }
        if self.auto_open {
            tlv(0x05, &[]);
        }
        out
    }

    fn decode(b: &[u8]) -> Result<Policy> {
        let mut p = Policy::default();
        let mut i = 0usize;
        let bad = || Error::corrupt("bad policy block");
        while i < b.len() {
            if i + 3 > b.len() {
                return Err(bad());
            }
            let tag = b[i];
            let len = le16(b, i + 1) as usize;
            let v = b.get(i + 3..i + 3 + len).ok_or_else(bad)?;
            match (tag, len) {
                (0x01, 1) => p.offline_only = Some(Action::from_byte(v[0]).ok_or_else(bad)?),
                (0x02, 9) => p.expires = Some((i64::from_le_bytes(v[..8].try_into().unwrap()), Action::from_byte(v[8]).ok_or_else(bad)?)),
                (0x03, 0) => p.open_once = true,
                (0x04, 2) => p.max_attempts = Some((v[0].max(1), Action::from_byte(v[1]).ok_or_else(bad)?)),
                (0x05, 0) => p.auto_open = true,
                // Unknown policies from a newer version: refuse rather than ignore.
                _ if tag & 0x80 == 0 => return Err(Error::unsupported("a policy from a newer QsCrypt version")),
                _ => {}
            }
            i += 3 + len;
        }
        Ok(p)
    }

    pub fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
}

/// What the phone knows when a file is opened.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub now: i64,
    /// Latest time the app has ever seen (clock rollback detection).
    pub max_seen: i64,
    pub online: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Refuse(&'static str),
    Destroy(&'static str),
}

fn act(a: Action, why: &'static str) -> Verdict {
    match a {
        Action::Refuse => Verdict::Refuse(why),
        Action::Destroy => Verdict::Destroy(why),
    }
}

/// Header facts readable without any key.
#[derive(Clone, Debug)]
pub struct Header {
    pub raw: Vec<u8>,
    pub flags: u16,
    pub file_id: [u8; 16],
    pub created: i64,
    pub policy: Policy,
    pub password_slots: usize,
    pub has_recovery: bool,
    pub recipients: usize,
    chunk: u32,
    stream_len: u64,
    slots: Vec<(u8, Vec<u8>)>,
}

impl Header {
    pub fn signed(&self) -> bool {
        self.flags & FLAG_SIGNED != 0
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn stream_len(&self) -> u64 {
        self.stream_len
    }

    pub fn evaluate(&self, ctx: &Context) -> Verdict {
        let p = &self.policy;
        if let Some(a) = p.offline_only {
            if ctx.online {
                return act(a, "online");
            }
        }
        if let Some((t, a)) = p.expires {
            if ctx.now > t {
                return act(a, "expired");
            }
            if ctx.now + CLOCK_SLACK < ctx.max_seen || ctx.now + CLOCK_SLACK < self.created {
                return act(a, "clock");
            }
        }
        Verdict::Allow
    }
}

/// How the file is being opened.
pub enum Unlock<'a> {
    Password(&'a [u8]),
    /// The 32-character recovery key.
    Recovery(&'a str),
    Identity(&'a SecretIdentity),
    /// Remembered by the app after a first opening ("auto-open").
    FileKey(&'a [u8; 32]),
}

pub struct Unlocked {
    pub file_key: Secret,
    /// The duress password was used: the app must destroy the file.
    pub duress: bool,
}

pub struct Options<'a> {
    pub password: Option<&'a [u8]>,
    pub duress: Option<&'a [u8]>,
    /// A recovery key from `generate_recovery_key`.
    pub recovery: Option<&'a str>,
    pub recipients: &'a [PublicIdentity],
    pub signer: Option<&'a SecretIdentity>,
    pub policy: Policy,
    pub params: Params,
}

pub struct Decrypted {
    pub meta: Meta,
    /// Ed25519 key of the signer, when signed.
    pub signer: Option<[u8; 32]>,
    pub signature_valid: bool,
}

/// A fresh recovery key, formatted `XXXX-XXXX-...` (8 groups of 4).
pub fn generate_recovery_key(backend: &dyn Backend) -> Result<String> {
    let mut k = [0u8; RECOVERY_BYTES];
    backend.fill_random(&mut k)?;
    let s = base32_encode(&k);
    Ok(s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-"))
}

pub fn parse_recovery_key(s: &str) -> Option<[u8; RECOVERY_BYTES]> {
    base32_decode(s, RECOVERY_BYTES).map(|v| v.try_into().unwrap())
}

pub fn is_v2(prefix: &[u8]) -> bool {
    prefix.len() >= 10 && prefix[..8] == MAGIC && le16(prefix, 8) == VERSION
}

struct Keys {
    aes: Box<dyn BlockCipher>,
    twofish: Box<dyn BlockCipher>,
    aead: Secret,
    mac: Secret,
    iv_aes: [u8; 8],
    iv_twofish: [u8; 8],
}

fn schedule(backend: &dyn Backend, fk: &[u8], file_id: &[u8]) -> Result<Keys> {
    let mut okm = Secret::new(32 * 4 + 16);
    hkdf_sha512(backend, b"QsCrypt v2 key schedule", fk, file_id, &mut okm)?;
    Ok(Keys {
        aes: backend.cipher(CipherKind::Aes, okm[0..32].try_into().unwrap())?,
        twofish: backend.cipher(CipherKind::Twofish, okm[32..64].try_into().unwrap())?,
        aead: Secret::from_slice(&okm[64..96]),
        mac: Secret::from_slice(&okm[96..128]),
        iv_aes: okm[128..136].try_into().unwrap(),
        iv_twofish: okm[136..144].try_into().unwrap(),
    })
}

/// Keys for a container's data area (see qvol), from the same file key.
pub(crate) fn container_key(backend: &dyn Backend, fk: &[u8], file_id: &[u8]) -> Result<Secret> {
    let mut k = Secret::new(192);
    hkdf_sha512(backend, b"QsCrypt v2 container keys", fk, file_id, &mut k)?;
    Ok(k)
}

fn kek(backend: &dyn Backend, label: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut k = [0u8; 32];
    hkdf_sha512(backend, label, ikm, info, &mut k)?;
    Ok(k)
}

fn wrap(backend: &dyn Backend, key: &[u8; 32], aad: &[u8], kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    backend.fill_random(&mut nonce)?;
    let mut buf = Vec::with_capacity(33);
    buf.push(kind);
    buf.extend_from_slice(payload);
    let tag = backend.xchacha_seal(key, &nonce, aad, &mut buf)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn unwrap(backend: &dyn Backend, key: &[u8; 32], aad: &[u8], body: &[u8]) -> Option<(u8, Secret)> {
    if body.len() != WRAP_LEN {
        return None;
    }
    let nonce: [u8; 24] = body[..24].try_into().unwrap();
    let mut buf = Secret::from_slice(&body[24..57]);
    let tag: [u8; 16] = body[57..].try_into().unwrap();
    backend.xchacha_open(key, &nonce, aad, &mut buf, &tag).ok()?;
    Some((buf[0], Secret::from_slice(&buf[1..])))
}

fn slot_aad(file_id: &[u8; 16], ty: u8) -> [u8; 17] {
    let mut a = [0u8; 17];
    a[..16].copy_from_slice(file_id);
    a[16] = ty;
    a
}

fn password_kek(backend: &dyn Backend, raw: &[u8], password: &[u8], file_id: &[u8]) -> Result<[u8; 32]> {
    let mut stretched = Secret::new(32);
    backend.argon2id(password, &raw[28..60], le32(raw, 20), le32(raw, 24), raw[17] as u32, &mut stretched)?;
    kek(backend, b"QsCrypt v2 password slot", &stretched, file_id)
}

fn recipient_info(file_id: &[u8], e: &[u8], ct: &[u8], r: &PublicIdentity, backend: &dyn Backend) -> Vec<u8> {
    let mut info = file_id.to_vec();
    info.extend_from_slice(e);
    info.extend_from_slice(&backend.sha256(&[ct]));
    info.extend_from_slice(&r.x25519);
    info.extend_from_slice(&backend.sha256(&[&r.mlkem]));
    info
}

/// Builds a header (for files and containers). Returns it with its keys.
pub(crate) fn build_header(backend: &dyn Backend, opts: &Options, flags: u16, chunk: u32, stream_len: u64, created: i64) -> Result<(Vec<u8>, Secret, [u8; 16])> {
    let p = opts.params;
    if opts.password.is_none() && opts.recovery.is_none() && opts.recipients.is_empty() {
        return Err(Error::invalid("a password, a recovery key or a contact is needed"));
    }
    if opts.password.is_some_and(|pw| pw.is_empty()) || (opts.duress.is_some() && opts.password.is_none()) {
        return Err(Error::invalid("empty password"));
    }
    if opts.duress.is_some() && opts.duress == opts.password {
        return Err(Error::invalid("the duress password must differ from the password"));
    }
    if p.lanes == 0 || p.lanes > 255 || p.iterations == 0 {
        return Err(Error::invalid("bad parameters"));
    }
    let mut fk = Secret::new(32);
    backend.fill_random(&mut fk)?;
    let mut file_id = [0u8; 16];
    backend.fill_random(&mut file_id)?;

    let policy = opts.policy.encode();
    let mut h = vec![0u8; FIXED];
    h[..8].copy_from_slice(&MAGIC);
    put_le16(&mut h, 8, VERSION);
    put_le16(&mut h, 10, flags);
    h[16] = KDF_ARGON2ID;
    h[17] = p.lanes as u8;
    put_le32(&mut h, 20, p.memory_kib);
    put_le32(&mut h, 24, p.iterations);
    backend.fill_random(&mut h[28..76])?;
    put_le32(&mut h, 76, chunk);
    put_le64(&mut h, 80, stream_len);
    h[88..104].copy_from_slice(&file_id);
    h[104..112].copy_from_slice(&created.to_le_bytes());
    put_le32(&mut h, 112, policy.len() as u32);
    h.extend_from_slice(&policy);

    let mut slots: Vec<(u8, Vec<u8>)> = Vec::new();
    if let Some(pw) = opts.password {
        let k = password_kek(backend, &h, pw, &file_id)?;
        let aad = slot_aad(&file_id, SLOT_PASSWORD);
        slots.push((SLOT_PASSWORD, wrap(backend, &k, &aad, KIND_FILE_KEY, &fk)?));
        let second = match opts.duress {
            Some(d) => {
                let dk = password_kek(backend, &h, d, &file_id)?;
                let mut junk = [0u8; 32];
                backend.fill_random(&mut junk)?;
                wrap(backend, &dk, &aad, KIND_DURESS, &junk)?
            }
            None => {
                let mut decoy = vec![0u8; WRAP_LEN];
                backend.fill_random(&mut decoy)?;
                decoy
            }
        };
        slots.push((SLOT_PASSWORD, second));
    }
    if let Some(rk) = opts.recovery {
        let key = parse_recovery_key(rk).ok_or_else(|| Error::invalid("bad recovery key"))?;
        let k = kek(backend, b"QsCrypt v2 recovery slot", &key, &file_id)?;
        slots.push((SLOT_RECOVERY, wrap(backend, &k, &slot_aad(&file_id, SLOT_RECOVERY), KIND_FILE_KEY, &fk)?));
    }
    for r in opts.recipients {
        let mut e = Secret::new(32);
        backend.fill_random(&mut e)?;
        let epub = backend.x25519(e[..].try_into().unwrap(), &X25519_BASE)?;
        let ss1 = backend.x25519(e[..].try_into().unwrap(), &r.x25519)?;
        let (ct, ss2) = backend.mlkem768_encapsulate(&r.mlkem)?;
        let mut ikm = ss1.to_vec();
        ikm.extend_from_slice(&ss2);
        let k = kek(backend, b"QsCrypt v2 recipient slot", &ikm, &recipient_info(&file_id, &epub, &ct, r, backend))?;
        crate::util::wipe(&mut ikm);
        let mut body = epub.to_vec();
        body.extend_from_slice(&ct);
        body.extend(wrap(backend, &k, &slot_aad(&file_id, SLOT_RECIPIENT), KIND_FILE_KEY, &fk)?);
        slots.push((SLOT_RECIPIENT, body));
    }
    // Random order (Fisher-Yates with system randomness).
    for i in (1..slots.len()).rev() {
        let mut r = [0u8; 4];
        backend.fill_random(&mut r)?;
        slots.swap(i, u32::from_le_bytes(r) as usize % (i + 1));
    }
    h.extend_from_slice(&(slots.len() as u16).to_le_bytes());
    for (ty, body) in &slots {
        h.push(*ty);
        h.extend_from_slice(&(body.len() as u16).to_le_bytes());
        h.extend_from_slice(body);
    }
    let total = h.len() + MAC_LEN;
    if total > MAX_HEADER {
        return Err(Error::invalid("too many contacts for one file"));
    }
    put_le32(&mut h, 12, total as u32);
    let keys = schedule(backend, &fk, &file_id)?;
    let mac = backend.hmac_sha512(&keys.mac, &[&h]);
    h.extend_from_slice(&mac[..MAC_LEN]);
    Ok((h, fk, file_id))
}

/// Parses a header from its full bytes (no key needed).
pub fn parse_header(raw: Vec<u8>) -> Result<Header> {
    if raw.len() < FIXED + 2 + MAC_LEN || raw[..8] != MAGIC || le16(&raw, 8) != VERSION {
        return Err(Error::corrupt("not a QsCrypt v2 header"));
    }
    if le32(&raw, 12) as usize != raw.len() || raw[16] != KDF_ARGON2ID {
        return Err(Error::corrupt("bad QsCrypt header"));
    }
    let (mem, passes, lanes) = (le32(&raw, 20), le32(&raw, 24), raw[17] as u32);
    if !(8..=1 << 20).contains(&mem) || !(1..=64).contains(&passes) || lanes == 0 || mem < 8 * lanes {
        return Err(Error::corrupt("QsCrypt parameters out of range"));
    }
    let flags = le16(&raw, 10);
    let chunk = le32(&raw, 76);
    if flags & FLAG_CONTAINER == 0 && !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk) {
        return Err(Error::corrupt("QsCrypt chunk size out of range"));
    }
    let plen = le32(&raw, 112) as usize;
    let end = raw.len() - MAC_LEN;
    if FIXED + plen + 2 > end {
        return Err(Error::corrupt("bad QsCrypt header"));
    }
    let policy = Policy::decode(&raw[FIXED..FIXED + plen])?;
    let mut p = FIXED + plen;
    let n = le16(&raw, p) as usize;
    p += 2;
    let mut slots = Vec::with_capacity(n);
    for _ in 0..n {
        if p + 3 > end {
            return Err(Error::corrupt("bad QsCrypt slot"));
        }
        let ty = raw[p];
        let len = le16(&raw, p + 1) as usize;
        let body = raw.get(p + 3..p + 3 + len).filter(|_| p + 3 + len <= end).ok_or_else(|| Error::corrupt("bad QsCrypt slot"))?;
        slots.push((ty, body.to_vec()));
        p += 3 + len;
    }
    if p != end {
        return Err(Error::corrupt("bad QsCrypt header"));
    }
    Ok(Header {
        flags,
        file_id: raw[88..104].try_into().unwrap(),
        created: i64::from_le_bytes(raw[104..112].try_into().unwrap()),
        policy,
        password_slots: slots.iter().filter(|s| s.0 == SLOT_PASSWORD).count(),
        has_recovery: slots.iter().any(|s| s.0 == SLOT_RECOVERY),
        recipients: slots.iter().filter(|s| s.0 == SLOT_RECIPIENT).count(),
        chunk,
        stream_len: le64(&raw, 80),
        slots,
        raw,
    })
}

/// Reads the header from the start of a stream.
pub fn read_header(input: &mut dyn Read) -> Result<Header> {
    let mut start = [0u8; 16];
    if read_full(input, &mut start)? != 16 || start[..8] != MAGIC || le16(&start, 8) != VERSION {
        return Err(Error::corrupt("not a QsCrypt v2 file"));
    }
    let len = le32(&start, 12) as usize;
    if !(FIXED + 2 + MAC_LEN..=MAX_HEADER).contains(&len) {
        return Err(Error::corrupt("bad QsCrypt header length"));
    }
    let mut raw = start.to_vec();
    raw.resize(len, 0);
    if read_full(input, &mut raw[16..])? != len - 16 {
        return Err(Error::Tampered);
    }
    parse_header(raw)
}

/// Finds the file key. Errors: `WrongPassword` if nothing opens a slot,
/// `Tampered` if a slot opens but the header MAC does not match.
pub fn unlock(backend: &dyn Backend, h: &Header, how: &Unlock) -> Result<Unlocked> {
    let mut found: Option<(u8, Secret)> = None;
    match how {
        Unlock::Password(pw) => {
            if h.password_slots == 0 {
                return Err(Error::WrongPassword);
            }
            let k = password_kek(backend, &h.raw, pw, &h.file_id)?;
            let aad = slot_aad(&h.file_id, SLOT_PASSWORD);
            found = h.slots.iter().filter(|s| s.0 == SLOT_PASSWORD).find_map(|s| unwrap(backend, &k, &aad, &s.1));
        }
        Unlock::Recovery(text) => {
            let key = parse_recovery_key(text).ok_or(Error::WrongPassword)?;
            let k = kek(backend, b"QsCrypt v2 recovery slot", &key, &h.file_id)?;
            let aad = slot_aad(&h.file_id, SLOT_RECOVERY);
            found = h.slots.iter().filter(|s| s.0 == SLOT_RECOVERY).find_map(|s| unwrap(backend, &k, &aad, &s.1));
        }
        Unlock::Identity(id) => {
            let aad = slot_aad(&h.file_id, SLOT_RECIPIENT);
            for (_, body) in h.slots.iter().filter(|s| s.0 == SLOT_RECIPIENT) {
                if body.len() != 32 + 1088 + WRAP_LEN {
                    continue;
                }
                let (epub, rest) = body.split_at(32);
                let (ct, wrapped) = rest.split_at(1088);
                let Ok(ss1) = backend.x25519(id.x25519_secret(), epub.try_into().unwrap()) else { continue };
                let Ok(ss2) = backend.mlkem768_decapsulate(id.mlkem_secret(), ct) else { continue };
                let mut ikm = ss1.to_vec();
                ikm.extend_from_slice(&ss2);
                let k = kek(backend, b"QsCrypt v2 recipient slot", &ikm, &recipient_info(&h.file_id, epub, ct, &id.public, backend))?;
                crate::util::wipe(&mut ikm);
                if let Some(r) = unwrap(backend, &k, &aad, wrapped) {
                    found = Some(r);
                    break;
                }
            }
        }
        Unlock::FileKey(fk) => found = Some((KIND_FILE_KEY, Secret::from_slice(&fk[..]))),
    }
    let (kind, key) = found.ok_or(Error::WrongPassword)?;
    if kind == KIND_DURESS {
        return Ok(Unlocked { file_key: Secret::new(32), duress: true });
    }
    if kind != KIND_FILE_KEY || key.len() != 32 {
        return Err(Error::corrupt("bad key slot"));
    }
    let keys = schedule(backend, &key, &h.file_id)?;
    let end = h.raw.len() - MAC_LEN;
    let mac = backend.hmac_sha512(&keys.mac, &[&h.raw[..end]]);
    if !ct_eq(&mac[..MAC_LEN], &h.raw[end..]) {
        return Err(Error::Tampered);
    }
    Ok(Unlocked { file_key: key, duress: false })
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

fn nonce(prefix: &[u8], index: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&index.to_le_bytes());
    n
}

fn aad(mac: &[u8], index: u64, last: bool) -> [u8; MAC_LEN + 9] {
    let mut a = [0u8; MAC_LEN + 9];
    a[..MAC_LEN].copy_from_slice(mac);
    a[MAC_LEN..MAC_LEN + 8].copy_from_slice(&index.to_le_bytes());
    a[MAC_LEN + 8] = last as u8;
    a
}

fn meta_block(meta: &Meta) -> Result<Vec<u8>> {
    let name = meta.name.as_bytes();
    if name.len() > 4096 {
        return Err(Error::invalid("file name too long"));
    }
    let mut m = Vec::with_capacity(4 + 2 + name.len() + 16);
    m.extend_from_slice(&((2 + name.len() + 16) as u32).to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(name);
    m.extend_from_slice(&meta.modified.to_le_bytes());
    m.extend_from_slice(&meta.size.to_le_bytes());
    Ok(m)
}

fn sig_seed(backend: &dyn Backend, file_id: &[u8]) -> [u8; 64] {
    backend.sha512(&[b"QsCrypt v2 signature", file_id])
}

/// Encrypts `input` (exactly `meta.size` bytes). Returns the file id.
pub fn encrypt(
    backend: &dyn Backend,
    opts: &Options,
    meta: &Meta,
    created: i64,
    input: &mut dyn Read,
    output: &mut dyn Write,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<[u8; 16]> {
    let chunk = opts.params.chunk_size;
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk) {
        return Err(Error::invalid("bad chunk size"));
    }
    let meta_bytes = meta_block(meta)?;
    let sig_len = if opts.signer.is_some() { SIG_BLOCK as u64 } else { 0 };
    let body_len = meta_bytes.len() as u64 + meta.size;
    let stream_len = body_len + sig_len;
    let flags = if opts.signer.is_some() { FLAG_SIGNED } else { 0 };
    let (h, fk, file_id) = build_header(backend, opts, flags, chunk, stream_len, created)?;
    let keys = schedule(backend, &fk, &file_id)?;
    output.write_all(&h)?;
    let mac = &h[h.len() - MAC_LEN..];

    let c = chunk as usize;
    let total = stream_len.div_ceil(c as u64).max(1);
    let mut buf = vec![0u8; c];
    let mut meta_pos = 0usize;
    let mut chain = sig_seed(backend, &file_id);
    let mut sig_block: Option<Vec<u8>> = None;
    let mut sig_pos = 0usize;
    let mut pos = 0u64;
    let mut data_done = 0u64;
    for i in 0..total {
        let want = (stream_len - pos).min(c as u64) as usize;
        let mut fill = 0usize;
        while fill < want && meta_pos < meta_bytes.len() {
            let n = (want - fill).min(meta_bytes.len() - meta_pos);
            buf[fill..fill + n].copy_from_slice(&meta_bytes[meta_pos..meta_pos + n]);
            fill += n;
            meta_pos += n;
        }
        let data_end = (body_len.saturating_sub(pos)).min(want as u64) as usize;
        if fill < data_end {
            let got = read_full(input, &mut buf[fill..data_end])?;
            if got != data_end - fill {
                return Err(Error::invalid("input shorter than its declared size"));
            }
            data_done += got as u64;
            fill = data_end;
        }
        if let Some(signer) = opts.signer {
            chain = backend.sha512(&[&chain, &buf[..data_end]]);
            if fill < want {
                if sig_block.is_none() {
                    let sig = signer.sign(backend, &chain)?;
                    let mut b = signer.public.ed25519.to_vec();
                    b.extend_from_slice(&sig);
                    sig_block = Some(b);
                }
                let b = sig_block.as_ref().unwrap();
                let n = want - fill;
                buf[fill..want].copy_from_slice(&b[sig_pos..sig_pos + n]);
                sig_pos += n;
            }
        }
        let data = &mut buf[..want];
        ctr_xor(keys.aes.as_ref(), &keys.iv_aes, i << 16, data);
        ctr_xor(keys.twofish.as_ref(), &keys.iv_twofish, i << 16, data);
        let tag = backend.xchacha_seal(keys.aead[..].try_into().unwrap(), &nonce(&h[60..76], i), &aad(mac, i, i + 1 == total), data)?;
        output.write_all(data)?;
        output.write_all(&tag)?;
        pos += want as u64;
        if !progress(data_done, meta.size) {
            return Err(Error::Cancelled);
        }
    }
    crate::util::wipe(&mut buf);
    output.flush()?;
    Ok(file_id)
}

/// Decrypts after `read_header` and `unlock`; `output` None reads only the metadata.
pub fn decrypt(
    backend: &dyn Backend,
    h: &Header,
    file_key: &[u8],
    input: &mut dyn Read,
    mut output: Option<&mut dyn Write>,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<Decrypted> {
    if h.flags & FLAG_CONTAINER != 0 {
        return Err(Error::invalid("this is a QsCrypt container, not a file"));
    }
    let keys = schedule(backend, file_key, &h.file_id)?;
    let mac = &h.raw[h.raw.len() - MAC_LEN..];
    let c = h.chunk as usize;
    let stream_len = h.stream_len;
    let sig_len = if h.signed() { SIG_BLOCK as u64 } else { 0 };
    if stream_len < sig_len + 4 {
        return Err(Error::corrupt("QsCrypt stream too short"));
    }
    let body_len = stream_len - sig_len;
    let total = stream_len.div_ceil(c as u64).max(1);
    let mut buf = vec![0u8; c + TAG_LEN];
    let mut meta_buf: Vec<u8> = Vec::new();
    let mut meta: Option<Meta> = None;
    let mut meta_len = 0usize;
    let mut chain = sig_seed(backend, &h.file_id);
    let mut sig = Vec::new();
    let mut pos = 0u64;
    let mut written = 0u64;
    for i in 0..total {
        let want = (stream_len - pos).min(c as u64) as usize;
        if read_full(input, &mut buf[..want + TAG_LEN])? != want + TAG_LEN {
            return Err(Error::Tampered);
        }
        let (data, tag) = buf[..want + TAG_LEN].split_at_mut(want);
        backend.xchacha_open(keys.aead[..].try_into().unwrap(), &nonce(&h.raw[60..76], i), &aad(mac, i, i + 1 == total), data, (&*tag).try_into().unwrap())?;
        ctr_xor(keys.twofish.as_ref(), &keys.iv_twofish, i << 16, data);
        ctr_xor(keys.aes.as_ref(), &keys.iv_aes, i << 16, data);
        let data_end = (body_len.saturating_sub(pos)).min(want as u64) as usize;
        if h.signed() {
            chain = backend.sha512(&[&chain, &data[..data_end]]);
            sig.extend_from_slice(&data[data_end..]);
        }
        let mut body: &[u8] = &data[..data_end];
        if meta.is_none() {
            while meta.is_none() && !body.is_empty() {
                let need = if meta_buf.len() < 4 { 4 } else { 4 + le32(&meta_buf, 0) as usize };
                let take = (need - meta_buf.len()).min(body.len());
                meta_buf.extend_from_slice(&body[..take]);
                body = &body[take..];
                if meta_buf.len() >= 4 {
                    let mlen = le32(&meta_buf, 0) as usize;
                    if !(18..=4096 + 18).contains(&mlen) {
                        return Err(Error::corrupt("bad metadata block"));
                    }
                    if meta_buf.len() == 4 + mlen {
                        let m = &meta_buf[4..];
                        let nlen = le16(m, 0) as usize;
                        if 2 + nlen + 16 != mlen {
                            return Err(Error::corrupt("bad metadata block"));
                        }
                        let size = le64(m, 10 + nlen);
                        if (4 + mlen) as u64 + size != body_len {
                            return Err(Error::corrupt("size mismatch"));
                        }
                        meta_len = 4 + mlen;
                        meta = Some(Meta {
                            name: String::from_utf8_lossy(&m[2..2 + nlen]).into_owned(),
                            modified: i64::from_le_bytes(m[2 + nlen..10 + nlen].try_into().unwrap()),
                            size,
                        });
                    }
                }
            }
            if meta.is_some() && output.is_none() {
                let m = meta.take().unwrap();
                return Ok(Decrypted { meta: m, signer: None, signature_valid: false });
            }
        }
        if let Some(out) = output.as_deref_mut() {
            if !body.is_empty() {
                out.write_all(body)?;
                written += body.len() as u64;
            }
        }
        pos += want as u64;
        if !progress(written, meta.as_ref().map_or(0, |m| m.size)) {
            return Err(Error::Cancelled);
        }
    }
    crate::util::wipe(&mut buf);
    let meta = meta.ok_or_else(|| Error::corrupt("missing metadata"))?;
    let _ = meta_len;
    let mut extra = [0u8; 1];
    if read_full(input, &mut extra)? != 0 {
        return Err(Error::Tampered);
    }
    if let Some(out) = output {
        out.flush()?;
    }
    if written != meta.size {
        return Err(Error::Tampered);
    }
    let (signer, signature_valid) = if h.signed() && sig.len() == SIG_BLOCK {
        let pk: [u8; 32] = sig[..32].try_into().unwrap();
        let s: [u8; 64] = sig[32..].try_into().unwrap();
        (Some(pk), backend.ed25519_verify(&pk, &chain, &s))
    } else {
        (None, false)
    };
    Ok(Decrypted { meta, signer, signature_valid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::RefBackend;

    fn params() -> Params {
        Params { memory_kib: 64, iterations: 1, lanes: 1, chunk_size: 4096 }
    }

    fn opts<'a>(pw: Option<&'a [u8]>) -> Options<'a> {
        Options { password: pw, duress: None, recovery: None, recipients: &[], signer: None, policy: Policy::default(), params: params() }
    }

    fn enc(o: &Options, content: &[u8]) -> Vec<u8> {
        let b = RefBackend::with_fakes();
        let meta = Meta { name: "وثيقة.pdf".into(), modified: 1_770_000_000, size: content.len() as u64 };
        let mut out = Vec::new();
        encrypt(&b, o, &meta, 1_770_000_000, &mut &content[..], &mut out, &mut |_, _| true).unwrap();
        out
    }

    fn dec(file: &[u8], how: &Unlock) -> Result<(Decrypted, Vec<u8>, bool)> {
        let b = RefBackend::with_fakes();
        let mut input = file;
        let h = read_header(&mut input)?;
        let u = unlock(&b, &h, how)?;
        if u.duress {
            return Ok((Decrypted { meta: Meta { name: String::new(), modified: 0, size: 0 }, signer: None, signature_valid: false }, Vec::new(), true));
        }
        let mut out = Vec::new();
        let d = decrypt(&b, &h, &u.file_key, &mut input, Some(&mut out), &mut |_, _| true)?;
        Ok((d, out, false))
    }

    #[test]
    fn password_round_trip_and_sizes() {
        for size in [0usize, 1, 4000, 4096, 4096 * 3 + 5, 30_000] {
            let content: Vec<u8> = (0..size).map(|i| (i * 7 % 256) as u8).collect();
            let f = enc(&opts(Some(b"pw")), &content);
            let (d, out, duress) = dec(&f, &Unlock::Password(b"pw")).unwrap();
            assert!(!duress);
            assert_eq!(out, content, "{size}");
            assert_eq!(d.meta.name, "وثيقة.pdf");
            assert!(matches!(dec(&f, &Unlock::Password(b"nope")), Err(Error::WrongPassword)));
        }
    }

    #[test]
    fn duress_recovery_contacts_signature() {
        let b = RefBackend::with_fakes();
        let alice = SecretIdentity::generate(&b, "Alice").unwrap();
        let bob = SecretIdentity::generate(&b, "Bob").unwrap();
        let eve = SecretIdentity::generate(&b, "Eve").unwrap();
        let rk = generate_recovery_key(&b).unwrap();
        assert_eq!(rk.len(), 39);
        let recipients = vec![bob.public.clone()];
        let o = Options { password: Some(b"real"), duress: Some(b"panic"), recovery: Some(&rk), recipients: &recipients, signer: Some(&alice), policy: Policy::default(), params: params() };
        let content = vec![42u8; 10_000];
        let f = enc(&o, &content);
        let h = read_header(&mut &f[..]).unwrap();
        assert_eq!((h.password_slots, h.has_recovery, h.recipients, h.signed()), (2, true, 1, true));

        let (d, out, _) = dec(&f, &Unlock::Password(b"real")).unwrap();
        assert_eq!(out, content);
        assert_eq!(d.signer, Some(alice.public.ed25519));
        assert!(d.signature_valid);
        assert!(dec(&f, &Unlock::Password(b"panic")).unwrap().2, "duress detected");
        assert_eq!(dec(&f, &Unlock::Recovery(&rk.to_lowercase())).unwrap().1, content);
        assert_eq!(dec(&f, &Unlock::Identity(&bob)).unwrap().1, content);
        assert!(matches!(dec(&f, &Unlock::Identity(&eve)), Err(Error::WrongPassword)));

        // Contacts only: no password at all.
        let o2 = Options { password: None, duress: None, recovery: None, recipients: &recipients, signer: None, policy: Policy::default(), params: params() };
        let f2 = enc(&o2, b"for bob");
        assert!(matches!(dec(&f2, &Unlock::Password(b"real")), Err(Error::WrongPassword)));
        let (d2, out2, _) = dec(&f2, &Unlock::Identity(&bob)).unwrap();
        assert_eq!(out2, b"for bob");
        assert!(d2.signer.is_none());
    }

    #[test]
    fn policies_are_authenticated_and_evaluated() {
        let b = RefBackend::with_fakes();
        let mut o = opts(Some(b"pw"));
        o.policy = Policy { offline_only: Some(Action::Destroy), expires: Some((1_780_000_000, Action::Refuse)), open_once: true, max_attempts: Some((3, Action::Destroy)), auto_open: true };
        let f = enc(&o, b"x");
        let h = read_header(&mut &f[..]).unwrap();
        assert_eq!(h.policy, o.policy);
        let ok = Context { now: 1_775_000_000, max_seen: 1_775_000_000, online: false };
        assert_eq!(h.evaluate(&ok), Verdict::Allow);
        assert_eq!(h.evaluate(&Context { online: true, ..ok }), Verdict::Destroy("online"));
        assert_eq!(h.evaluate(&Context { now: 1_790_000_000, max_seen: 1_790_000_000, ..ok }), Verdict::Refuse("expired"));
        assert_eq!(h.evaluate(&Context { now: 1_771_000_000, max_seen: 1_776_000_000, ..ok }), Verdict::Refuse("clock"));
        assert_eq!(h.evaluate(&Context { now: 1_760_000_000, max_seen: 1_760_000_000, ..ok }), Verdict::Refuse("clock"), "before the file was made");

        // Removing a policy breaks the header MAC.
        let plen = le32(&f, 112) as usize;
        let mut stripped = f.clone();
        stripped[FIXED..FIXED + plen].iter_mut().for_each(|x| *x = 0x80 | 0x7F);
        let r = dec(&stripped, &Unlock::Password(b"pw"));
        assert!(matches!(r, Err(Error::Tampered) | Err(Error::Corrupt(_))), "{:?}", r.err());

        // Auto-open: the remembered file key opens it.
        let mut input = &f[..];
        let h = read_header(&mut input).unwrap();
        let u = unlock(&b, &h, &Unlock::Password(b"pw")).unwrap();
        let fk: [u8; 32] = u.file_key[..].try_into().unwrap();
        assert_eq!(dec(&f, &Unlock::FileKey(&fk)).unwrap().1, b"x");
    }

    #[test]
    fn tampering_is_detected() {
        let f = enc(&opts(Some(b"pw")), &vec![1u8; 9000]);
        let h = read_header(&mut &f[..]).unwrap();
        let hl = h.len();
        for (what, at) in [("data", hl + 100), ("header nonce prefix", 70), ("slot", hl - 40)] {
            let mut bad = f.clone();
            bad[at] ^= 1;
            let r = dec(&bad, &Unlock::Password(b"pw"));
            assert!(r.is_err(), "{what}");
        }
        let mut short = f.clone();
        short.truncate(f.len() - 1);
        assert!(dec(&short, &Unlock::Password(b"pw")).is_err());
        let mut long = f.clone();
        long.push(0);
        assert!(matches!(dec(&long, &Unlock::Password(b"pw")), Err(Error::Tampered)));
    }
}
