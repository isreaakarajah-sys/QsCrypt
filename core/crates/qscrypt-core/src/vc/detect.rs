//! Finding the format, PRF and cipher of a volume from its password alone.
//!
//! A volume header is indistinguishable from random data, so every
//! plausible combination is tried: header location (normal, hidden, and
//! optionally the backups) x format x PRF x encryption algorithm.
//!
//! The costly part is PBKDF2 (500 000 iterations per output block). The
//! output blocks are independent, so they are scheduled individually across
//! worker threads in order of likelihood: the first block of SHA-512 is
//! enough to test the single ciphers, later blocks unlock the cascades. The
//! first header whose magic and CRCs check out wins and stops all workers.

use super::header::{PlainHeader, ENC_SIZE, HEADER_SIZE, SALT_SIZE};
use super::{CipherChain, Ea, Format, HEADER_GROUP, HIDDEN_HEADER_OFFSET};
use crate::crypto::{Backend, Prf};
use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::Secret;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub struct OpenOptions<'a> {
    pub password: &'a [u8],
    /// 0 = default iteration count.
    pub pim: u32,
    /// `None` tries every PRF the backend supports.
    pub prf: Option<Prf>,
    /// `None` tries VeraCrypt then TrueCrypt.
    pub format: Option<Format>,
    pub try_hidden: bool,
    pub use_backup: bool,
}

impl<'a> OpenOptions<'a> {
    pub fn new(password: &'a [u8]) -> OpenOptions<'a> {
        OpenOptions { password, pim: 0, prf: None, format: None, try_hidden: true, use_backup: false }
    }
}

#[derive(Debug)]
pub struct OpenedHeader {
    pub header: PlainHeader,
    pub prf: Prf,
    pub ea: Ea,
    pub iterations: u32,
    pub pim: u32,
    pub hidden: bool,
    pub backup: bool,
    pub header_offset: u64,
}

struct Location {
    offset: u64,
    hidden: bool,
    backup: bool,
    salt: [u8; SALT_SIZE],
    enc: [u8; ENC_SIZE],
}

struct Config {
    format: Format,
    prf: Prf,
    iterations: u32,
}

struct Group {
    loc: usize,
    cfg: usize,
    blocks: Vec<Option<Secret>>,
    tested: [bool; 3],
}

struct State {
    groups: Vec<Group>,
    queue: VecDeque<(usize, usize)>,
    result: Option<OpenedHeader>,
    error: Option<Error>,
}

const TIER_EAS: [&[Ea]; 3] = [
    &[Ea::Aes, Ea::Serpent, Ea::Twofish],
    &[Ea::AesTwofish, Ea::SerpentAes, Ea::TwofishSerpent],
    &[Ea::AesTwofishSerpent, Ea::SerpentTwofishAes],
];

/// PBKDF2 blocks needed before the algorithms of `tier` can be tried.
fn blocks_for(tier: usize, prf: Prf) -> usize {
    (64 * (tier + 1)).div_ceil(prf.output_len())
}

fn rank(cfg: &Config) -> u32 {
    match (cfg.format, cfg.prf) {
        (Format::VeraCrypt, Prf::Sha512) => 0,
        (Format::TrueCrypt, _) => 1, // cheap: 1000-2000 iterations
        (Format::VeraCrypt, Prf::Sha256) => 2,
        (Format::VeraCrypt, Prf::Whirlpool) => 3,
        (Format::VeraCrypt, Prf::Ripemd160) => 4,
    }
}

fn try_header(backend: &dyn Backend, ea: Ea, dk: &[u8], enc: &[u8; ENC_SIZE]) -> Option<PlainHeader> {
    let chain = CipherChain::new(backend, ea, dk).ok()?;
    let mut buf = Secret::from_slice(enc);
    chain.decrypt(&mut buf, 512, 0);
    PlainHeader::parse(&buf)
}

fn read_location(disk: &mut dyn Disk, offset: u64, hidden: bool, backup: bool) -> Result<Location> {
    let mut raw = [0u8; HEADER_SIZE];
    disk.read_at(offset, &mut raw)?;
    Ok(Location {
        offset,
        hidden,
        backup,
        salt: raw[..SALT_SIZE].try_into().unwrap(),
        enc: raw[SALT_SIZE..].try_into().unwrap(),
    })
}

pub fn detect(backend: &dyn Backend, disk: &mut dyn Disk, opts: &OpenOptions, cancel: &AtomicBool) -> Result<OpenedHeader> {
    let size = disk.len();
    if size < HEADER_SIZE as u64 {
        return Err(Error::corrupt("file too small to be a volume"));
    }

    let mut locs = vec![read_location(disk, 0, false, false)?];
    if opts.try_hidden && size >= HIDDEN_HEADER_OFFSET + HEADER_SIZE as u64 {
        locs.push(read_location(disk, HIDDEN_HEADER_OFFSET, true, false)?);
    }
    if opts.use_backup && size >= 2 * HEADER_GROUP + HEADER_SIZE as u64 {
        locs.push(read_location(disk, size - HEADER_GROUP, false, true)?);
        if opts.try_hidden {
            locs.push(read_location(disk, size - HIDDEN_HEADER_OFFSET, true, true)?);
        }
    }

    let formats = match opts.format {
        Some(f) => vec![f],
        None => vec![Format::VeraCrypt, Format::TrueCrypt],
    };
    let mut cfgs = Vec::new();
    for format in formats {
        if format == Format::TrueCrypt && opts.pim > 0 {
            continue; // TrueCrypt has no PIM
        }
        for &prf in format.prfs() {
            if opts.prf.is_some_and(|p| p != prf) || !backend.has_prf(prf) {
                continue;
            }
            // 655 331 iterations of RIPEMD-160, dropped by VeraCrypt 1.26:
            // only when asked for explicitly.
            if format == Format::VeraCrypt && prf == Prf::Ripemd160 && opts.prf.is_none() {
                continue;
            }
            cfgs.push(Config { format, prf, iterations: format.iterations(prf, opts.pim) });
        }
    }
    cfgs.sort_by_key(rank);
    if cfgs.is_empty() {
        return Err(Error::unsupported("no usable PRF for these options"));
    }

    let tiers: Vec<Vec<Ea>> = TIER_EAS
        .iter()
        .map(|eas| eas.iter().copied().filter(|ea| ea.ciphers().iter().all(|c| backend.has_cipher(*c))).collect())
        .collect();
    let max_tier = (0..3).rev().find(|&t| !tiers[t].is_empty()).unwrap_or(0);

    let mut groups = Vec::new();
    let mut queue = VecDeque::new();
    for (ci, cfg) in cfgs.iter().enumerate() {
        let first = groups.len();
        for li in 0..locs.len() {
            groups.push(Group { loc: li, cfg: ci, blocks: vec![None; blocks_for(max_tier, cfg.prf)], tested: [false; 3] });
        }
        for tier in 0..=max_tier {
            let from = if tier == 0 { 0 } else { blocks_for(tier - 1, cfg.prf) };
            for g in first..groups.len() {
                for b in from..blocks_for(tier, cfg.prf) {
                    queue.push_back((g, b));
                }
            }
        }
    }

    let state = Mutex::new(State { groups, queue, result: None, error: None });
    let stop = AtomicBool::new(false);
    let workers = crate::kdf::worker_count().min(state.lock().unwrap().queue.len()).max(1);

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| s.spawn(|| worker(backend, opts, &locs, &cfgs, &tiers, max_tier, &state, &stop)))
            .collect();
        while !handles.iter().all(|h| h.is_finished()) {
            if cancel.load(Ordering::Relaxed) {
                stop.store(true, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    });

    let st = state.into_inner().unwrap();
    if let Some(found) = st.result {
        return validate(found, size);
    }
    if let Some(e) = st.error {
        return Err(e);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    Err(Error::WrongPassword)
}

#[allow(clippy::too_many_arguments)]
fn worker(
    backend: &dyn Backend,
    opts: &OpenOptions,
    locs: &[Location],
    cfgs: &[Config],
    tiers: &[Vec<Ea>],
    max_tier: usize,
    state: &Mutex<State>,
    stop: &AtomicBool,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let Some((gi, bi)) = state.lock().unwrap().queue.pop_front() else {
            return;
        };
        let (li, ci) = {
            let st = state.lock().unwrap();
            (st.groups[gi].loc, st.groups[gi].cfg)
        };
        let (loc, cfg) = (&locs[li], &cfgs[ci]);
        let hl = cfg.prf.output_len();
        let mut block = Secret::new(hl);
        match backend.pbkdf2_block(cfg.prf, opts.password, &loc.salt, cfg.iterations, bi as u32 + 1, &mut block, stop) {
            Ok(()) => {}
            Err(Error::Cancelled) => return,
            Err(e) => {
                let mut st = state.lock().unwrap();
                st.error.get_or_insert(e);
                stop.store(true, Ordering::Relaxed);
                return;
            }
        }

        let ready: Vec<(usize, Secret)> = {
            let mut st = state.lock().unwrap();
            let g = &mut st.groups[gi];
            g.blocks[bi] = Some(block);
            let mut ready = Vec::new();
            for tier in 0..=max_tier {
                let need = blocks_for(tier, cfg.prf);
                if g.tested[tier] || !(0..need).all(|i| g.blocks[i].is_some()) {
                    continue;
                }
                g.tested[tier] = true;
                let mut dk = Secret::new(need * hl);
                for i in 0..need {
                    dk[i * hl..(i + 1) * hl].copy_from_slice(g.blocks[i].as_ref().unwrap());
                }
                ready.push((tier, dk));
            }
            ready
        };

        for (tier, dk) in ready {
            for &ea in &tiers[tier] {
                let Some(header) = try_header(backend, ea, &dk, &loc.enc) else {
                    continue;
                };
                if header.format != cfg.format {
                    continue;
                }
                let mut st = state.lock().unwrap();
                st.result.get_or_insert(OpenedHeader {
                    header,
                    prf: cfg.prf,
                    ea,
                    iterations: cfg.iterations,
                    pim: opts.pim,
                    hidden: loc.hidden,
                    backup: loc.backup,
                    header_offset: loc.offset,
                });
                stop.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
}

fn validate(found: OpenedHeader, size: u64) -> Result<OpenedHeader> {
    let h = &found.header;
    if h.is_system() {
        return Err(Error::unsupported("system encryption (boot drive)"));
    }
    if h.format == Format::TrueCrypt && (h.version < 4 || h.required_version < 0x0600) {
        return Err(Error::unsupported("TrueCrypt volume older than 6.0"));
    }
    if h.version > 5 {
        return Err(Error::unsupported(format!("header version {}", h.version)));
    }
    let ok = h.data_offset % 512 == 0
        && h.data_size % 512 == 0
        && h.data_size > 0
        && h.data_offset >= HEADER_SIZE as u64
        && h.data_offset.checked_add(h.data_size).is_some_and(|end| end <= size);
    if !ok {
        return Err(Error::corrupt("data area outside the volume"));
    }
    Ok(found)
}
