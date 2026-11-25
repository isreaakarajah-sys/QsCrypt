//! Key derivation drivers built on the backend: parallel PBKDF2 and HKDF.

use crate::crypto::{Backend, Prf};
use crate::error::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

pub fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(1, 8)
}

/// Full PBKDF2 output, computing independent output blocks in parallel.
pub fn pbkdf2(
    backend: &dyn Backend,
    prf: Prf,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
    cancel: &AtomicBool,
) -> Result<()> {
    let hl = prf.output_len();
    let blocks = out.len().div_ceil(hl);
    let next = Mutex::new(0usize);
    let results: Vec<Mutex<Option<Result<Vec<u8>>>>> = (0..blocks).map(|_| Mutex::new(None)).collect();
    let workers = worker_count().min(blocks.max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = {
                    let mut n = next.lock().unwrap();
                    if *n >= blocks || cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    *n += 1;
                    *n - 1
                };
                // Blocks are computed at full length; the copy below truncates the last.
                let mut buf = vec![0u8; hl];
                let r = backend
                    .pbkdf2_block(prf, password, salt, iterations, i as u32 + 1, &mut buf, cancel)
                    .map(|_| buf);
                let failed = r.is_err();
                *results[i].lock().unwrap() = Some(r);
                if failed {
                    return;
                }
            });
        }
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let total = out.len();
    for (i, slot) in results.into_iter().enumerate() {
        let mut block = slot.into_inner().unwrap().ok_or(Error::Cancelled)??;
        let start = i * hl;
        let end = (start + hl).min(total);
        out[start..end].copy_from_slice(&block[..end - start]);
        crate::util::wipe(&mut block);
    }
    Ok(())
}

/// HKDF with HMAC-SHA-512 (RFC 5869).
pub fn hkdf_sha512(backend: &dyn Backend, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() > 255 * 64 {
        return Err(Error::invalid("HKDF output too long"));
    }
    let mut prk = backend.hmac_sha512(salt, &[ikm]);
    let mut t: Vec<u8> = Vec::new();
    let mut off = 0;
    let mut counter = 1u8;
    while off < out.len() {
        let block = backend.hmac_sha512(&prk, &[&t, info, &[counter]]);
        let n = 64.min(out.len() - off);
        out[off..off + n].copy_from_slice(&block[..n]);
        crate::util::wipe(&mut t);
        t = block.to_vec();
        off += n;
        counter = counter.wrapping_add(1);
    }
    crate::util::wipe(&mut t);
    crate::util::wipe(&mut prk);
    Ok(())
}
