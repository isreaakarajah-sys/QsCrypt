//! FAT formatting as a sparse plan: the few metadata sectors that are not
//! zero. Container creation writes the whole data area (encrypted) anyway,
//! so the plan is overlaid on zeros as it streams.

use crate::error::{Error, Result};
use crate::util::{put_le16, put_le32};

pub struct FatPlan {
    pub fat_type: &'static str,
    pub cluster_size: u32,
    /// Sorted, non-overlapping (offset, bytes); everything else is zero.
    pub patches: Vec<(u64, Vec<u8>)>,
    /// Everything before this offset is file system metadata (boot area,
    /// allocation tables, root directory) and must be written as zeros plus
    /// patches even by a quick format: through an encryption layer,
    /// unwritten sectors read back as random bytes, not zeros.
    pub meta_end: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Fat12,
    Fat16,
    Fat32,
}

const BPS: u64 = 512;
const NUM_FATS: u64 = 2;

struct Geometry {
    ty: Ty,
    spc: u64,
    reserved: u64,
    root_entries: u64,
    fat_size: u64,
    clusters: u64,
}

fn geometry(total: u64, ty: Ty, spc: u64) -> Geometry {
    let (reserved, root_entries, bits): (u64, u64, u64) = match ty {
        Ty::Fat12 => (1, 512, 12),
        Ty::Fat16 => (1, 512, 16),
        Ty::Fat32 => (32, 0, 32),
    };
    let root_sectors = (root_entries * 32).div_ceil(BPS);
    let mut fat_size = 1u64;
    loop {
        let used = reserved + NUM_FATS * fat_size + root_sectors;
        let clusters = total.saturating_sub(used) / spc;
        let needed = ((clusters + 2) * bits).div_ceil(8).div_ceil(BPS);
        if needed <= fat_size {
            return Geometry { ty, spc, reserved, root_entries, fat_size, clusters };
        }
        fat_size = needed;
    }
}

fn valid(g: &Geometry) -> bool {
    match g.ty {
        Ty::Fat12 => (1..4085).contains(&g.clusters),
        Ty::Fat16 => (4085..65_525).contains(&g.clusters),
        Ty::Fat32 => (65_525..0x0FFF_FFF5).contains(&g.clusters),
    }
}

/// Microsoft's recommended cluster sizes (fatgen103), then the nearest valid one.
fn choose(total: u64) -> Result<Geometry> {
    let (ty, preferred) = if total < 8_400 {
        (Ty::Fat12, 1)
    } else if total < 1_048_576 {
        let spc = match total {
            t if t <= 32_680 => 2,
            t if t <= 262_144 => 4,
            _ => 8,
        };
        (Ty::Fat16, spc)
    } else {
        let spc = match total {
            t if t <= 16_777_216 => 8,
            t if t <= 33_554_432 => 16,
            t if t <= 67_108_864 => 32,
            _ => 64,
        };
        (Ty::Fat32, spc)
    };
    let mut candidates = vec![preferred];
    candidates.extend([1u64, 2, 4, 8, 16, 32, 64, 128].iter().filter(|&&s| s != preferred));
    for spc in candidates {
        let g = geometry(total, ty, spc);
        if valid(&g) {
            return Ok(g);
        }
    }
    Err(Error::invalid("size not suitable for FAT"))
}

fn sanitize_label(label: &str) -> Option<[u8; 11]> {
    let up: String = label.trim().to_ascii_uppercase();
    if up.is_empty() || !up.is_ascii() {
        return None;
    }
    let mut out = [b' '; 11];
    for (i, c) in up.chars().take(11).enumerate() {
        out[i] = if c.is_ascii_alphanumeric() || " $%'-_@~`!(){}^#&".contains(c) { c as u8 } else { b'_' };
    }
    Some(out)
}

pub fn format_plan(size: u64, label: &str, volume_id: u32) -> Result<FatPlan> {
    plan_with(size, label, volume_id, None)
}

/// Test hook: force FAT32 on a small volume.
#[cfg(test)]
pub fn format_plan_fat32(size: u64, label: &str) -> Result<FatPlan> {
    plan_with(size, label, 0x1234_5678, Some(Ty::Fat32))
}

fn plan_with(size: u64, label: &str, volume_id: u32, force: Option<Ty>) -> Result<FatPlan> {
    let total = size / BPS;
    if total < 128 {
        return Err(Error::invalid("volume too small for FAT"));
    }
    if total > u32::MAX as u64 {
        return Err(Error::invalid("volume too large for FAT (2 TiB)"));
    }
    let g = match force {
        Some(ty) => [1u64, 2, 4, 8].iter().map(|&spc| geometry(total, ty, spc)).find(valid).ok_or_else(|| Error::invalid("size not suitable"))?,
        None => choose(total)?,
    };
    let label_bytes = sanitize_label(label);
    let mut boot = vec![0u8; 512];
    boot[0] = 0xEB;
    boot[1] = if g.ty == Ty::Fat32 { 0x58 } else { 0x3C };
    boot[2] = 0x90;
    boot[3..11].copy_from_slice(b"MSDOS5.0");
    put_le16(&mut boot, 11, BPS as u16);
    boot[13] = g.spc as u8;
    put_le16(&mut boot, 14, g.reserved as u16);
    boot[16] = NUM_FATS as u8;
    put_le16(&mut boot, 17, g.root_entries as u16);
    if g.ty != Ty::Fat32 && total < 65_536 {
        put_le16(&mut boot, 19, total as u16);
    } else {
        put_le32(&mut boot, 32, total as u32);
    }
    boot[21] = 0xF8;
    if g.ty != Ty::Fat32 {
        put_le16(&mut boot, 22, g.fat_size as u16);
    }
    put_le16(&mut boot, 24, 63);
    put_le16(&mut boot, 26, 255);
    let ebpb = if g.ty == Ty::Fat32 {
        put_le32(&mut boot, 36, g.fat_size as u32);
        put_le32(&mut boot, 44, 2); // root cluster
        put_le16(&mut boot, 48, 1); // FSInfo sector
        put_le16(&mut boot, 50, 6); // backup boot sector
        64
    } else {
        36
    };
    boot[ebpb] = 0x80;
    boot[ebpb + 2] = 0x29;
    put_le32(&mut boot, ebpb + 3, volume_id);
    boot[ebpb + 7..ebpb + 18].copy_from_slice(&label_bytes.unwrap_or(*b"NO NAME    "));
    boot[ebpb + 18..ebpb + 26].copy_from_slice(match g.ty {
        Ty::Fat12 => b"FAT12   ",
        Ty::Fat16 => b"FAT16   ",
        Ty::Fat32 => b"FAT32   ",
    });
    boot[510] = 0x55;
    boot[511] = 0xAA;

    let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
    if g.ty == Ty::Fat32 {
        let mut fsinfo = vec![0u8; 512];
        put_le32(&mut fsinfo, 0, 0x4161_5252);
        put_le32(&mut fsinfo, 484, 0x6141_7272);
        put_le32(&mut fsinfo, 488, (g.clusters - 1) as u32);
        put_le32(&mut fsinfo, 492, 3);
        put_le32(&mut fsinfo, 508, 0xAA55_0000);
        let mut first = boot.clone();
        first.extend_from_slice(&fsinfo);
        patches.push((0, first));
        let mut backup = boot.clone();
        backup.extend_from_slice(&fsinfo);
        patches.push((6 * BPS, backup));
    } else {
        patches.push((0, boot));
    }

    let fat_head: Vec<u8> = match g.ty {
        Ty::Fat12 => vec![0xF8, 0xFF, 0xFF],
        Ty::Fat16 => vec![0xF8, 0xFF, 0xFF, 0xFF],
        Ty::Fat32 => vec![0xF8, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F],
    };
    for f in 0..NUM_FATS {
        patches.push(((g.reserved + f * g.fat_size) * BPS, fat_head.clone()));
    }

    if let Some(l) = label_bytes {
        let mut e = vec![0u8; 32];
        e[..11].copy_from_slice(&l);
        e[11] = 0x08;
        // FAT12/16: the fixed root region; FAT32: cluster 2. Both start
        // right after the FATs.
        patches.push(((g.reserved + NUM_FATS * g.fat_size) * BPS, e));
    }

    patches.sort_by_key(|p| p.0);
    let root_bytes = (g.root_entries * 32).div_ceil(BPS) * BPS;
    let meta_end = (g.reserved + NUM_FATS * g.fat_size) * BPS + root_bytes + if g.ty == Ty::Fat32 { g.spc * BPS } else { 0 };
    Ok(FatPlan {
        fat_type: match g.ty {
            Ty::Fat12 => "FAT12",
            Ty::Fat16 => "FAT16",
            Ty::Fat32 => "FAT32",
        },
        cluster_size: (g.spc * BPS) as u32,
        patches,
        meta_end,
    })
}

/// Copies the parts of `plan` that fall in [offset, offset + buf.len()).
pub fn apply_patches(patches: &[(u64, Vec<u8>)], offset: u64, buf: &mut [u8]) {
    let end = offset + buf.len() as u64;
    for (p_off, bytes) in patches {
        let p_end = p_off + bytes.len() as u64;
        if p_end <= offset || *p_off >= end {
            continue;
        }
        let from = offset.max(*p_off);
        let to = end.min(p_end);
        buf[(from - offset) as usize..(to - offset) as usize].copy_from_slice(&bytes[(from - p_off) as usize..(to - p_off) as usize]);
    }
}
