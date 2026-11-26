//! exFAT formatting as a sparse plan, with the same contract as the FAT one:
//! only the metadata that is not zero, overlaid on a zeroed data area.
//!
//! Layout (512-byte sectors): main boot region 0-11, backup 12-23, one FAT
//! at sector 128, then the cluster heap aligned to the cluster size, holding
//! the allocation bitmap, the up-case table and the root directory.

use super::fat_format::FatPlan;
use crate::error::{Error, Result};
use crate::util::{put_le16, put_le32, put_le64};

const BPS: u64 = 512;
const FAT_OFFSET: u64 = 128;
const EOC: u32 = 0xFFFF_FFFF;

/// Microsoft's default cluster sizes for exFAT.
pub fn default_cluster_size(size: u64) -> u64 {
    if size < 256 << 20 {
        4096
    } else if size < 32 << 30 {
        32 * 1024
    } else {
        128 * 1024
    }
}

/// Simple one-to-one upper-case mapping of the Basic Multilingual Plane.
pub fn upcase_table() -> Vec<u16> {
    (0..=0xFFFFu32)
        .map(|c| {
            let Some(ch) = char::from_u32(c) else { return c as u16 };
            let mut up = ch.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) if (u as u32) < 0x10000 => u as u16,
                _ => c as u16,
            }
        })
        .collect()
}

/// Compressed form: runs of identity mappings become `0xFFFF, length`.
pub fn compress_upcase(table: &[u16]) -> Vec<u8> {
    let mut words: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i < table.len() {
        if table[i] as usize == i {
            let mut j = i;
            while j < table.len() && table[j] as usize == j {
                j += 1;
            }
            // A literal 0xFFFF would read as a run marker, so the run that
            // reaches U+FFFF is always compressed.
            if j - i >= 3 || j == table.len() {
                words.push(0xFFFF);
                words.push((j - i) as u16);
            } else {
                words.extend((i..j).map(|k| k as u16));
            }
            i = j;
        } else {
            words.push(table[i]);
            i += 1;
        }
    }
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(crate) fn table_checksum(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |c, &b| (if c & 1 != 0 { 0x8000_0000u32 } else { 0 }).wrapping_add(c >> 1).wrapping_add(b as u32))
}

/// Checksum of the first 11 sectors of a boot region, skipping
/// VolumeFlags (106, 107) and PercentInUse (112).
pub(crate) fn boot_checksum(region: &[u8]) -> u32 {
    let mut c = 0u32;
    for (i, &b) in region[..11 * BPS as usize].iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        c = (if c & 1 != 0 { 0x8000_0000u32 } else { 0 }).wrapping_add(c >> 1).wrapping_add(b as u32);
    }
    c
}

pub fn exfat_format_plan(size: u64, label: &str, volume_id: u32) -> Result<FatPlan> {
    plan_with(size, label, volume_id, default_cluster_size(size))
}

pub(crate) fn plan_with(size: u64, label: &str, volume_id: u32, cluster: u64) -> Result<FatPlan> {
    let total = size / BPS;
    if total < 2048 {
        return Err(Error::invalid("volume too small for exFAT (1 MiB minimum)"));
    }
    let spc = cluster / BPS;
    let mut fat_len = 1u64;
    let (heap, count) = loop {
        let heap = (FAT_OFFSET + fat_len).div_ceil(spc) * spc;
        if heap >= total {
            return Err(Error::invalid("volume too small for exFAT"));
        }
        let count = ((total - heap) / spc).min(0xFFFF_FFF5);
        let need = ((count + 2) * 4).div_ceil(BPS);
        if need <= fat_len {
            break (heap, count);
        }
        fat_len = need;
    };
    let units: Vec<u16> = label.trim().encode_utf16().take(11).collect();

    let upcase = compress_upcase(&upcase_table());
    let bitmap_bytes = count.div_ceil(8);
    let bitmap_clusters = bitmap_bytes.div_ceil(cluster);
    let upcase_clusters = (upcase.len() as u64).div_ceil(cluster);
    let used = bitmap_clusters + upcase_clusters + 1;
    if used + 1 > count {
        return Err(Error::invalid("volume too small for exFAT"));
    }
    let bitmap_first = 2u32;
    let upcase_first = bitmap_first + bitmap_clusters as u32;
    let root = upcase_first + upcase_clusters as u32;

    // Boot region.
    let mut region = vec![0u8; 12 * BPS as usize];
    {
        let b = &mut region[..512];
        b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        b[3..11].copy_from_slice(b"EXFAT   ");
        put_le64(b, 72, total);
        put_le32(b, 80, FAT_OFFSET as u32);
        put_le32(b, 84, fat_len as u32);
        put_le32(b, 88, heap as u32);
        put_le32(b, 92, count as u32);
        put_le32(b, 96, root);
        put_le32(b, 100, volume_id);
        put_le16(b, 104, 0x0100);
        b[108] = 9;
        b[109] = spc.trailing_zeros() as u8;
        b[110] = 1;
        b[111] = 0x80;
        b[112] = (used * 100 / count) as u8;
        b[120..510].fill(0xF4);
        b[510] = 0x55;
        b[511] = 0xAA;
    }
    for s in 1..9usize {
        let end = (s + 1) * 512;
        region[end - 2] = 0x55;
        region[end - 1] = 0xAA;
    }
    let sum = boot_checksum(&region);
    for k in 0..128usize {
        put_le32(&mut region, 11 * 512 + 4 * k, sum);
    }
    let mut boot = region.clone();
    boot.extend_from_slice(&region);

    // FAT: media entries, then chains for bitmap, up-case table and root.
    let mut fat = vec![0u8; (root as usize + 1) * 4];
    put_le32(&mut fat, 0, 0xFFFF_FFF8);
    put_le32(&mut fat, 4, EOC);
    for (first, n) in [(bitmap_first, bitmap_clusters as u32), (upcase_first, upcase_clusters as u32), (root, 1)] {
        for c in first..first + n {
            put_le32(&mut fat, c as usize * 4, if c + 1 == first + n { EOC } else { c + 1 });
        }
    }

    // Allocation bitmap: the first `used` clusters.
    let mut bitmap = vec![0u8; used.div_ceil(8) as usize];
    for i in 0..used as usize {
        bitmap[i / 8] |= 1 << (i % 8);
    }

    // Root directory: volume label, allocation bitmap, up-case table.
    let mut dir = vec![0u8; 96];
    dir[0] = 0x83;
    dir[1] = units.len() as u8;
    for (k, &u) in units.iter().enumerate() {
        put_le16(&mut dir, 2 + 2 * k, u);
    }
    dir[32] = 0x81;
    put_le32(&mut dir, 32 + 20, bitmap_first);
    put_le64(&mut dir, 32 + 24, bitmap_bytes);
    dir[64] = 0x82;
    put_le32(&mut dir, 64 + 4, table_checksum(&upcase));
    put_le32(&mut dir, 64 + 20, upcase_first);
    put_le64(&mut dir, 64 + 24, upcase.len() as u64);

    let at = |c: u32| heap * BPS + (c as u64 - 2) * cluster;
    let patches = vec![(0, boot), (FAT_OFFSET * BPS, fat), (at(bitmap_first), bitmap), (at(upcase_first), upcase), (at(root), dir)];
    debug_assert!(patches.windows(2).all(|w| w[0].0 + w[0].1.len() as u64 <= w[1].0));
    Ok(FatPlan { fat_type: "exFAT", cluster_size: cluster as u32, patches })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upcase_round_trips_through_compression() {
        let t = upcase_table();
        assert_eq!(t[b'a' as usize], b'A' as u16);
        assert_eq!(t['ß' as usize], 'ß' as u16, "multi-character mappings stay identity");
        assert_eq!(t['ا' as usize], 'ا' as u16);
        let c = compress_upcase(&t);
        assert!(c.len() < 12_000, "{}", c.len());
        assert_eq!(super::super::exfat::expand_upcase(&c), t);
    }

    #[test]
    fn geometry() {
        let p = exfat_format_plan(64 << 20, "QsCrypt", 7).unwrap();
        assert_eq!(p.cluster_size, 4096);
        let p = exfat_format_plan(5 << 30, "", 7).unwrap();
        assert_eq!(p.cluster_size, 32768);
        assert!(exfat_format_plan(512 * 1024, "", 7).is_err());
    }
}
