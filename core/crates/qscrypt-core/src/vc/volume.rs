//! The decrypted view of a volume's data area, as a `Disk`.

use super::{CipherChain, UNIT};
use crate::disk::Disk;
use crate::error::{Error, Result};

/// Largest span decrypted in one go (bounds the scratch buffer).
const CHUNK: usize = 1 << 20;

pub struct EncVolume {
    disk: Box<dyn Disk>,
    chain: CipherChain,
    data_offset: u64,
    data_size: u64,
    /// XTS unit number of the first data unit (VeraCrypt: data_offset / 512).
    unit_base: u64,
    read_only: bool,
    /// Absolute byte range of a hidden volume that writes must not touch.
    protect: Option<(u64, u64)>,
    tripped: bool,
}

impl EncVolume {
    /// `data_offset`/`data_size` come from the header (absolute, in bytes).
    /// XTS unit numbers are absolute too: unit = (data_offset + offset) / 512.
    pub fn new(disk: Box<dyn Disk>, chain: CipherChain, data_offset: u64, data_size: u64, read_only: bool) -> Result<EncVolume> {
        if data_offset % UNIT != 0 || data_size % UNIT != 0 {
            return Err(Error::corrupt("unaligned data area"));
        }
        if data_offset + data_size > disk.len() {
            return Err(Error::corrupt("data area beyond end of file"));
        }
        EncVolume::with_unit_base(disk, chain, data_offset, data_size, read_only, data_offset / UNIT)
    }

    /// Like `new`, with an explicit number for the first data unit.
    pub fn with_unit_base(disk: Box<dyn Disk>, chain: CipherChain, data_offset: u64, data_size: u64, read_only: bool, unit_base: u64) -> Result<EncVolume> {
        if data_offset % UNIT != 0 || data_size % UNIT != 0 {
            return Err(Error::corrupt("unaligned data area"));
        }
        if data_offset + data_size > disk.len() {
            return Err(Error::corrupt("data area beyond end of file"));
        }
        let read_only = read_only || disk.is_read_only();
        Ok(EncVolume { disk, chain, data_offset, data_size, unit_base, read_only, protect: None, tripped: false })
    }

    /// Hidden volume protection: refuse writes overlapping `[start, end)`
    /// (absolute offsets in the container). After the first refused write
    /// every write is refused, as VeraCrypt does.
    pub fn protect(&mut self, start: u64, end: u64) {
        self.protect = Some((start, end));
    }

    /// The protected range relative to this volume's data area.
    pub fn protected_range(&self) -> Option<(u64, u64)> {
        self.protect.map(|(s, e)| (s.saturating_sub(self.data_offset), e.saturating_sub(self.data_offset).min(self.data_size)))
    }

    pub fn protection_tripped(&self) -> bool {
        self.tripped
    }

    pub fn ea_name(&self) -> &'static str {
        self.chain.ea().name()
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(end) if end <= self.data_size => Ok(()),
            _ => Err(Error::invalid("access beyond the end of the volume")),
        }
    }

    /// Reads and decrypts whole units [first, first + count).
    fn read_units(&mut self, first: u64, buf: &mut [u8]) -> Result<()> {
        self.disk.read_at(self.data_offset + first * UNIT, buf)?;
        self.chain.decrypt(buf, UNIT as usize, self.unit_base + first);
        Ok(())
    }

    fn write_units(&mut self, first: u64, buf: &mut [u8]) -> Result<()> {
        self.chain.encrypt(buf, UNIT as usize, self.unit_base + first);
        self.disk.write_at(self.data_offset + first * UNIT, buf)
    }
}

impl Disk for EncVolume {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        let mut done = 0usize;
        let mut scratch = Vec::new();
        while done < buf.len() {
            let pos = offset + done as u64;
            let unit = pos / UNIT;
            let skip = (pos % UNIT) as usize;
            let want = (buf.len() - done).min(CHUNK - skip);
            let span = (skip + want).div_ceil(UNIT as usize) * UNIT as usize;
            if skip == 0 && want == span {
                // Aligned: decrypt straight into the caller's buffer.
                self.read_units(unit, &mut buf[done..done + span])?;
            } else {
                scratch.resize(span, 0);
                self.read_units(unit, &mut scratch)?;
                buf[done..done + want].copy_from_slice(&scratch[skip..skip + want]);
            }
            done += want;
        }
        crate::util::wipe(&mut scratch);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check(offset, buf.len())?;
        if let Some((start, end)) = self.protect {
            let a = self.data_offset + offset;
            let b = a + buf.len() as u64;
            if self.tripped || (!buf.is_empty() && a < end && b > start) {
                self.tripped = true;
                return Err(Error::HiddenProtected);
            }
        }
        let mut done = 0usize;
        let mut scratch = Vec::new();
        while done < buf.len() {
            let pos = offset + done as u64;
            let unit = pos / UNIT;
            let skip = (pos % UNIT) as usize;
            let want = (buf.len() - done).min(CHUNK - skip);
            let span = (skip + want).div_ceil(UNIT as usize) * UNIT as usize;
            scratch.resize(span, 0);
            if skip != 0 || want != span {
                // Partial units at either end: read-modify-write.
                if skip != 0 {
                    self.read_units(unit, &mut scratch[..UNIT as usize])?;
                }
                if (skip + want) % UNIT as usize != 0 {
                    let last = span - UNIT as usize;
                    let last_unit = unit + (last as u64 / UNIT);
                    if last != 0 || skip == 0 {
                        self.read_units(last_unit, &mut scratch[last..span])?;
                    }
                }
            }
            scratch[skip..skip + want].copy_from_slice(&buf[done..done + want]);
            self.write_units(unit, &mut scratch)?;
            done += want;
        }
        crate::util::wipe(&mut scratch);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.data_size
    }

    fn flush(&mut self) -> Result<()> {
        self.disk.flush()
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
}
