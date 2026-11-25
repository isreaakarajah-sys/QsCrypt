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
    read_only: bool,
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
        let read_only = read_only || disk.is_read_only();
        Ok(EncVolume { disk, chain, data_offset, data_size, read_only })
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
        self.chain.decrypt(buf, UNIT as usize, (self.data_offset / UNIT) + first);
        Ok(())
    }

    fn write_units(&mut self, first: u64, buf: &mut [u8]) -> Result<()> {
        self.chain.encrypt(buf, UNIT as usize, (self.data_offset / UNIT) + first);
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
