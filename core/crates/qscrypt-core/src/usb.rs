//! USB flash drives and disks: Mass Storage Bulk-Only Transport (BOT) with
//! the SCSI transparent command set, as a `Disk`.
//!
//! The transport (one bulk transfer at a time) is supplied by the app: on
//! Android, usbfs ioctls on the descriptor of a claimed interface. Error
//! recovery follows the BOT specification: a stalled data stage is cleared
//! and the status still read; a bad status or phase error triggers the
//! Bulk-Only Mass Storage Reset.

use crate::disk::Disk;
use crate::error::{Error, Result};
use crate::util::{be32, be64};
use std::time::Duration;

/// Outcome of one bulk transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Xfer {
    Done(usize),
    /// The endpoint answered with STALL.
    Stalled,
}

pub trait UsbTransport: Send {
    fn bulk_out(&mut self, data: &[u8], timeout_ms: u32) -> Result<Xfer>;
    fn bulk_in(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<Xfer>;
    fn clear_halt(&mut self, endpoint_in: bool) -> Result<()>;
    /// Bulk-Only Mass Storage Reset (class request 0xFF), then clear both halts.
    fn reset(&mut self) -> Result<()>;
    /// Largest single bulk transfer the host stack accepts.
    fn max_transfer(&self) -> usize {
        16 * 1024
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    None,
    In,
    Out,
}

const CBW_SIG: u32 = 0x4342_5355;
const CSW_SIG: u32 = 0x5342_5355;
const TIMEOUT: u32 = 10_000;
/// Bytes moved per SCSI READ/WRITE.
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const CACHE_SEGMENT: u64 = 64 * 1024;
const CACHE_SLOTS: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct DriveInfo {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub block_size: u32,
    pub blocks: u64,
    pub write_protected: bool,
    pub removable: bool,
}

pub struct UsbDisk<T: UsbTransport> {
    t: T,
    lun: u8,
    tag: u32,
    info: DriveInfo,
    read_only: bool,
    /// (segment index, bytes, last use) — small read cache.
    cache: Vec<(u64, Vec<u8>, u64)>,
    clock: u64,
}

fn sense_error(sense: &[u8]) -> Error {
    let key = sense.get(2).map_or(0, |b| b & 0x0F);
    let asc = sense.get(12).copied().unwrap_or(0);
    let ascq = sense.get(13).copied().unwrap_or(0);
    match key {
        0x02 if asc == 0x3A => Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no medium in the drive")),
        0x07 => Error::ReadOnly,
        _ => Error::Io(std::io::Error::other(format!("SCSI error: sense {key:X}/{asc:02X}/{ascq:02X}"))),
    }
}

impl<T: UsbTransport> UsbDisk<T> {
    /// Probes the drive: INQUIRY, waits until it is ready, READ CAPACITY,
    /// write protection.
    pub fn open(t: T, lun: u8, read_only: bool) -> Result<UsbDisk<T>> {
        let mut d = UsbDisk { t, lun, tag: 1, info: DriveInfo::default(), read_only, cache: Vec::new(), clock: 0 };
        let mut inq = [0u8; 36];
        d.command(&[0x12, 0, 0, 0, 36, 0], Dir::In, &mut inq)?;
        let text = |b: &[u8]| String::from_utf8_lossy(b).trim().to_string();
        d.info.vendor = text(&inq[8..16]);
        d.info.product = text(&inq[16..32]);
        d.info.revision = text(&inq[32..36]);
        d.info.removable = inq[1] & 0x80 != 0;

        let mut ready = false;
        for attempt in 0..20 {
            match d.command(&[0, 0, 0, 0, 0, 0], Dir::None, &mut []) {
                Ok(()) => {
                    ready = true;
                    break;
                }
                Err(e) if attempt == 19 => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(if cfg!(test) { 0 } else { 150 })),
            }
        }
        if !ready {
            return Err(Error::Io(std::io::Error::other("drive not ready")));
        }

        let mut cap = [0u8; 8];
        d.command(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], Dir::In, &mut cap)?;
        let (mut last, mut bs) = (be32(&cap, 0) as u64, be32(&cap, 4));
        if last == 0xFFFF_FFFF {
            let mut cap16 = [0u8; 32];
            let mut cdb = [0u8; 16];
            cdb[0] = 0x9E;
            cdb[1] = 0x10;
            cdb[13] = 32;
            d.command(&cdb, Dir::In, &mut cap16)?;
            last = be64(&cap16, 0);
            bs = be32(&cap16, 8);
        }
        if !(512..=4096).contains(&bs) || !bs.is_power_of_two() {
            return Err(Error::unsupported(format!("block size {bs}")));
        }
        d.info.block_size = bs;
        d.info.blocks = last + 1;

        // MODE SENSE(6): device-specific parameter bit 7 = write protected.
        let mut ms = [0u8; 192];
        if d.command(&[0x1A, 0, 0x3F, 0, 192, 0], Dir::In, &mut ms).is_ok() {
            d.info.write_protected = ms[2] & 0x80 != 0;
        }
        if d.info.write_protected {
            d.read_only = true;
        }
        Ok(d)
    }

    pub fn info(&self) -> &DriveInfo {
        &self.info
    }

    pub fn into_transport(self) -> T {
        self.t
    }

    fn transfer_in(&mut self, buf: &mut [u8]) -> Result<Xfer> {
        let max = self.t.max_transfer();
        let mut done = 0;
        while done < buf.len() {
            let n = (buf.len() - done).min(max);
            match self.t.bulk_in(&mut buf[done..done + n], TIMEOUT)? {
                Xfer::Stalled => return Ok(Xfer::Stalled),
                Xfer::Done(got) => {
                    done += got;
                    if got < n {
                        break; // short packet ends the data stage
                    }
                }
            }
        }
        Ok(Xfer::Done(done))
    }

    fn transfer_out(&mut self, buf: &[u8]) -> Result<Xfer> {
        let max = self.t.max_transfer();
        let mut done = 0;
        while done < buf.len() {
            let n = (buf.len() - done).min(max);
            match self.t.bulk_out(&buf[done..done + n], TIMEOUT)? {
                Xfer::Stalled => return Ok(Xfer::Stalled),
                Xfer::Done(0) => return Err(Error::Io(std::io::Error::other("USB write made no progress"))),
                Xfer::Done(got) => done += got,
            }
        }
        Ok(Xfer::Done(done))
    }

    fn recover(&mut self) -> Error {
        match self.t.reset() {
            Ok(()) => Error::Io(std::io::Error::other("USB transfer failed; the drive was reset")),
            Err(e) => e,
        }
    }

    /// One BOT command cycle. Status "failed" is turned into an error from
    /// REQUEST SENSE; UNIT ATTENTION is retried once.
    fn command(&mut self, cdb: &[u8], dir: Dir, data: &mut [u8]) -> Result<()> {
        match self.command_once(cdb, dir, data)? {
            None => Ok(()),
            Some(sense) if sense.get(2).map(|b| b & 0x0F) == Some(0x06) => match self.command_once(cdb, dir, data)? {
                None => Ok(()),
                Some(sense) => Err(sense_error(&sense)),
            },
            Some(sense) => Err(sense_error(&sense)),
        }
    }

    /// `Ok(None)` on success, `Ok(Some(sense))` when the command failed.
    fn command_once(&mut self, cdb: &[u8], dir: Dir, data: &mut [u8]) -> Result<Option<Vec<u8>>> {
        debug_assert!(!cdb.is_empty() && cdb.len() <= 16);
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&CBW_SIG.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        cbw[12] = if dir == Dir::In { 0x80 } else { 0 };
        cbw[13] = self.lun;
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        match self.t.bulk_out(&cbw, TIMEOUT)? {
            Xfer::Done(31) => {}
            _ => return Err(self.recover()),
        }

        let mut data_ok = true;
        if !data.is_empty() {
            let r = match dir {
                Dir::In => self.transfer_in(data)?,
                Dir::Out => self.transfer_out(data)?,
                Dir::None => Xfer::Done(0),
            };
            match r {
                Xfer::Stalled => {
                    self.t.clear_halt(dir == Dir::In)?;
                    data_ok = false;
                }
                Xfer::Done(n) if n < data.len() => data_ok = false,
                _ => {}
            }
        }

        let mut csw = [0u8; 13];
        let mut got = self.t.bulk_in(&mut csw, TIMEOUT)?;
        if got == Xfer::Stalled {
            self.t.clear_halt(true)?;
            got = self.t.bulk_in(&mut csw, TIMEOUT)?;
        }
        if got != Xfer::Done(13) || u32::from_le_bytes(csw[0..4].try_into().unwrap()) != CSW_SIG || u32::from_le_bytes(csw[4..8].try_into().unwrap()) != tag {
            return Err(self.recover());
        }
        match csw[12] {
            0 if data_ok => Ok(None),
            0 => Err(Error::Io(std::io::Error::other("short USB transfer"))),
            1 => {
                if cdb[0] == 0x03 {
                    return Ok(Some(vec![0; 18]));
                }
                let mut sense = [0u8; 18];
                match self.command_once(&[0x03, 0, 0, 0, 18, 0], Dir::In, &mut sense)? {
                    None => Ok(Some(sense.to_vec())),
                    Some(_) => Ok(Some(vec![0; 18])),
                }
            }
            _ => Err(self.recover()),
        }
    }

    fn rw_blocks(&mut self, lba: u64, buf: &mut [u8], write: bool) -> Result<()> {
        let bs = self.info.block_size as usize;
        let per = (MAX_COMMAND_BYTES / bs).max(1);
        let mut done = 0usize;
        while done < buf.len() {
            let count = ((buf.len() - done) / bs).min(per);
            let at = lba + (done / bs) as u64;
            let chunk = &mut buf[done..done + count * bs];
            let cdb: Vec<u8> = if at + count as u64 > 0xFFFF_FFFF {
                let mut c = vec![if write { 0x8A } else { 0x88 }, 0];
                c.extend_from_slice(&at.to_be_bytes());
                c.extend_from_slice(&(count as u32).to_be_bytes());
                c.extend_from_slice(&[0, 0]);
                c
            } else {
                let mut c = vec![if write { 0x2A } else { 0x28 }, 0];
                c.extend_from_slice(&(at as u32).to_be_bytes());
                c.push(0);
                c.extend_from_slice(&(count as u16).to_be_bytes());
                c.push(0);
                c
            };
            self.command(&cdb, if write { Dir::Out } else { Dir::In }, chunk)?;
            done += count * bs;
        }
        Ok(())
    }

    fn segment(&mut self, seg: u64) -> Result<&[u8]> {
        self.clock += 1;
        let clock = self.clock;
        if let Some(i) = self.cache.iter().position(|c| c.0 == seg) {
            self.cache[i].2 = clock;
            return Ok(&self.cache[i].1);
        }
        let start = seg * CACHE_SEGMENT;
        let len = (self.len() - start).min(CACHE_SEGMENT) as usize;
        let mut bytes = vec![0u8; len];
        let bs = self.info.block_size as u64;
        self.rw_blocks(start / bs, &mut bytes, false)?;
        if self.cache.len() >= CACHE_SLOTS {
            let oldest = (0..self.cache.len()).min_by_key(|&i| self.cache[i].2).unwrap();
            self.cache.swap_remove(oldest);
        }
        self.cache.push((seg, bytes, clock));
        Ok(&self.cache.last().unwrap().1)
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(e) if e <= self.len() => Ok(()),
            _ => Err(Error::invalid("access beyond the end of the drive")),
        }
    }
}

impl<T: UsbTransport> Disk for UsbDisk<T> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        let bs = self.info.block_size as u64;
        // Large aligned reads bypass the cache.
        if buf.len() as u64 >= CACHE_SEGMENT && offset % bs == 0 && buf.len() as u64 % bs == 0 {
            return self.rw_blocks(offset / bs, buf, false);
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let seg = pos / CACHE_SEGMENT;
            let within = (pos % CACHE_SEGMENT) as usize;
            let bytes = self.segment(seg)?;
            let n = (bytes.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&bytes[within..within + n]);
            done += n;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check(offset, buf.len())?;
        let bs = self.info.block_size as u64;
        let first = offset / bs;
        let end = (offset + buf.len() as u64).div_ceil(bs);
        let mut blocks = vec![0u8; ((end - first) * bs) as usize];
        let skip = (offset - first * bs) as usize;
        if skip != 0 || buf.len() % bs as usize != 0 {
            // Partial blocks at the edges: read them first.
            self.read_at(first * bs, &mut blocks[..bs as usize])?;
            let last = blocks.len() - bs as usize;
            if last != 0 {
                let mut tail = vec![0u8; bs as usize];
                self.read_at((end - 1) * bs, &mut tail)?;
                blocks[last..].copy_from_slice(&tail);
            }
        }
        blocks[skip..skip + buf.len()].copy_from_slice(buf);
        self.rw_blocks(first, &mut blocks, true)?;
        // Keep cached segments coherent.
        let (a, b) = (first * bs, end * bs);
        for (seg, bytes, _) in self.cache.iter_mut() {
            let s = *seg * CACHE_SEGMENT;
            let e = s + bytes.len() as u64;
            if e <= a || s >= b {
                continue;
            }
            let from = a.max(s);
            let to = b.min(e);
            bytes[(from - s) as usize..(to - s) as usize].copy_from_slice(&blocks[(from - a) as usize..(to - a) as usize]);
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.info.blocks * self.info.block_size as u64
    }

    fn flush(&mut self) -> Result<()> {
        if !self.read_only {
            // SYNCHRONIZE CACHE(10); many flash drives do not implement it.
            let _ = self.command(&[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Dir::None, &mut []);
        }
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A SCSI target behind a BOT state machine, with fault injection.
    use super::*;

    #[derive(PartialEq)]
    enum Phase {
        Command,
        DataIn(Vec<u8>, usize),
        DataOut(Vec<u8>, u64, usize),
        Status(u32, u8),
    }

    pub struct MockDrive {
        pub data: Vec<u8>,
        pub block: u32,
        pub unit_attention: bool,
        pub stall_next_read: bool,
        pub commands: usize,
        phase: Phase,
        tag: u32,
        sense: [u8; 18],
    }

    impl MockDrive {
        pub fn new(size: usize, block: u32) -> MockDrive {
            MockDrive { data: vec![0; size], block, unit_attention: true, stall_next_read: false, commands: 0, phase: Phase::Command, tag: 0, sense: [0; 18] }
        }

        fn fail(&mut self, key: u8) -> Phase {
            self.sense = [0; 18];
            self.sense[0] = 0x70;
            self.sense[2] = key;
            Phase::Status(self.tag, 1)
        }

        fn run(&mut self, cdb: &[u8], len: usize) -> Phase {
            self.commands += 1;
            let bs = self.block as u64;
            match cdb[0] {
                0x00 if self.unit_attention => {
                    self.unit_attention = false;
                    self.fail(0x06)
                }
                0x00 | 0x35 => Phase::Status(self.tag, 0),
                0x03 => {
                    let s = self.sense.to_vec();
                    Phase::DataIn(s[..len.min(18)].to_vec(), 0)
                }
                0x12 => {
                    let mut r = vec![0u8; 36];
                    r[1] = 0x80;
                    r[8..16].copy_from_slice(b"QsTest  ");
                    r[16..32].copy_from_slice(b"Mock Drive      ");
                    r[32..36].copy_from_slice(b"1.00");
                    Phase::DataIn(r, 0)
                }
                0x1A => {
                    let mut r = vec![0u8; len];
                    r[0] = 3;
                    Phase::DataIn(r, 0)
                }
                0x25 => {
                    let mut r = vec![0u8; 8];
                    let last = (self.data.len() as u64 / bs - 1) as u32;
                    r[0..4].copy_from_slice(&last.to_be_bytes());
                    r[4..8].copy_from_slice(&self.block.to_be_bytes());
                    Phase::DataIn(r, 0)
                }
                0x28 | 0x88 => {
                    let (lba, n) = if cdb[0] == 0x28 { (be32(cdb, 2) as u64, u16::from_be_bytes([cdb[7], cdb[8]]) as u64) } else { (be64(cdb, 2), be32(cdb, 10) as u64) };
                    if (lba + n) * bs > self.data.len() as u64 {
                        return self.fail(0x05);
                    }
                    if self.stall_next_read {
                        self.stall_next_read = false;
                        return Phase::DataIn(Vec::new(), usize::MAX);
                    }
                    let s = (lba * bs) as usize;
                    Phase::DataIn(self.data[s..s + (n * bs) as usize].to_vec(), 0)
                }
                0x2A | 0x8A => {
                    let (lba, n) = if cdb[0] == 0x2A { (be32(cdb, 2) as u64, u16::from_be_bytes([cdb[7], cdb[8]]) as u64) } else { (be64(cdb, 2), be32(cdb, 10) as u64) };
                    Phase::DataOut(vec![0; (n * bs) as usize], lba, 0)
                }
                _ => self.fail(0x05),
            }
        }
    }

    impl UsbTransport for MockDrive {
        fn bulk_out(&mut self, data: &[u8], _: u32) -> Result<Xfer> {
            match std::mem::replace(&mut self.phase, Phase::Command) {
                Phase::Command => {
                    assert_eq!(data.len(), 31);
                    assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), CBW_SIG);
                    self.tag = u32::from_le_bytes(data[4..8].try_into().unwrap());
                    let len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
                    let cdb = data[15..15 + data[14] as usize].to_vec();
                    self.phase = self.run(&cdb, len);
                    Ok(Xfer::Done(31))
                }
                Phase::DataOut(mut buf, lba, pos) => {
                    buf[pos..pos + data.len()].copy_from_slice(data);
                    let pos = pos + data.len();
                    if pos == buf.len() {
                        let s = (lba * self.block as u64) as usize;
                        self.data[s..s + buf.len()].copy_from_slice(&buf);
                        self.phase = Phase::Status(self.tag, 0);
                    } else {
                        self.phase = Phase::DataOut(buf, lba, pos);
                    }
                    Ok(Xfer::Done(data.len()))
                }
                other => {
                    self.phase = other;
                    Ok(Xfer::Stalled)
                }
            }
        }

        fn bulk_in(&mut self, buf: &mut [u8], _: u32) -> Result<Xfer> {
            match std::mem::replace(&mut self.phase, Phase::Command) {
                Phase::DataIn(_, usize::MAX) => {
                    self.phase = Phase::Status(self.tag, 1);
                    self.sense = [0; 18];
                    self.sense[2] = 0x03;
                    Ok(Xfer::Stalled)
                }
                Phase::DataIn(bytes, pos) => {
                    let n = buf.len().min(bytes.len() - pos);
                    buf[..n].copy_from_slice(&bytes[pos..pos + n]);
                    if pos + n == bytes.len() {
                        self.phase = Phase::Status(self.tag, 0);
                    } else {
                        self.phase = Phase::DataIn(bytes, pos + n);
                    }
                    Ok(Xfer::Done(n))
                }
                Phase::Status(tag, status) => {
                    assert_eq!(buf.len(), 13);
                    buf[0..4].copy_from_slice(&CSW_SIG.to_le_bytes());
                    buf[4..8].copy_from_slice(&tag.to_le_bytes());
                    buf[8..12].fill(0);
                    buf[12] = status;
                    Ok(Xfer::Done(13))
                }
                other => {
                    self.phase = other;
                    Ok(Xfer::Stalled)
                }
            }
        }

        fn clear_halt(&mut self, _: bool) -> Result<()> {
            Ok(())
        }

        fn reset(&mut self) -> Result<()> {
            self.phase = Phase::Command;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockDrive;
    use super::*;

    #[test]
    fn probes_reads_and_writes() {
        let mut m = MockDrive::new(8 << 20, 512);
        for (i, b) in m.data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut d = UsbDisk::open(m, 0, false).unwrap();
        assert_eq!(d.info().vendor, "QsTest");
        assert_eq!(d.info().product, "Mock Drive");
        assert_eq!(d.len(), 8 << 20);
        assert!(!d.is_read_only());
        let mut buf = vec![0u8; 300_000];
        d.read_at(1234, &mut buf).unwrap();
        assert!(buf.iter().enumerate().all(|(i, &b)| b == ((i + 1234) % 251) as u8));
        d.write_at(100, b"hello usb").unwrap();
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 7) as u8).collect();
        d.write_at(1 << 20, &big).unwrap();
        let mut back = vec![0u8; 9];
        d.read_at(100, &mut back).unwrap();
        assert_eq!(&back, b"hello usb");
        let mut back = vec![0u8; big.len()];
        d.read_at(1 << 20, &mut back).unwrap();
        assert_eq!(back, big);
        d.flush().unwrap();
        let m = d.into_transport();
        assert_eq!(&m.data[100..109], b"hello usb");
        assert_eq!(m.data[99], 99);
    }

    #[test]
    fn recovers_from_a_stalled_read() {
        let m = MockDrive::new(1 << 20, 4096);
        let mut d = UsbDisk::open(m, 0, false).unwrap();
        assert_eq!(d.info().block_size, 4096);
        d.write_at(512, b"x").unwrap(); // sub-block write on a 4K drive
        d.cache.clear();
        let mut mt = d.into_transport();
        mt.stall_next_read = true;
        let mut d = UsbDisk::open(mt, 0, false).unwrap();
        d.cache.clear();
        // The open itself consumed no read; the next read stalls and fails...
        let mut b = [0u8; 1];
        let r = d.read_at(512, &mut b);
        assert!(r.is_err());
        // ...and the drive keeps working afterwards.
        d.read_at(512, &mut b).unwrap();
        assert_eq!(b[0], b'x');
    }
}
