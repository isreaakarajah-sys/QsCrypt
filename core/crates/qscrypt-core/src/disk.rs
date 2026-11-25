//! Random-access storage: raw container files, decrypted volumes, memory.

use crate::error::{Error, Result};
use std::fs::File;
use std::io::{Seek, SeekFrom};

pub trait Disk: Send {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    fn len(&self) -> u64;
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn is_read_only(&self) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn check_range(offset: u64, len: usize, size: u64) -> Result<()> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Ok(()),
        _ => Err(Error::invalid(format!("access {offset}+{len} beyond end {size}"))),
    }
}

/// In-memory disk, used by tests and for building images.
pub struct MemDisk {
    pub data: Vec<u8>,
}

impl MemDisk {
    pub fn new(size: usize) -> MemDisk {
        MemDisk { data: vec![0u8; size] }
    }
}

impl Disk for MemDisk {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.data.len() as u64)?;
        let o = offset as usize;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        check_range(offset, buf.len(), self.data.len() as u64)?;
        let o = offset as usize;
        self.data[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.data.len() as u64
    }
}

/// A file (or a file descriptor handed over by Android's Storage Access
/// Framework) accessed with positional reads and writes.
pub struct FileDisk {
    file: File,
    len: u64,
    read_only: bool,
}

impl FileDisk {
    pub fn new(mut file: File, read_only: bool) -> Result<FileDisk> {
        let len = file.seek(SeekFrom::End(0))?;
        Ok(FileDisk { file, len, read_only })
    }

    /// Takes a duplicate of a raw descriptor owned by the caller (the app
    /// keeps and closes its own copy).
    #[cfg(unix)]
    pub fn from_borrowed_fd(fd: i32, read_only: bool) -> Result<FileDisk> {
        use std::os::fd::BorrowedFd;
        if fd < 0 {
            return Err(Error::invalid("bad file descriptor"));
        }
        // SAFETY: the caller guarantees `fd` is open for the duration of this call.
        let owned = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        FileDisk::new(File::from(owned), read_only)
    }

    /// Grows or shrinks the underlying file (used when creating containers).
    pub fn set_len(&mut self, len: u64) -> Result<()> {
        self.file.set_len(len)?;
        self.len = len;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

impl Disk for FileDisk {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_exact_at(buf, offset)?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            let mut done = 0;
            while done < buf.len() {
                let n = self.file.seek_read(&mut buf[done..], offset + done as u64)?;
                if n == 0 {
                    return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                done += n;
            }
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        check_range(offset, buf.len(), self.len)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.write_all_at(buf, offset)?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            let mut done = 0;
            while done < buf.len() {
                let n = self.file.seek_write(&buf[done..], offset + done as u64)?;
                done += n;
            }
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn flush(&mut self) -> Result<()> {
        if !self.read_only {
            self.file.sync_data()?;
        }
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
}
