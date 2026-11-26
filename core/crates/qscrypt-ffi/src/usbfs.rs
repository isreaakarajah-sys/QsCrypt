//! USB bulk transfers through Linux usbfs (what Android's
//! `UsbDeviceConnection` uses underneath), on the descriptor of a
//! connection whose mass-storage interface the app has claimed.

use qscrypt_core::usb::{UsbTransport, Xfer};
use qscrypt_core::{Error, Result};
use std::os::raw::{c_int, c_void};

#[repr(C)]
struct BulkTransfer {
    ep: u32,
    len: u32,
    timeout: u32,
    data: *mut c_void,
}

#[repr(C)]
struct CtrlTransfer {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    timeout: u32,
    data: *mut c_void,
}

const fn ioc(dir: u32, nr: u32, size: usize) -> u32 {
    (dir << 30) | ((size as u32) << 16) | ((b'U' as u32) << 8) | nr
}

const USBDEVFS_CONTROL: u32 = ioc(3, 0, std::mem::size_of::<CtrlTransfer>());
const USBDEVFS_BULK: u32 = ioc(3, 2, std::mem::size_of::<BulkTransfer>());
const USBDEVFS_CLEAR_HALT: u32 = ioc(2, 21, 4);
const EPIPE: i32 = 32;

#[cfg(target_os = "android")]
type Request = c_int;
#[cfg(not(target_os = "android"))]
type Request = std::os::raw::c_ulong;

extern "C" {
    fn ioctl(fd: c_int, request: Request, ...) -> c_int;
}

pub struct Usbfs {
    fd: c_int,
    ep_in: u8,
    ep_out: u8,
    interface: u16,
}

impl Usbfs {
    pub fn new(fd: i32, ep_in: u8, ep_out: u8, interface: u16) -> Result<Usbfs> {
        if fd < 0 || ep_in & 0x80 == 0 || ep_out & 0x80 != 0 {
            return Err(Error::invalid("bad USB endpoints"));
        }
        Ok(Usbfs { fd, ep_in, ep_out, interface })
    }

    fn bulk(&mut self, ep: u8, data: *mut c_void, len: usize, timeout: u32) -> Result<Xfer> {
        let mut t = BulkTransfer { ep: ep as u32, len: len as u32, timeout, data };
        // SAFETY: `t` points at a live buffer of `len` bytes for the call.
        let r = unsafe { ioctl(self.fd, USBDEVFS_BULK as Request, &mut t as *mut BulkTransfer) };
        if r >= 0 {
            return Ok(Xfer::Done(r as usize));
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(EPIPE) {
            return Ok(Xfer::Stalled);
        }
        Err(Error::Io(e))
    }
}

// SAFETY: the descriptor is only used from the thread holding the disk lock.
unsafe impl Send for Usbfs {}

impl UsbTransport for Usbfs {
    fn bulk_out(&mut self, data: &[u8], timeout_ms: u32) -> Result<Xfer> {
        let ep = self.ep_out;
        self.bulk(ep, data.as_ptr() as *mut c_void, data.len(), timeout_ms)
    }

    fn bulk_in(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<Xfer> {
        let ep = self.ep_in;
        self.bulk(ep, buf.as_mut_ptr() as *mut c_void, buf.len(), timeout_ms)
    }

    fn clear_halt(&mut self, endpoint_in: bool) -> Result<()> {
        let mut ep: u32 = if endpoint_in { self.ep_in } else { self.ep_out } as u32;
        // SAFETY: `ep` lives for the call.
        let r = unsafe { ioctl(self.fd, USBDEVFS_CLEAR_HALT as Request, &mut ep as *mut u32) };
        if r < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let mut c = CtrlTransfer { request_type: 0x21, request: 0xFF, value: 0, index: self.interface, length: 0, timeout: 5000, data: std::ptr::null_mut() };
        // SAFETY: no data stage; `c` lives for the call.
        let r = unsafe { ioctl(self.fd, USBDEVFS_CONTROL as Request, &mut c as *mut CtrlTransfer) };
        if r < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        self.clear_halt(true)?;
        self.clear_halt(false)
    }
}
