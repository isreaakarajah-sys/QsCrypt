//! A secret mixed into the activation password before Argon2id.
//!
//! The activation password is never stored: it only decrypts the sealed fonts.
//! Its weak point is guessing, offline, against the sealed file. The pepper
//! takes that away: the fonts are sealed with password + pepper, and the
//! pepper is not in this public repository. Here the slot holds a placeholder;
//! the release step (`android/tools/pepper.py`) writes the real value into the
//! built library, masked, and erases the marker it finds it by.

/// A 16-byte marker for the release step, then the masked pepper.
#[used]
static SLOT: [u8; 48] = *b"QsPepperSlot-v1:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// Keeps the raw pepper out of the library file; the same bytes are in `pepper.py`.
const MASK: [u8; 32] = [0xb2, 0x3d, 0xa5, 0x8d, 0x91, 0x60, 0x77, 0x0d, 0x1b, 0x4b, 0xfc, 0xd7, 0xb2, 0x36, 0x3e, 0xcc, 0x16, 0x46, 0x0d, 0xc5, 0xbc, 0xc5, 0xad, 0x99, 0xf0, 0x44, 0x1c, 0xd6, 0x2e, 0xbd, 0xb0, 0xe5];

/// The pepper of this build (all-mask in an unpatched one, which therefore cannot activate).
pub fn get() -> [u8; 32] {
    // A volatile read: the compiler may not assume the slot's bytes.
    let raw: [u8; 48] = unsafe { core::ptr::read_volatile(&SLOT) };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = raw[16 + i] ^ MASK[i];
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn unpatched_build_has_the_mask_as_pepper() {
        assert_eq!(super::get(), super::MASK);
    }
}
