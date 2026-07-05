//! errors.

use core::fmt;

// ============================================================================
// Error (zero .rodata, no match)
// ============================================================================

/// Authentication error codes (E1–E5). Zero `.rodata` in release builds.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthError {
    E1 = 1,
    E2 = 2,
    E3 = 3,
    E4 = 4,
    E5 = 5,
}

impl fmt::Display for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            let c = [b'E', b'0' + (*self as u8)];
            f.write_str(unsafe { core::str::from_utf8_unchecked(&c) })
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = f;
            Ok(())
        }
    }
}

impl fmt::Debug for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub type Result<T> = core::result::Result<T, AuthError>;
