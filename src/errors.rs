//! errors.

use core::fmt;

// ============================================================================
// Error (zero .rodata, no match)
// ============================================================================

/// Authentication error codes (E1–E6). Zero `.rodata` in release builds.
///
/// The numbers are fixed (they cross the C ABI and appear in logs); a new code
/// takes the next number, so the enum is `#[non_exhaustive]`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AuthError {
    E1 = 1,
    E2 = 2,
    E3 = 3,
    E4 = 4,
    E5 = 5,
    /// An arithmetic overflow (for example a validity window past `u64::MAX` ms).
    E6 = 6,
}

impl fmt::Display for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 0.5.1: release でも同じ出力 (以前は release で空文字列 = silent no-op)
        let c = [b'E', b'0' + (*self as u8)];
        f.write_str(unsafe { core::str::from_utf8_unchecked(&c) })
    }
}

impl fmt::Debug for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub type Result<T> = core::result::Result<T, AuthError>;
