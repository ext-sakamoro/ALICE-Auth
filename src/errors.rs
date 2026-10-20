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
    /// A caller-supplied value that the crate signs starts with
    /// [`RESERVED_PREFIX`] (for example an endorsement target).
    E7 = 7,
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

// ============================================================================
// SignError
// ============================================================================

/// The first bytes of every message format this crate signs for itself (each
/// format starts with a tag under this prefix, for example
/// `alice-auth/grant/v1/////`).
///
/// The public signing paths ([`crate::Identity::sign`], `sign32`,
/// [`crate::RotatingIdentity::sign`], [`crate::respond`], `aa_sign` and the
/// Python `sign` / `sign32`) refuse a message whose raw bytes start with it, so
/// a key that signs bytes chosen by a host or by the other side of a protocol
/// cannot be made to sign one of these formats. The crate's own signers that
/// put caller-chosen bytes first refuse them the same way (`endorse` refuses a
/// target under the prefix with [`AuthError::E7`], and `verify_endorsement`
/// refuses such an endorsed id). The comparison is byte-exact: no case folding,
/// no trimming, offset 0 only.
pub const RESERVED_PREFIX: &[u8; 11] = b"alice-auth/";

/// Why a public signing path refused a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The message starts with [`RESERVED_PREFIX`].
    ReservedPrefix,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedPrefix => {
                f.write_str("the message starts with the reserved prefix alice-auth/")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {}
