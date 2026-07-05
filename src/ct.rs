//! ct.

use subtle::ConstantTimeEq;

// Constant-time comparison
// ============================================================================

/// Constant-time byte slice comparison (no early exit on content).
/// Returns true only if both slices have the same length and content.
///
/// Uses the `subtle` crate's `ConstantTimeEq` to guarantee that the
/// compiler cannot optimize away the constant-time property.
///
/// **Note**: The length check is NOT constant-time — different lengths
/// return `false` immediately. This is standard practice (lengths are
/// typically public in authentication protocols). For comparisons where
/// the length must also be secret, use [`ct_eq_n`] with fixed-size arrays.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison for fixed-size byte arrays.
///
/// Both length and content comparisons are constant-time since the
/// length is statically known at compile time.
#[inline]
#[must_use]
pub fn ct_eq_n<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.as_slice().ct_eq(b.as_slice()).into()
}
