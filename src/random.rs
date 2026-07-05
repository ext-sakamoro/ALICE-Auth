//! random.

use crate::errors::*;

// Random
// ============================================================================

/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline(always)]
pub fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| AuthError::E5)?;
    Ok(b)
}

/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline(always)]
pub fn challenge() -> Result<[u8; 32]> {
    rand()
}
