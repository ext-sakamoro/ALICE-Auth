//! verify.

use crate::errors::*;
use crate::types::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// Verify
// ============================================================================

/// # Errors
/// Returns `AuthError::E1` if the public key is invalid, or `AuthError::E3` if
/// the signature verification fails.
#[inline(always)]
pub fn verify(id: &AliceId, m: &[u8], s: &AliceSig) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&id.0).map_err(|_| AuthError::E1)?;
    pk.verify(m, &Signature::from_bytes(&s.0))
        .map_err(|_| AuthError::E3)
}

/// # Errors
/// Returns `AuthError::E1` if the public key is invalid, or `AuthError::E3` if
/// the signature verification fails.
#[inline(always)]
pub fn verify32(id: &AliceId, c: &[u8; 32], s: &AliceSig) -> Result<()> {
    verify(id, c, s)
}
/// Boolean signature verification (returns `true`/`false` instead of `Result`).
#[inline(always)]
#[must_use]
pub fn ok(id: &AliceId, m: &[u8], s: &AliceSig) -> bool {
    verify(id, m, s).is_ok()
}
