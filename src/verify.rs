//! verify.
//!
//! Every signature check of the crate goes through [`verify`], which uses
//! `ed25519-dalek`'s `verify_strict`: besides an invalid signature it refuses a
//! small-order public key (under which a plain Ed25519 check accepts one
//! signature for every message) and a small-order R.

use crate::errors::*;
use crate::types::*;
use ed25519_dalek::{Signature, VerifyingKey};

// Verify
// ============================================================================

/// Strict Ed25519 verification of `s` over `m` under `id`.
///
/// # Errors
/// Returns `AuthError::E1` if the public key is invalid, or `AuthError::E3` if
/// the signature does not verify strictly (including a small-order key or R).
#[inline(always)]
pub fn verify(id: &AliceId, m: &[u8], s: &AliceSig) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&id.0).map_err(|_| AuthError::E1)?;
    pk.verify_strict(m, &Signature::from_bytes(&s.0))
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
