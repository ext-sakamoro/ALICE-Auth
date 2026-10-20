//! trust chain.

use crate::errors::{AuthError, Result};
use crate::identity::*;
use crate::types::*;
use crate::verify::ok;
use core::fmt;

// Trust Chain (Identity Bootstrap / Endorsement)
// ============================================================================

/// An endorsement: a trust anchor (or intermediate) signs another identity's
/// public key to create a verifiable chain of trust.
///
/// Endorsements have an expiry time (`expires_ms`). Verification rejects
/// expired endorsements automatically.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Endorsement {
    pub endorser: AliceId,
    pub endorsed: AliceId,
    pub sig: AliceSig,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

impl fmt::Debug for Endorsement {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl Endorsement {
    /// Serialize the endorsement payload (`endorsed_id` || `issued_ms` || `expires_ms`)
    /// that gets signed by the endorser.
    #[inline]
    fn payload(endorsed: &AliceId, issued_ms: u64, expires_ms: u64) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..32].copy_from_slice(endorsed.as_bytes());
        buf[32..40].copy_from_slice(&issued_ms.to_le_bytes());
        buf[40..48].copy_from_slice(&expires_ms.to_le_bytes());
        buf
    }
}

/// Create an endorsement: the signer vouches for the target identity.
///
/// The endorsement is valid from `now_ms` until `now_ms + ttl_ms` inclusive
/// ([`verify_endorsement`] refuses only when `now_ms > expires_ms`), so
/// `ttl_ms = 0` gives an endorsement that verifies at `now_ms` and not after.
///
/// # Errors
///
/// [`AuthError::E6`] when `now_ms + ttl_ms` exceeds `u64::MAX`, [`AuthError::E7`]
/// when `target` starts with [`crate::RESERVED_PREFIX`] (the payload would start
/// like one of the crate's tagged formats; no real key does); nothing is signed.
#[inline]
pub fn endorse(
    signer: &Identity,
    target: &AliceId,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<Endorsement> {
    if target.as_bytes().starts_with(crate::RESERVED_PREFIX) {
        return Err(AuthError::E7);
    }
    let expires_ms = now_ms.checked_add(ttl_ms).ok_or(AuthError::E6)?;
    let payload = Endorsement::payload(target, now_ms, expires_ms);
    Ok(Endorsement {
        endorser: signer.id(),
        endorsed: *target,
        sig: signer.sign_reserved(&payload),
        issued_ms: now_ms,
        expires_ms,
    })
}

/// Verify a single endorsement: check signature validity AND expiry.
///
/// Returns `false` if the signature is invalid or `now_ms > expires_ms`.
#[inline]
#[must_use]
pub fn verify_endorsement(e: &Endorsement, now_ms: u64) -> bool {
    if now_ms > e.expires_ms || e.endorsed.as_bytes().starts_with(crate::RESERVED_PREFIX) {
        return false;
    }
    let payload = Endorsement::payload(&e.endorsed, e.issued_ms, e.expires_ms);
    ok(&e.endorser, &payload, &e.sig)
}

/// Verify a chain of endorsements from a root trust anchor.
///
/// The chain must satisfy:
/// 1. The first endorsement's endorser must be the root.
/// 2. Each subsequent endorsement's endorser must be the previous endorsed.
/// 3. All signatures must be valid.
/// 4. No endorsement is expired at `now_ms`.
#[must_use]
pub fn verify_chain(chain: &[Endorsement], root: &AliceId, now_ms: u64) -> bool {
    if chain.is_empty() {
        return false;
    }
    if chain[0].endorser != *root {
        return false;
    }
    if !verify_endorsement(&chain[0], now_ms) {
        return false;
    }
    let mut i = 1;
    while i < chain.len() {
        if chain[i].endorser != chain[i - 1].endorsed {
            return false;
        }
        if !verify_endorsement(&chain[i], now_ms) {
            return false;
        }
        i += 1;
    }
    true
}
