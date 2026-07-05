//! challenge ttl.

use crate::errors::*;
use crate::protocol::{check, AuthResult, Pending, Response};
use crate::random::challenge;
use crate::types::*;
use core::fmt;

// Challenge TTL (Timed Challenge-Response)
// ============================================================================

/// Challenge with a creation timestamp for TTL enforcement.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TimedPending {
    pub id: AliceId,
    pub c: [u8; 32],
    pub created_ms: u64,
}

impl fmt::Debug for TimedPending {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// Default challenge TTL: 30 seconds
pub const CHALLENGE_TTL_MS: u64 = 30_000;

/// Create a challenge with a timestamp for TTL enforcement.
/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline]
pub fn make_timed_challenge(id: AliceId, now_ms: u64) -> Result<TimedPending> {
    Ok(TimedPending {
        id,
        c: challenge()?,
        created_ms: now_ms,
    })
}

/// Verify a challenge-response with TTL enforcement.
///
/// Returns `AuthResult::Fail` if:
/// - The signature is invalid
/// - The challenge has expired (`now_ms` - `created_ms` > `ttl_ms`)
/// - The RNG fails to generate a session token
#[inline]
#[must_use]
pub fn check_timed(p: &TimedPending, r: &Response, now_ms: u64, ttl_ms: u64) -> AuthResult {
    if now_ms.saturating_sub(p.created_ms) > ttl_ms {
        return AuthResult::Fail;
    }
    let pending = Pending { id: p.id, c: p.c };
    check(&pending, r)
}
