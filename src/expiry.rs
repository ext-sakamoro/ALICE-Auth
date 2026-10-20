//! expiry.

/// `true` when something that expires at `expires_ms` has expired at `now_ms`.
///
/// The crate's one expiry convention, exclusive: valid while
/// `now_ms < expires_ms`, expired from `now_ms == expires_ms` on. Tokens,
/// endorsements, JWT claims, timed challenges, synced rate-limit reports, and
/// player grants and revocation entries all decide expiry here.
#[inline(always)]
#[must_use]
pub const fn is_expired(now_ms: u64, expires_ms: u64) -> bool {
    now_ms >= expires_ms
}
