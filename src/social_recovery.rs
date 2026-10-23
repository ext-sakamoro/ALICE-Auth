//! social recovery.

use crate::identity::*;
use crate::types::*;
use crate::verify::ok;
use core::fmt;

// Social Recovery (Guardian-based Key Migration)
// ============================================================================

/// The domain tag of an approval's signed bytes (24 bytes, under the reserved `alice-auth/` prefix).
pub const TAG_RECOVERY_V2: &[u8; 24] = b"alice-auth/recover/v2///";

/// Length of the bytes a guardian signs: tag (24) || old (32) || new (32) || nonce (16) || issued (8) ||
/// approved (8).
const APPROVAL_SIGNED_LEN: usize = 24 + 32 + 32 + 16 + 8 + 8;

/// Configuration for social recovery: the guardian identities, how many approvals authorize a key migration, and
/// how long a recovery request stays good.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct RecoveryConfig {
    pub guardians: Vec<AliceId>,
    pub threshold: u8,
    /// A request is refused once more than this many milliseconds have passed since it was issued.
    pub max_age_ms: u64,
}

/// One request to move `old_id` to `new_id`, made by whoever starts the recovery and shown to the guardians.
///
/// The random `nonce` makes every request distinct: a guardian's approval is for this request only, so approvals
/// collected for an earlier recovery of the same pair cannot be counted again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct RecoveryRequest {
    pub old_id: AliceId,
    pub new_id: AliceId,
    pub nonce: [u8; 16],
    pub issued_ms: u64,
}

impl RecoveryRequest {
    /// A request issued at `issued_ms` with a random nonce.
    ///
    /// # Errors
    ///
    /// `AuthError::E5` if the platform RNG fails.
    pub fn new(old_id: AliceId, new_id: AliceId, issued_ms: u64) -> crate::errors::Result<Self> {
        Ok(Self::with_nonce(
            old_id,
            new_id,
            crate::random::rand()?,
            issued_ms,
        ))
    }

    /// A request with a given nonce (a test, or a nonce drawn elsewhere: it must not repeat).
    #[must_use]
    pub const fn with_nonce(
        old_id: AliceId,
        new_id: AliceId,
        nonce: [u8; 16],
        issued_ms: u64,
    ) -> Self {
        Self {
            old_id,
            new_id,
            nonce,
            issued_ms,
        }
    }
}

/// A guardian's approval of one [`RecoveryRequest`].
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RecoveryApproval {
    pub guardian: AliceId,
    pub old_id: AliceId,
    pub new_id: AliceId,
    pub nonce: [u8; 16],
    pub issued_ms: u64,
    pub sig: AliceSig,
    pub approved_ms: u64,
}

impl fmt::Debug for RecoveryApproval {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl RecoveryApproval {
    /// The bytes a guardian signs: [`TAG_RECOVERY_V2`] || old (32) || new (32) || nonce (16) || `issued_ms` (u64
    /// LE) || `approved_ms` (u64 LE), 120 bytes.
    fn signed_bytes(request: &RecoveryRequest, approved_ms: u64) -> [u8; APPROVAL_SIGNED_LEN] {
        let mut buf = [0u8; APPROVAL_SIGNED_LEN];
        buf[0..24].copy_from_slice(TAG_RECOVERY_V2);
        buf[24..56].copy_from_slice(request.old_id.as_bytes());
        buf[56..88].copy_from_slice(request.new_id.as_bytes());
        buf[88..104].copy_from_slice(&request.nonce);
        buf[104..112].copy_from_slice(&request.issued_ms.to_le_bytes());
        buf[112..120].copy_from_slice(&approved_ms.to_le_bytes());
        buf
    }

    /// The request this approval is for.
    #[must_use]
    pub const fn request(&self) -> RecoveryRequest {
        RecoveryRequest::with_nonce(self.old_id, self.new_id, self.nonce, self.issued_ms)
    }
}

/// A guardian approves `request` at `now_ms`.
///
/// The guardian vouches that `request.old_id` should be replaced by `request.new_id`, for this request only.
#[must_use]
pub fn approve_recovery(
    guardian: &Identity,
    request: &RecoveryRequest,
    now_ms: u64,
) -> RecoveryApproval {
    let signed = RecoveryApproval::signed_bytes(request, now_ms);
    RecoveryApproval {
        guardian: guardian.id(),
        old_id: request.old_id,
        new_id: request.new_id,
        nonce: request.nonce,
        issued_ms: request.issued_ms,
        sig: guardian.sign_reserved(&signed),
        approved_ms: now_ms,
    }
}

/// Whether the approval's signature is its guardian's, over its request and time.
#[must_use]
pub fn verify_recovery_approval(approval: &RecoveryApproval) -> bool {
    let signed = RecoveryApproval::signed_bytes(&approval.request(), approval.approved_ms);
    ok(&approval.guardian, &signed, &approval.sig)
}

/// A recovery the guardians approved: the request it was for, and how many approvals counted.
///
/// The caller must record `request().nonce` as consumed once it has migrated the identity, and must refuse a
/// request whose nonce it has already consumed: the approvals of one request stay valid until the request expires,
/// so without the record the same approvals could migrate the identity again within that time.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedRecovery {
    request: RecoveryRequest,
    approvals: u8,
}

#[cfg(feature = "std")]
impl ApprovedRecovery {
    /// The request that was approved (its nonce is the one to record as consumed).
    #[must_use]
    pub const fn request(&self) -> &RecoveryRequest {
        &self.request
    }

    /// How many distinct registered guardians' valid approvals counted.
    #[must_use]
    pub const fn approvals(&self) -> u8 {
        self.approvals
    }
}

/// Why `validate_recovery` refused a recovery.
#[cfg(feature = "std")]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The configuration names no guardian, or a threshold of 0.
    NotConfigured,
    /// `now_ms` is before the request was issued.
    NotYetIssued,
    /// The request is older than the configuration allows.
    Expired { age_ms: u64, max_age_ms: u64 },
    /// Fewer valid approvals for this request than the threshold.
    NotEnoughApprovals { valid: u8, needed: u8 },
}

#[cfg(feature = "std")]
impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => {
                f.write_str("the recovery configuration names no guardian or a threshold of 0")
            }
            Self::NotYetIssued => f.write_str("the recovery request is dated after now"),
            Self::Expired { age_ms, max_age_ms } => {
                write!(
                    f,
                    "the recovery request is {age_ms} ms old, more than {max_age_ms} ms"
                )
            }
            Self::NotEnoughApprovals { valid, needed } => {
                write!(
                    f,
                    "{valid} valid approval(s) for this request, {needed} needed"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoveryError {}

/// Validate a recovery request at `now_ms` against a config.
///
/// Approves when the request is still good (`now_ms` is not before it was issued and at most `config.max_age_ms`
/// after) and at least `threshold` approvals are for this exact request (same old, new, nonce and issue time),
/// from distinct registered guardians, dated from the issue time to `now_ms`, with valid signatures.
///
/// Clocks: there is no tolerance for skew. An approval dated later than `now_ms` is not counted, and a request
/// dated later than `now_ms` is refused, so `now_ms` should come from a clock that is not behind the guardians' and
/// the requester's. A caller that accepts some skew passes `now_ms` plus that amount, and sets `max_age_ms` with it
/// in mind.
///
/// Replay: approvals collected for one request never count for another (the request's random nonce is signed),
/// but they stay valid for the same request until it expires. Record the approved request's nonce as consumed
/// (see [`ApprovedRecovery`]).
///
/// # Errors
///
/// [`RecoveryError`] says why the recovery was refused.
#[cfg(feature = "std")]
pub fn validate_recovery(
    config: &RecoveryConfig,
    request: &RecoveryRequest,
    approvals: &[RecoveryApproval],
    now_ms: u64,
) -> Result<ApprovedRecovery, RecoveryError> {
    if config.threshold == 0 || config.guardians.is_empty() {
        return Err(RecoveryError::NotConfigured);
    }
    let Some(age) = now_ms.checked_sub(request.issued_ms) else {
        return Err(RecoveryError::NotYetIssued);
    };
    if age > config.max_age_ms {
        return Err(RecoveryError::Expired {
            age_ms: age,
            max_age_ms: config.max_age_ms,
        });
    }

    let mut valid_count: u8 = 0;
    let mut seen_guardians = Vec::new();

    for approval in approvals {
        // Must be for this request: an approval of another request (even of the same pair) is a replay
        if approval.request() != *request {
            continue;
        }
        // Must be dated within the request's time so far
        if approval.approved_ms < request.issued_ms || approval.approved_ms > now_ms {
            continue;
        }
        // Must be a registered guardian
        if !config.guardians.contains(&approval.guardian) {
            continue;
        }
        // Reject duplicate guardian approvals (same guardian cannot vote twice)
        if seen_guardians.contains(&approval.guardian) {
            continue;
        }
        // Signature must verify
        if !verify_recovery_approval(approval) {
            continue;
        }
        seen_guardians.push(approval.guardian);
        valid_count = valid_count.saturating_add(1);
    }

    if valid_count >= config.threshold {
        Ok(ApprovedRecovery {
            request: *request,
            approvals: valid_count,
        })
    } else {
        Err(RecoveryError::NotEnoughApprovals {
            valid: valid_count,
            needed: config.threshold,
        })
    }
}
