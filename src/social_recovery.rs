//! social recovery.

use crate::identity::*;
use crate::types::*;
use crate::verify::ok;
use core::fmt;

// Social Recovery (Guardian-based Key Migration)
// ============================================================================

/// Configuration for social recovery: a set of guardian identities and
/// the minimum number of approvals needed to authorize key migration.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct RecoveryConfig {
    pub guardians: Vec<AliceId>,
    pub threshold: u8,
}

/// A guardian's approval for migrating from `old_id` to `new_id`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RecoveryApproval {
    pub guardian: AliceId,
    pub old_id: AliceId,
    pub new_id: AliceId,
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
    /// Serialize the recovery payload that gets signed:
    /// "recover" || `old_id(32)` || `new_id(32)` || timestamp(8) = 79 bytes
    fn payload(old_id: &AliceId, new_id: &AliceId, approved_ms: u64) -> [u8; 79] {
        let mut buf = [0u8; 79];
        buf[0..7].copy_from_slice(b"recover");
        buf[7..39].copy_from_slice(old_id.as_bytes());
        buf[39..71].copy_from_slice(new_id.as_bytes());
        buf[71..79].copy_from_slice(&approved_ms.to_le_bytes());
        buf
    }
}

/// Guardian signs an approval for key migration.
///
/// The guardian vouches that `old_id` should be replaced by `new_id`.
#[must_use]
pub fn approve_recovery(
    guardian: &Identity,
    old_id: &AliceId,
    new_id: &AliceId,
    now_ms: u64,
) -> RecoveryApproval {
    let payload = RecoveryApproval::payload(old_id, new_id, now_ms);
    RecoveryApproval {
        guardian: guardian.id(),
        old_id: *old_id,
        new_id: *new_id,
        sig: guardian.sign(&payload),
        approved_ms: now_ms,
    }
}

/// Verify a single guardian's recovery approval.
#[must_use]
pub fn verify_recovery_approval(approval: &RecoveryApproval) -> bool {
    let payload =
        RecoveryApproval::payload(&approval.old_id, &approval.new_id, approval.approved_ms);
    ok(&approval.guardian, &payload, &approval.sig)
}

/// Validate a complete recovery request against a config.
///
/// Returns true if:
/// 1. At least `threshold` valid approvals from registered guardians
/// 2. All approvals agree on the same `old_id` and `new_id`
/// 3. All signatures verify correctly
#[cfg(feature = "std")]
#[must_use]
pub fn validate_recovery(
    config: &RecoveryConfig,
    old_id: &AliceId,
    new_id: &AliceId,
    approvals: &[RecoveryApproval],
) -> bool {
    if config.threshold == 0 || config.guardians.is_empty() {
        return false;
    }

    let mut valid_count: u8 = 0;
    let mut seen_guardians = Vec::new();

    for approval in approvals {
        // Must match the target migration
        if approval.old_id != *old_id || approval.new_id != *new_id {
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

    valid_count >= config.threshold
}
