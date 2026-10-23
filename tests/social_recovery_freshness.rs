//! Social recovery: a guardian approves one recovery request, not a bare (old, new) pair, and a request is good
//! for a bounded time.
//!
//! An approval used to sign only "recover" || old || new || `approved_ms`, and `validate_recovery` did not look at
//! the time: an approval collected once could be collected again and counted for a later recovery of the same
//! pair. Now the approval signs the request (its random nonce and the time it was issued), and the request is
//! refused once it is older than the configuration's `max_age_ms`.
//!
//! References: the expected signature below was computed by a separate program (Python, the RFC 8032 section 6
//! reference Ed25519, checked against RFC 8032 TEST 1 and 3; it also reproduces the keys of `tests/player_grant.rs`),
//! not by this crate. The guardian is the identity of the seed `[5; 32]`; the request moves the identity of seed
//! `[1; 32]` to that of `[2; 32]`, with the nonce `00 01 .. 0f`, issued at 1000 ms; the guardian approves it at
//! 1500 ms, signing `alice-auth/recover/v2///` || old || new || nonce || `issued_ms` (u64 LE) || `approved_ms` (u64 LE),
//! 120 bytes.

#![cfg(feature = "std")]

use alice_auth::{
    approve_recovery, validate_recovery, verify_recovery_approval, Identity, RecoveryConfig,
    RecoveryError, RecoveryRequest, TAG_RECOVERY_V2,
};

const SIG: &str = "90e0350d8b16b2ac099003c3fc8d7e411c21757d3e263679cdd54c9e96e23a7f021ebb5f9e2437c0596a5b5104192f58c1cc81b34c201de0e811e3907ebb0800";
const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn id(b: u8) -> Identity {
    Identity::from_seed(&[b; 32])
}

fn request(nonce: [u8; 16], issued_ms: u64) -> RecoveryRequest {
    RecoveryRequest::with_nonce(id(1).id(), id(2).id(), nonce, issued_ms)
}

/// guardians 5, 6, 7, two needed, a request is good for 10 s
fn config() -> RecoveryConfig {
    RecoveryConfig {
        guardians: vec![id(5).id(), id(6).id(), id(7).id()],
        threshold: 2,
        max_age_ms: 10_000,
    }
}

fn assert_ok(r: Result<alice_auth::ApprovedRecovery, RecoveryError>) {
    let a = r.expect("the recovery is approved");
    assert!(a.approvals() >= 2);
}

fn assert_refused(r: Result<alice_auth::ApprovedRecovery, RecoveryError>) {
    assert!(r.is_err(), "the recovery was approved");
}

#[test]
fn the_tag_is_24_bytes_under_the_reserved_prefix() {
    assert_eq!(TAG_RECOVERY_V2, b"alice-auth/recover/v2///");
}

#[test]
fn the_approval_signs_the_request() {
    let a = approve_recovery(&id(5), &request(NONCE, 1000), 1500);
    let want: Vec<u8> = (0..SIG.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&SIG[k..k + 2], 16).unwrap())
        .collect();
    assert_eq!(a.sig.0.to_vec(), want);
    assert!(verify_recovery_approval(&a));
}

#[test]
fn approvals_of_a_fresh_request_recover() {
    let r = request(NONCE, 1000);
    let approvals = [
        approve_recovery(&id(5), &r, 1500),
        approve_recovery(&id(6), &r, 2000),
    ];
    assert_ok(validate_recovery(&config(), &r, &approvals, 3000));
    // up to and including the end of the request's time
    assert_ok(validate_recovery(&config(), &r, &approvals, 11_000));
}

#[test]
fn approvals_collected_for_one_request_do_not_count_for_another() {
    let first = request(NONCE, 1000);
    let approvals = [
        approve_recovery(&id(5), &first, 1500),
        approve_recovery(&id(6), &first, 2000),
    ];
    // the same pair, a later request with another nonce: the old approvals are a replay
    let same_time = request([9; 16], 1000); // inside the approvals' time: only the nonce tells them apart
    assert_refused(validate_recovery(&config(), &same_time, &approvals, 3000));
    let later = request([9; 16], 50_000);
    assert_refused(validate_recovery(&config(), &later, &approvals, 50_500));
}

#[test]
fn an_expired_request_is_refused() {
    let r = request(NONCE, 1000);
    let approvals = [
        approve_recovery(&id(5), &r, 1500),
        approve_recovery(&id(6), &r, 2000),
    ];
    assert_refused(validate_recovery(&config(), &r, &approvals, 11_001));
}

#[test]
fn an_approval_dated_before_the_request_or_after_now_does_not_count() {
    let r = request(NONCE, 1000);
    let early = approve_recovery(&id(5), &r, 999);
    let late = approve_recovery(&id(5), &r, 4000);
    let good = approve_recovery(&id(6), &r, 2000);
    assert_refused(validate_recovery(&config(), &r, &[early, good], 3000));
    assert_refused(validate_recovery(&config(), &r, &[late, good], 3000));
}

#[test]
fn an_approval_whose_nonce_or_issue_time_was_changed_does_not_verify() {
    let r = request(NONCE, 1000);
    let mut a = approve_recovery(&id(5), &r, 1500);
    a.nonce[0] ^= 1;
    assert!(!verify_recovery_approval(&a));
    let mut b = approve_recovery(&id(5), &r, 1500);
    b.issued_ms += 1;
    assert!(!verify_recovery_approval(&b));
}

#[test]
fn a_random_request_has_a_fresh_nonce() {
    let a = RecoveryRequest::new(id(1).id(), id(2).id(), 1000).unwrap();
    let b = RecoveryRequest::new(id(1).id(), id(2).id(), 1000).unwrap();
    assert_ne!(a.nonce, b.nonce);
}

#[test]
fn the_approved_recovery_names_its_request_so_the_nonce_can_be_recorded() {
    let r = request(NONCE, 1000);
    let approvals = [
        approve_recovery(&id(5), &r, 1500),
        approve_recovery(&id(6), &r, 2000),
    ];
    let ok = validate_recovery(&config(), &r, &approvals, 3000).unwrap();
    assert_eq!(*ok.request(), r);
    assert_eq!(ok.request().nonce, NONCE);
    assert_eq!(ok.approvals(), 2);
}

#[test]
fn the_reason_of_a_refusal_is_told() {
    let r = request(NONCE, 1000);
    let one = [approve_recovery(&id(5), &r, 1500)];
    assert_eq!(
        validate_recovery(&config(), &r, &one, 3000).err(),
        Some(RecoveryError::NotEnoughApprovals {
            valid: 1,
            needed: 2
        })
    );
    assert_eq!(
        validate_recovery(&config(), &r, &one, 11_001).err(),
        Some(RecoveryError::Expired {
            age_ms: 10_001,
            max_age_ms: 10_000
        })
    );
    assert_eq!(
        validate_recovery(&config(), &r, &one, 999).err(),
        Some(RecoveryError::NotYetIssued)
    );
    let empty = RecoveryConfig {
        guardians: vec![],
        threshold: 0,
        max_age_ms: 10_000,
    };
    assert_eq!(
        validate_recovery(&empty, &r, &one, 3000).err(),
        Some(RecoveryError::NotConfigured)
    );
    assert!(!RecoveryError::NotConfigured.to_string().is_empty());
}

#[test]
fn an_approval_of_another_pair_with_the_same_nonce_does_not_count() {
    // A2: the nonce alone does not bind the approval; the pair does too
    let r = request(NONCE, 1000);
    let other = RecoveryRequest::with_nonce(id(3).id(), id(4).id(), NONCE, 1000);
    let approvals = [
        approve_recovery(&id(5), &other, 1500),
        approve_recovery(&id(6), &other, 2000),
    ];
    assert_eq!(
        validate_recovery(&config(), &r, &approvals, 3000).err(),
        Some(RecoveryError::NotEnoughApprovals {
            valid: 0,
            needed: 2
        })
    );
}

#[test]
fn an_approval_with_a_flipped_signature_byte_does_not_count() {
    // A11: fed to validate_recovery, not only to verify_recovery_approval
    let r = request(NONCE, 1000);
    let mut bad = approve_recovery(&id(5), &r, 1500);
    bad.sig.0[0] ^= 1;
    let good = approve_recovery(&id(6), &r, 2000);
    assert_eq!(
        validate_recovery(&config(), &r, &[bad, good], 3000).err(),
        Some(RecoveryError::NotEnoughApprovals {
            valid: 1,
            needed: 2
        })
    );
}
