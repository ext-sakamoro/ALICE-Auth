//! Integration tests.

#![allow(
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use crate::challenge_ttl::*;
use crate::ct::*;
use crate::errors::*;
use crate::identity::*;
use crate::protocol::*;
use crate::random::*;
use crate::social_recovery::*;
use crate::trust_chain::*;
use crate::types::*;
use crate::verify::*;

#[test]
fn gen() {
    assert_eq!(Identity::gen().unwrap().id().0.len(), 32);
}
#[test]
fn sign_verify() {
    let i = Identity::gen().unwrap();
    assert!(ok(&i.id(), b"x", &i.sign(b"x")));
}
#[test]
fn challenge_flow() {
    let i = Identity::gen().unwrap();
    let c = challenge().unwrap();
    assert!(verify32(&i.id(), &c, &i.sign32(&c)).is_ok());
}
#[test]
fn wrong_signer() {
    let a = Identity::gen().unwrap();
    let b = Identity::gen().unwrap();
    assert!(!ok(&b.id(), b"x", &a.sign(b"x")));
}
#[test]
fn tamper() {
    let i = Identity::gen().unwrap();
    assert!(!ok(&i.id(), b"y", &i.sign(b"x")));
}
#[test]
fn seed_recovery() {
    let a = Identity::gen().unwrap();
    let b = Identity::from_seed(&a.seed());
    assert_eq!(a.id(), b.id());
}
#[test]
fn full_flow() {
    let i = Identity::gen().unwrap();
    let h = hello(&i);
    let p = make_challenge(h.id).unwrap();
    let r = respond(&i, &Challenge { n: p.c });
    assert!(matches!(check(&p, &r), AuthResult::Ok(_)));
}
#[test]
fn did() {
    let i = Identity::gen().unwrap();
    let mut b = [0u8; 84];
    assert!(i.id().write_did(&mut b).starts_with("alice://did:ed25519:"));
}
#[test]
fn layout() {
    assert_eq!(core::mem::size_of::<AliceId>(), 32);
    assert_eq!(core::mem::size_of::<AliceSig>(), 64);
}

// --- Additional tests ---

#[test]
fn alice_id_new_and_as_bytes() {
    let raw = [0x42u8; 32];
    let id = AliceId::new(raw);
    assert_eq!(*id.as_bytes(), raw);
}

#[test]
fn alice_id_into_bytes() {
    let raw = [0xAB; 32];
    let id = AliceId::new(raw);
    assert_eq!(id.into_bytes(), raw);
}

#[test]
fn alice_id_equality() {
    let a = AliceId::new([1u8; 32]);
    let b = AliceId::new([1u8; 32]);
    let c = AliceId::new([2u8; 32]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn alice_sig_new_and_as_bytes() {
    let raw = [0xEE; 64];
    let sig = AliceSig::new(raw);
    assert_eq!(*sig.as_bytes(), raw);
}

#[test]
fn alice_sig_into_bytes() {
    let raw = [0xDD; 64];
    let sig = AliceSig::new(raw);
    assert_eq!(sig.into_bytes(), raw);
}

#[test]
fn alice_sig_equality() {
    let a = AliceSig::new([1u8; 64]);
    let b = AliceSig::new([1u8; 64]);
    let c = AliceSig::new([2u8; 64]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn verify_invalid_public_key_returns_e1() {
    let bad_id = AliceId::new([0xFF; 32]);
    let sig = AliceSig::new([0u8; 64]);
    let result = verify(&bad_id, b"msg", &sig);
    assert!(result.is_err());
}

#[test]
fn verify32_invalid_sig_returns_err() {
    let i = Identity::gen().unwrap();
    let bad_sig = AliceSig::new([0u8; 64]);
    assert!(verify32(&i.id(), &[0u8; 32], &bad_sig).is_err());
}

#[test]
fn sign_empty_message() {
    let i = Identity::gen().unwrap();
    let sig = i.sign(b"");
    assert!(ok(&i.id(), b"", &sig));
}

#[test]
fn sign_large_message() {
    let i = Identity::gen().unwrap();
    let msg = [0xAA; 256];
    let sig = i.sign(&msg);
    assert!(ok(&i.id(), &msg, &sig));
}

#[test]
fn two_identities_different_ids() {
    let a = Identity::gen().unwrap();
    let b = Identity::gen().unwrap();
    assert_ne!(a.id(), b.id());
}

#[test]
fn did_length_84() {
    let i = Identity::gen().unwrap();
    let d = i.id().to_did_bytes();
    assert_eq!(d.len(), 84);
}

#[test]
fn did_prefix_exact() {
    let i = Identity::gen().unwrap();
    let mut buf = [0u8; 84];
    let did = i.id().write_did(&mut buf);
    assert_eq!(&did[..20], "alice://did:ed25519:");
    assert_eq!(did.len(), 84);
}

#[test]
fn hello_version() {
    let i = Identity::gen().unwrap();
    let h = hello(&i);
    assert_eq!(h.v, 1);
    assert_eq!(h.id, i.id());
}

#[test]
fn check_wrong_response_fails() {
    let i = Identity::gen().unwrap();
    let other = Identity::gen().unwrap();
    let p = make_challenge(i.id()).unwrap();
    let r = respond(&other, &Challenge { n: p.c });
    assert!(matches!(check(&p, &r), AuthResult::Fail));
}

#[test]
fn auth_error_repr() {
    assert_eq!(AuthError::E1 as u8, 1);
    assert_eq!(AuthError::E2 as u8, 2);
    assert_eq!(AuthError::E3 as u8, 3);
    assert_eq!(AuthError::E4 as u8, 4);
    assert_eq!(AuthError::E5 as u8, 5);
}

#[test]
fn auth_error_eq() {
    assert_eq!(AuthError::E1, AuthError::E1);
    assert_ne!(AuthError::E1, AuthError::E2);
}

#[test]
fn pending_layout() {
    assert_eq!(core::mem::size_of::<Pending>(), 64);
}

#[test]
fn challenge_is_random() {
    let c1 = challenge().unwrap();
    let c2 = challenge().unwrap();
    assert_ne!(c1, c2);
}

// --- Key Rotation tests (require std for RotatingIdentity) ---

#[cfg(feature = "std")]
mod rotation_tests {
    use super::super::*;

    #[test]
    fn rotating_identity_gen() {
        let ri = RotatingIdentity::gen().unwrap();
        assert!(!ri.has_previous());
        assert_eq!(ri.id().0.len(), 32);
    }

    #[test]
    fn rotating_identity_rotate() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let old_id = ri.id();
        let new_id = ri.rotate(1000).unwrap();
        assert_ne!(old_id, new_id);
        assert!(ri.has_previous());
        let (prev_id, ts) = ri.previous_id().unwrap();
        assert_eq!(prev_id, old_id);
        assert_eq!(ts, 1000);
    }

    #[test]
    fn rotating_identity_verify_any_current() {
        let ri = RotatingIdentity::gen().unwrap();
        let sig = ri.sign(b"msg");
        assert!(ri.verify_any(&ri.id(), b"msg", &sig));
    }

    #[test]
    fn rotating_identity_verify_any_previous() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let old_id = ri.id();
        let sig = ri.sign(b"msg");
        ri.rotate(1000).unwrap();
        // Old signature still verifiable via verify_any
        assert!(ri.verify_any(&old_id, b"msg", &sig));
    }

    #[test]
    fn rotating_identity_clear_previous() {
        let mut ri = RotatingIdentity::gen().unwrap();
        ri.rotate(1000).unwrap();
        assert!(ri.has_previous());
        ri.clear_previous();
        assert!(!ri.has_previous());
    }

    #[test]
    fn rotating_identity_double_rotate() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let id1 = ri.id();
        ri.rotate(1000).unwrap();
        let id2 = ri.id();
        ri.rotate(2000).unwrap();
        let id3 = ri.id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        // Most recent previous key
        let (prev, ts) = ri.previous_id().unwrap();
        assert_eq!(prev, id2);
        assert_eq!(ts, 2000);
        // Both previous generations retained (max_generations=2)
        assert_eq!(ri.generation_count(), 2);
    }

    #[test]
    fn rotating_identity_n_generations() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let id0 = ri.id();
        ri.rotate(1000).unwrap();
        let id1 = ri.id();
        ri.rotate(2000).unwrap();
        let id2 = ri.id();
        ri.rotate(3000).unwrap();
        // max_generations=2: oldest (id0) should be evicted
        assert_eq!(ri.generation_count(), 2);
        let prev_ids = ri.previous_ids();
        assert_eq!(prev_ids[0].0, id1);
        assert_eq!(prev_ids[1].0, id2);
        // Evicted id0 not in previous_ids
        assert!(prev_ids.iter().all(|(id, _)| *id != id0));
    }

    #[test]
    fn rotating_identity_custom_max_generations() {
        let base = Identity::gen().unwrap();
        let mut ri = RotatingIdentity::with_max_generations(base, 4);
        for i in 0..6 {
            ri.rotate(i * 1000).unwrap();
        }
        // Should retain at most 4 previous generations
        assert_eq!(ri.generation_count(), 4);
    }
} // mod rotation_tests

// --- Challenge TTL tests ---

#[test]
fn timed_challenge_valid() {
    let i = Identity::gen().unwrap();
    let tp = make_timed_challenge(i.id(), 1000).unwrap();
    let r = respond(&i, &Challenge { n: tp.c });
    assert!(matches!(
        check_timed(&tp, &r, 2000, CHALLENGE_TTL_MS),
        AuthResult::Ok(_)
    ));
}

#[test]
fn timed_challenge_expired() {
    let i = Identity::gen().unwrap();
    let tp = make_timed_challenge(i.id(), 1000).unwrap();
    let r = respond(&i, &Challenge { n: tp.c });
    // 31 seconds later → expired (TTL = 30s)
    assert!(matches!(
        check_timed(&tp, &r, 32_000, CHALLENGE_TTL_MS),
        AuthResult::Fail
    ));
}

#[test]
fn timed_challenge_at_boundary() {
    let i = Identity::gen().unwrap();
    let tp = make_timed_challenge(i.id(), 0).unwrap();
    let r = respond(&i, &Challenge { n: tp.c });
    // Exactly at TTL boundary → still valid (not >)
    assert!(matches!(
        check_timed(&tp, &r, CHALLENGE_TTL_MS, CHALLENGE_TTL_MS),
        AuthResult::Ok(_)
    ));
    // 1ms over → expired
    assert!(matches!(
        check_timed(&tp, &r, CHALLENGE_TTL_MS + 1, CHALLENGE_TTL_MS),
        AuthResult::Fail
    ));
}

#[test]
fn timed_challenge_wrong_signer() {
    let i = Identity::gen().unwrap();
    let other = Identity::gen().unwrap();
    let tp = make_timed_challenge(i.id(), 1000).unwrap();
    let r = respond(&other, &Challenge { n: tp.c });
    assert!(matches!(
        check_timed(&tp, &r, 1500, CHALLENGE_TTL_MS),
        AuthResult::Fail
    ));
}

// --- Trust Chain / Endorsement tests ---

#[test]
fn endorsement_basic() {
    let root = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let e = endorse(&root, &user.id(), 1000, 60_000);
    assert!(verify_endorsement(&e, 2000));
    assert_eq!(e.endorser, root.id());
    assert_eq!(e.endorsed, user.id());
    assert_eq!(e.issued_ms, 1000);
    assert_eq!(e.expires_ms, 61_000);
}

#[test]
fn endorsement_tampered() {
    let root = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let mut e = endorse(&root, &user.id(), 1000, 60_000);
    // Tamper with the endorsed identity
    e.endorsed = AliceId::new([0xFF; 32]);
    assert!(!verify_endorsement(&e, 2000));
}

#[test]
fn endorsement_wrong_signer() {
    let root = Identity::gen().unwrap();
    let fake = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let mut e = endorse(&root, &user.id(), 1000, 60_000);
    e.endorser = fake.id();
    assert!(!verify_endorsement(&e, 2000));
}

#[test]
fn endorsement_expired() {
    let root = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let e = endorse(&root, &user.id(), 1000, 5000);
    // Valid before expiry
    assert!(verify_endorsement(&e, 5000));
    // Expired after expiry
    assert!(!verify_endorsement(&e, 6001));
}

#[test]
fn verify_chain_single() {
    let root = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let e = endorse(&root, &user.id(), 1000, 60_000);
    assert!(verify_chain(&[e], &root.id(), 2000));
}

#[test]
fn verify_chain_multi_hop() {
    let root = Identity::gen().unwrap();
    let intermediate = Identity::gen().unwrap();
    let leaf = Identity::gen().unwrap();
    let e1 = endorse(&root, &intermediate.id(), 1000, 60_000);
    let e2 = endorse(&intermediate, &leaf.id(), 2000, 60_000);
    assert!(verify_chain(&[e1, e2], &root.id(), 3000));
}

#[test]
fn verify_chain_wrong_root() {
    let root = Identity::gen().unwrap();
    let fake_root = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    let e = endorse(&root, &user.id(), 1000, 60_000);
    assert!(!verify_chain(&[e], &fake_root.id(), 2000));
}

#[test]
fn verify_chain_broken_link() {
    let root = Identity::gen().unwrap();
    let a = Identity::gen().unwrap();
    let b = Identity::gen().unwrap();
    let unrelated = Identity::gen().unwrap();
    let e1 = endorse(&root, &a.id(), 1000, 60_000);
    let e2 = endorse(&unrelated, &b.id(), 2000, 60_000);
    assert!(!verify_chain(&[e1, e2], &root.id(), 3000));
}

#[test]
fn verify_chain_empty() {
    let root = Identity::gen().unwrap();
    assert!(!verify_chain(&[], &root.id(), 1000));
}

#[test]
fn verify_chain_expired_link() {
    let root = Identity::gen().unwrap();
    let intermediate = Identity::gen().unwrap();
    let leaf = Identity::gen().unwrap();
    let e1 = endorse(&root, &intermediate.id(), 1000, 5000); // expires at 6000
    let e2 = endorse(&intermediate, &leaf.id(), 2000, 60_000);
    // At 3000: both valid
    assert!(verify_chain(&[e1, e2], &root.id(), 3000));
    // At 7000: e1 expired → chain fails
    assert!(!verify_chain(&[e1, e2], &root.id(), 7000));
}

// --- Constant-time timing tests (require std for Vec/Instant) ---

#[cfg(feature = "std")]
mod timing_tests {
    use super::super::*;

    #[test]
    fn verify_timing_consistency() {
        let i = Identity::gen().unwrap();
        let msg = [0xAA; 64];
        let valid_sig = i.sign(&msg);
        let invalid_sig = AliceSig::new([0u8; 64]);

        // Run multiple rounds to check variance is bounded
        let rounds = 100;
        let mut valid_times = Vec::with_capacity(rounds);
        let mut invalid_times = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = verify(&i.id(), &msg, &valid_sig);
            valid_times.push(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = verify(&i.id(), &msg, &invalid_sig);
            invalid_times.push(start.elapsed().as_nanos());
        }

        let valid_avg: u128 = valid_times.iter().sum::<u128>() / rounds as u128;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / rounds as u128;

        // The ratio between valid and invalid verification times should be
        // within 10x of each other (loose bound to avoid flaky CI).
        // A non-constant-time implementation would show much larger divergence.
        let ratio = if valid_avg > invalid_avg {
            valid_avg / invalid_avg.max(1)
        } else {
            invalid_avg / valid_avg.max(1)
        };
        assert!(
            ratio < 10,
            "timing ratio {ratio} too large (valid_avg={valid_avg}ns, invalid_avg={invalid_avg}ns)"
        );
    }

    #[test]
    fn ct_eq_16_timing_consistency() {
        let a = [0xAAu8; 16];
        let b_same = [0xAAu8; 16];
        let mut b_diff = [0xAAu8; 16];
        b_diff[0] = 0xBB;
        let mut b_last = [0xAAu8; 16];
        b_last[15] = 0xBB;

        let rounds = 200;
        let mut diff_first_times = Vec::with_capacity(rounds);
        let mut diff_last_times = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_same);
            std::hint::black_box(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_diff);
            diff_first_times.push(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_last);
            diff_last_times.push(start.elapsed().as_nanos());
        }

        // Difference at first byte vs last byte should produce similar timing
        let df_avg: u128 = diff_first_times.iter().sum::<u128>() / rounds as u128;
        let dl_avg: u128 = diff_last_times.iter().sum::<u128>() / rounds as u128;
        let ratio = if df_avg > dl_avg {
            df_avg / dl_avg.max(1)
        } else {
            dl_avg / df_avg.max(1)
        };
        assert!(
            ratio < 10,
            "timing ratio {ratio} too large (first={df_avg}ns, last={dl_avg}ns)"
        );
    }
} // mod timing_tests

#[test]
fn ct_eq_correctness() {
    assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
    assert!(!ct_eq(&[], &[1]));
    assert!(ct_eq(&[], &[]));
}

#[test]
fn ct_eq_n_fixed_size() {
    assert!(ct_eq_n(&[1u8, 2, 3, 4], &[1, 2, 3, 4]));
    assert!(!ct_eq_n(&[1u8, 2, 3, 4], &[1, 2, 3, 5]));
    assert!(ct_eq_n(&[0xAAu8; 32], &[0xAAu8; 32]));
    assert!(!ct_eq_n(&[0xAAu8; 32], &[0xBBu8; 32]));
}

// --- Social Recovery tests ---

#[test]
fn recovery_approval_basic() {
    let guardian = Identity::gen().unwrap();
    let old = Identity::gen().unwrap();
    let new = Identity::gen().unwrap();
    let approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
    assert!(verify_recovery_approval(&approval));
    assert_eq!(approval.guardian, guardian.id());
    assert_eq!(approval.old_id, old.id());
    assert_eq!(approval.new_id, new.id());
}

#[test]
fn recovery_approval_tampered_fails() {
    let guardian = Identity::gen().unwrap();
    let old = Identity::gen().unwrap();
    let new = Identity::gen().unwrap();
    let mut approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
    // Tamper with new_id
    approval.new_id = AliceId::new([0xFF; 32]);
    assert!(!verify_recovery_approval(&approval));
}

#[cfg(feature = "std")]
mod recovery_validate_tests {
    use super::super::*;

    #[test]
    fn validate_recovery_threshold_met() {
        let g1 = Identity::gen().unwrap();
        let g2 = Identity::gen().unwrap();
        let g3 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id(), g2.id(), g3.id()],
            threshold: 2,
        };

        let a1 = approve_recovery(&g1, &old.id(), &new.id(), 1000);
        let a2 = approve_recovery(&g2, &old.id(), &new.id(), 2000);

        assert!(validate_recovery(&config, &old.id(), &new.id(), &[a1, a2],));
    }

    #[test]
    fn validate_recovery_threshold_not_met() {
        let g1 = Identity::gen().unwrap();
        let g2 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id(), g2.id()],
            threshold: 2,
        };

        let a1 = approve_recovery(&g1, &old.id(), &new.id(), 1000);
        // Only 1 approval, need 2
        assert!(!validate_recovery(&config, &old.id(), &new.id(), &[a1],));
    }

    #[test]
    fn validate_recovery_unregistered_guardian() {
        let g1 = Identity::gen().unwrap();
        let stranger = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id()],
            threshold: 1,
        };

        // Stranger's approval should not count
        let a = approve_recovery(&stranger, &old.id(), &new.id(), 1000);
        assert!(!validate_recovery(&config, &old.id(), &new.id(), &[a],));
    }

    #[test]
    fn validate_recovery_empty_config() {
        let config = RecoveryConfig {
            guardians: vec![],
            threshold: 0,
        };
        assert!(!validate_recovery(
            &config,
            &AliceId::new([0; 32]),
            &AliceId::new([1; 32]),
            &[],
        ));
    }

    #[test]
    fn validate_recovery_duplicate_guardian_rejected() {
        let g1 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new_id = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id()],
            threshold: 2,
        };

        // Same guardian approves twice — should count as 1, not 2
        let a1 = approve_recovery(&g1, &old.id(), &new_id.id(), 1000);
        let a2 = approve_recovery(&g1, &old.id(), &new_id.id(), 2000);
        assert!(!validate_recovery(
            &config,
            &old.id(),
            &new_id.id(),
            &[a1, a2],
        ));
    }
} // mod recovery_validate_tests
