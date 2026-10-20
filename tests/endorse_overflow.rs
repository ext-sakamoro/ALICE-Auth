//! `endorse` refuses a validity window that does not fit in u64 milliseconds instead of
//! wrapping `now_ms + ttl_ms` (release) or panicking (debug), and the error codes keep
//! their numbers.

use alice_auth::{endorse, verify_endorsement, AuthError, Identity};

#[test]
fn a_window_past_u64_max_is_refused() {
    let root = Identity::from_seed(&[1u8; 32]);
    let user = Identity::from_seed(&[2u8; 32]);
    let r = std::panic::catch_unwind(|| endorse(&root, &user.id(), u64::MAX - 1, 2));
    assert_eq!(r.expect("no panic").err(), Some(AuthError::E6));
    assert_eq!(
        endorse(&root, &user.id(), 1, u64::MAX).err(),
        Some(AuthError::E6)
    );
}

#[test]
fn a_window_ending_at_u64_max_is_accepted_and_verifies() {
    let root = Identity::from_seed(&[1u8; 32]);
    let user = Identity::from_seed(&[2u8; 32]);
    let e = endorse(&root, &user.id(), u64::MAX - 10, 10).expect("fits");
    assert_eq!(e.expires_ms, u64::MAX);
    assert!(verify_endorsement(&e, u64::MAX - 10));
    assert!(verify_endorsement(&e, u64::MAX));
}

/// `ttl_ms = 0` gives `expires_ms == now_ms`; `verify_endorsement` refuses only when
/// `now_ms > expires_ms`, so the endorsement verifies at that instant and not after
#[test]
fn a_zero_ttl_ends_at_now() {
    let root = Identity::from_seed(&[1u8; 32]);
    let user = Identity::from_seed(&[2u8; 32]);
    let e = endorse(&root, &user.id(), 5_000, 0).expect("fits");
    assert_eq!((e.issued_ms, e.expires_ms), (5_000, 5_000));
    assert!(verify_endorsement(&e, 5_000));
    assert!(!verify_endorsement(&e, 5_001));
}

/// The error codes are part of the C ABI and of stored logs: their numbers do not move
#[test]
fn the_error_codes_keep_their_numbers() {
    let codes = [
        (AuthError::E1, 1u8),
        (AuthError::E2, 2),
        (AuthError::E3, 3),
        (AuthError::E4, 4),
        (AuthError::E5, 5),
        (AuthError::E6, 6),
    ];
    for (e, n) in codes {
        assert_eq!(e as u8, n);
        assert_eq!(e.to_string(), format!("E{n}"));
    }
}

#[cfg(feature = "ffi")]
#[test]
fn the_c_abi_reports_the_overflow_and_leaves_the_output_untouched() {
    use alice_auth::{aa_endorse, aa_free, aa_new, AA_ENDORSE_ERR_OVERFLOW, AA_ENDORSE_OK};
    let h = aa_new();
    assert!(!h.is_null());
    let target = Identity::from_seed(&[2u8; 32]).id().0;
    let mut out = [0xa5u8; 176];
    // SAFETY: h from aa_new, target 32 bytes, out 176 bytes
    let rc = unsafe { aa_endorse(h, target.as_ptr(), u64::MAX - 1, 2, out.as_mut_ptr()) };
    assert_eq!(rc, AA_ENDORSE_ERR_OVERFLOW);
    assert!(out.iter().all(|b| *b == 0xa5), "output written on error");
    let rc = unsafe { aa_endorse(h, target.as_ptr(), 1_000, 5_000, out.as_mut_ptr()) };
    assert_eq!(rc, AA_ENDORSE_OK);
    assert_eq!(u64::from_le_bytes(out[136..144].try_into().unwrap()), 6_000);
    unsafe { aa_free(h) };
}
