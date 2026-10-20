//! `RotatingIdentity::verify_any(id, m, s)` accepts a signature only under one of this
//! identity's own keys: `id` must be the current key or a retained previous one, and `s`
//! must be that key's valid signature of `m`. Another key, an evicted generation and a
//! cleared one are refused, and a signature is not accepted under a different generation
//! than the one that made it.

#![cfg(feature = "std")]

use alice_auth::{Identity, RotatingIdentity};

#[test]
fn another_keys_valid_signature_is_refused() {
    let r = RotatingIdentity::with_max_generations(Identity::from_seed(&[1u8; 32]), 3);
    let stranger = Identity::from_seed(&[9u8; 32]);
    let s = stranger.sign(b"m").expect("sign");
    assert!(
        alice_auth::ok(&stranger.id(), b"m", &s),
        "the signature itself is valid"
    );
    assert!(!r.verify_any(&stranger.id(), b"m", &s));
}

#[test]
fn the_current_and_each_retained_previous_key_are_accepted() {
    let first = Identity::from_seed(&[2u8; 32]);
    let first_id = first.id();
    let first_sig = first.sign(b"m").expect("sign");
    let mut r = RotatingIdentity::with_max_generations(first, 3);
    assert!(
        r.verify_any(&first_id, b"m", &first_sig),
        "before any rotation"
    );
    let mut ids = vec![(first_id, first_sig)];
    for t in 0..3 {
        let sig = r.sign(b"m").expect("sign");
        let id = r.id();
        assert!(r.verify_any(&id, b"m", &sig), "current at step {t}");
        r.rotate(t + 1).expect("rng");
        ids.push((id, sig));
    }
    // the last three generations are retained; the very first was the oldest
    for (id, sig) in &ids[1..] {
        assert!(r.verify_any(id, b"m", sig));
    }
}

#[test]
fn an_evicted_generation_is_refused() {
    let first = Identity::from_seed(&[3u8; 32]);
    let first_id = first.id();
    let first_sig = first.sign(b"m").expect("sign");
    let mut r = RotatingIdentity::with_max_generations(first, 1);
    r.rotate(1).expect("rng");
    assert!(
        r.verify_any(&first_id, b"m", &first_sig),
        "retained after one rotation"
    );
    r.rotate(2).expect("rng");
    assert!(
        !r.verify_any(&first_id, b"m", &first_sig),
        "evicted after the second"
    );
}

#[test]
fn a_cleared_previous_key_is_refused() {
    let first = Identity::from_seed(&[4u8; 32]);
    let first_id = first.id();
    let first_sig = first.sign(b"m").expect("sign");
    let mut r = RotatingIdentity::with_max_generations(first, 3);
    r.rotate(1).expect("rng");
    r.clear_previous();
    assert!(!r.verify_any(&first_id, b"m", &first_sig));
}

#[test]
fn a_signature_is_not_accepted_under_another_generation() {
    let first = Identity::from_seed(&[5u8; 32]);
    let first_id = first.id();
    let first_sig = first.sign(b"m").expect("sign");
    let mut r = RotatingIdentity::with_max_generations(first, 3);
    r.rotate(1).expect("rng");
    // the previous key's signature under the current id
    assert!(!r.verify_any(&r.id(), b"m", &first_sig));
    // and the current key's signature under the previous id
    let current_sig = r.sign(b"m").expect("sign");
    assert!(!r.verify_any(&first_id, b"m", &current_sig));
    assert!(r.verify_any(&first_id, b"m", &first_sig));
}

#[cfg(feature = "ffi")]
#[test]
fn the_c_abi_refuses_another_key() {
    use alice_auth::{aa_rotating_free, aa_rotating_id, aa_rotating_new, aa_rotating_verify};
    let h = aa_rotating_new();
    assert!(!h.is_null());
    let stranger = Identity::from_seed(&[9u8; 32]);
    let s = stranger.sign(b"m").expect("sign");
    let pk = stranger.id().0;
    // SAFETY: live arrays of the lengths the functions read; h from aa_rotating_new
    assert_eq!(
        unsafe { aa_rotating_verify(h, pk.as_ptr(), b"m".as_ptr(), 1, s.0.as_ptr()) },
        0
    );
    let mut cur = [0u8; 32];
    unsafe { aa_rotating_id(h, cur.as_mut_ptr()) };
    assert_eq!(
        unsafe { aa_rotating_verify(h, cur.as_ptr(), b"m".as_ptr(), 1, s.0.as_ptr()) },
        0
    );
    unsafe { aa_rotating_free(h) };
}
