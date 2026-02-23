#![no_main]
use libfuzzer_sys::fuzz_target;
use alice_auth::{Identity, hello, make_challenge, respond, check, AuthResult, Challenge};

// Fuzz the full challenge-response protocol flow.
// Correct flow must always succeed; wrong signer must always fail.
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut seed_a = [0u8; 32];
    seed_a.copy_from_slice(&data[..32]);
    let mut seed_b = [0u8; 32];
    seed_b.copy_from_slice(&data[32..64]);

    let alice = Identity::from_seed(&seed_a);
    let bob = Identity::from_seed(&seed_b);

    // Correct flow: alice proves her identity
    let h = hello(&alice);
    if let Ok(pending) = make_challenge(h.id) {
        let resp = respond(&alice, &Challenge { n: pending.c });
        assert!(
            matches!(check(&pending, &resp), AuthResult::Ok(_)),
            "correct signer must pass"
        );

        // Wrong signer: bob tries to impersonate alice
        let bad_resp = respond(&bob, &Challenge { n: pending.c });
        // Only fail if seeds are actually different (same seed = same identity)
        if seed_a != seed_b {
            assert!(
                matches!(check(&pending, &bad_resp), AuthResult::Fail),
                "wrong signer must fail"
            );
        }
    }
});
