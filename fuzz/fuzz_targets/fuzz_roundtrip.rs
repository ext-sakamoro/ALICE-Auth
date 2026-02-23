#![no_main]
use libfuzzer_sys::fuzz_target;
use alice_auth::{Identity, ok, verify};

// Fuzz sign-then-verify roundtrip with random seed + message.
// Valid signatures must always verify; no panics allowed.
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let msg = &data[32..];

    let id = Identity::from_seed(&seed);
    let sig = id.sign(msg);

    // Roundtrip must always succeed
    assert!(ok(&id.id(), msg, &sig), "roundtrip verify failed");
    assert!(verify(&id.id(), msg, &sig).is_ok(), "roundtrip verify returned Err");
});
