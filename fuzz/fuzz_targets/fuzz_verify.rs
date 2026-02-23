#![no_main]
use libfuzzer_sys::fuzz_target;
use alice_auth::{AliceId, AliceSig, ok, verify};

// Fuzz Ed25519 verify with random (pk, msg, sig) — must never panic.
fuzz_target!(|data: &[u8]| {
    // Need at least 32 (pk) + 64 (sig) = 96 bytes
    if data.len() < 96 {
        return;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[..32]);
    let sig_bytes = &data[32..96];
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes);
    let msg = &data[96..];

    let id = AliceId::new(pk);
    let s = AliceSig::new(sig);

    // Must not panic — failure returns Err/false
    let _ = verify(&id, msg, &s);
    let _ = ok(&id, msg, &s);
});
