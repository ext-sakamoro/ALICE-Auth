//! FFI for NIZK.

#![allow(clippy::missing_safety_doc)]

use crate::types::*;

#[inline(always)]
const unsafe fn r32(p: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
    a
}

#[cold]
#[inline(never)]
const fn null_ptr() {}

/// Generate a Schnorr NIZK proof. Writes 64 bytes (R || s) to `out`.
/// Returns 1 on success, 0 on failure.
///
/// # Safety
///
/// - `h` must be a valid `Handle` pointer (the prover).
/// - `m` must point to `ml` readable bytes.
/// - `out` must point to at least 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_nizk_prove(
    h: *const super::ffi::Handle,
    m: *const u8,
    ml: usize,
    out: *mut u8,
) -> i32 {
    if h.is_null() || m.is_null() || out.is_null() {
        null_ptr();
        return 0;
    }
    const MAX_MSG_LEN: usize = 64 * 1024 * 1024;
    if ml > MAX_MSG_LEN {
        return 0;
    }
    let msg = core::slice::from_raw_parts(m, ml);
    match crate::nizk::prove(&(*h).0, msg) {
        Ok(proof) => {
            let bytes = proof.to_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 64);
            1
        }
        Err(_) => 0,
    }
}

/// Verify a Schnorr NIZK proof. Returns 1 if valid, 0 otherwise.
///
/// # Safety
///
/// - `pk` must point to 32 readable bytes (public key).
/// - `m` must point to `ml` readable bytes.
/// - `proof` must point to 64 readable bytes (R || s).
#[no_mangle]
pub unsafe extern "C" fn aa_nizk_verify(
    pk: *const u8,
    m: *const u8,
    ml: usize,
    proof: *const u8,
) -> i32 {
    if pk.is_null() || m.is_null() || proof.is_null() {
        null_ptr();
        return 0;
    }
    const MAX_MSG_LEN: usize = 64 * 1024 * 1024;
    if ml > MAX_MSG_LEN {
        return 0;
    }
    let id = AliceId(r32(pk));
    let msg = core::slice::from_raw_parts(m, ml);
    let mut proof_bytes = [0u8; 64];
    core::ptr::copy_nonoverlapping(proof, proof_bytes.as_mut_ptr(), 64);
    let p = crate::nizk::SchnorrProof::from_bytes(&proof_bytes);
    crate::nizk::verify_proof(&id, msg, &p) as i32
}
