//! FFI for Crypto.

#![allow(clippy::missing_safety_doc)]

use crate::types::*;

extern crate std;
use std::boxed::Box;

#[inline(always)]
const unsafe fn r32(p: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
    a
}

#[cold]
#[inline(never)]
const fn null_ptr() {}

/// Derive an HD child identity. Returns a new Handle or null on failure.
///
/// # Safety
///
/// - `h` must be a valid `Handle` pointer (the parent).
#[no_mangle]
pub unsafe extern "C" fn aa_derive_child(
    h: *const super::ffi::Handle,
    index: u32,
) -> *mut super::ffi::Handle {
    if h.is_null() {
        null_ptr();
        return core::ptr::null_mut();
    }
    let child = crate::crypto_bridge::derive_child(&(*h).0, index);
    Box::into_raw(Box::new(super::ffi::Handle(child)))
}

/// Derive a session key from two IDs and a shared secret. Writes 32 bytes to `out`.
///
/// # Safety
///
/// - `id_a` and `id_b` must each point to 32 readable bytes.
/// - `secret` must point to `secret_len` readable bytes.
/// - `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_derive_session_key(
    id_a: *const u8,
    id_b: *const u8,
    secret: *const u8,
    secret_len: usize,
    out: *mut u8,
) {
    if id_a.is_null() || id_b.is_null() || secret.is_null() || out.is_null() {
        null_ptr();
        return;
    }
    const MAX_LEN: usize = 64 * 1024 * 1024;
    if secret_len > MAX_LEN {
        return;
    }
    let a = AliceId(r32(id_a));
    let b = AliceId(r32(id_b));
    let s = core::slice::from_raw_parts(secret, secret_len);
    let key = crate::crypto_bridge::derive_session_key(&a, &b, s);
    core::ptr::copy_nonoverlapping(key.as_bytes().as_ptr(), out, 32);
}
