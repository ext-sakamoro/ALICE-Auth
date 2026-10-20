//! FFI for the player module (player id, key chain, grants, revocations).
//!
//! Every function returns `AA_PLAYER_OK` (0) or the negative code of
//! [`GrantError::code`](crate::GrantError::code), sets `aa_last_error` on a refusal, and
//! writes its outputs only on success. A null argument is [`GrantError::Null`](crate::GrantError::Null).
//! Wire forms are passed as byte buffers of the lengths below.

#![allow(clippy::missing_safety_doc)]

use super::ffi::{guard, Handle};
use crate::player::*;
use std::boxed::Box;

/// Success.
pub const AA_PLAYER_OK: i32 = 0;
/// Length of a rotation link.
pub const AA_ROTATION_LINK_LEN: usize = ROTATION_LINK_LEN;
/// Length of a grant.
pub const AA_GRANT_LEN: usize = GRANT_LEN;
/// Length of a revocation.
pub const AA_REVOCATION_LEN: usize = REVOCATION_LEN;

/// A revocation set owned by the host.
pub struct RevSetHandle(RevocationSet);

/// A signing identity restored from its 32-byte seed (null on a null seed).
///
/// The seed is the secret key: whoever has it signs as this identity. It must come from a
/// secure random source (or from where the host stored one) and be kept like a key. The
/// handle's copy is overwritten when [`aa_free`](super::ffi::aa_free) drops it (the
/// identity replaces its key on drop and `ed25519-dalek` zeroizes the key it drops); the
/// caller's own buffer is the caller's to clear. Reading freed memory is undefined, so no
/// test observes the overwrite.
///
/// # Safety
/// `seed` must point to 32 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn aa_from_seed(_seed: *const u8) -> *mut Handle {
    guard::ffi_guard(core::ptr::null_mut(), || todo!("aa_from_seed"))
}

/// Write the player id of the first key `genesis` (32 bytes) into `out` (32 bytes).
///
/// # Safety
/// `genesis` must point to 32 readable bytes and `out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_player_id_from_genesis(_genesis: *const u8, _out: *mut u8) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        todo!("aa_player_id_from_genesis")
    })
}

/// Sign a rotation link from `old`'s key to `new_key` and write it into `out`
/// (`AA_ROTATION_LINK_LEN` bytes).
///
/// # Safety
/// `old` must be a valid handle; `player` and `new_key` must point to 32 readable bytes;
/// `out` to `AA_ROTATION_LINK_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_rotation_link_issue(
    _old: *const Handle,
    _player: *const u8,
    _seq: u32,
    _new_key: *const u8,
    _issued_ms: u64,
    _out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_rotation_link_issue"))
}

/// Check `n_links` rotation links (contiguous, `AA_ROTATION_LINK_LEN` bytes each) from the
/// first key `genesis`, and write the player id, the current key and the time it became
/// current.
///
/// # Safety
/// `genesis` must point to 32 readable bytes; `links` to `n_links * AA_ROTATION_LINK_LEN`
/// readable bytes (it may be null when `n_links` is 0); `out_player` and `out_key` to 32
/// writable bytes; `out_since_ms` to a writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn aa_player_chain_resolve(
    _genesis: *const u8,
    _links: *const u8,
    _n_links: usize,
    _out_player: *mut u8,
    _out_key: *mut u8,
    _out_since_ms: *mut u64,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_player_chain_resolve"))
}

/// Sign a grant from `game` and write it into `out` (`AA_GRANT_LEN` bytes).
///
/// # Safety
/// `game` must be a valid handle; `player` and `player_key` must point to 32 readable
/// bytes, `nonce` to 16; `out` to `AA_GRANT_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_grant_issue(
    _game: *const Handle,
    _player: *const u8,
    _player_key: *const u8,
    _scope: u64,
    _now_ms: u64,
    _ttl_ms: u64,
    _nonce: *const u8,
    _out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_grant_issue"))
}

/// Check a grant (`grant_len` bytes) for `expected_game` at `now_ms`, against the chain end
/// (`head_player`, `head_key`, `head_since_ms`) and the revocations in `revoked`; on success
/// write the player, the scope and the expiry.
///
/// # Safety
/// `grant` must point to `grant_len` readable bytes; `expected_game`, `head_player` and
/// `head_key` to 32; `revoked` must be a valid set; `out_player` to 32 writable bytes;
/// `out_scope` and `out_expires_ms` to writable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn aa_grant_verify(
    _grant: *const u8,
    _grant_len: usize,
    _expected_game: *const u8,
    _head_player: *const u8,
    _head_key: *const u8,
    _head_since_ms: u64,
    _now_ms: u64,
    _revoked: *const RevSetHandle,
    _out_player: *mut u8,
    _out_scope: *mut u64,
    _out_expires_ms: *mut u64,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_grant_verify"))
}

/// Sign the revocation of `grant` (`grant_len` bytes) by `game` and write it into `out`
/// (`AA_REVOCATION_LEN` bytes).
///
/// # Safety
/// `game` must be a valid handle; `grant` must point to `grant_len` readable bytes; `out`
/// to `AA_REVOCATION_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revocation_issue(
    _game: *const Handle,
    _grant: *const u8,
    _grant_len: usize,
    _revoked_ms: u64,
    _out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_revocation_issue"))
}

/// A revocation set holding at most `capacity` revocations (null when `capacity` is 0).
#[no_mangle]
pub extern "C" fn aa_revset_new(_capacity: usize) -> *mut RevSetHandle {
    guard::ffi_guard(core::ptr::null_mut(), || todo!("aa_revset_new"))
}

/// Add a revocation (`rev_len` bytes) after checking its signature.
///
/// # Safety
/// `set` must be a valid set; `rev` must point to `rev_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_add(
    _set: *mut RevSetHandle,
    _rev: *const u8,
    _rev_len: usize,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || todo!("aa_revset_add"))
}

/// 1 when the grant `nonce` (16 bytes) of `game` (32 bytes) is revoked, else 0. A null
/// argument reads as revoked.
///
/// # Safety
/// `set` must be a valid set or null; `game` must point to 32 readable bytes, `nonce` to 16.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_contains(
    _set: *const RevSetHandle,
    _game: *const u8,
    _nonce: *const u8,
) -> i32 {
    guard::ffi_guard(1, || todo!("aa_revset_contains"))
}

/// Drop the revocations whose grant has expired at `now_ms`; the number dropped, or -1 for
/// a null set.
///
/// # Safety
/// `set` must be a valid set or null.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_purge(_set: *mut RevSetHandle, _now_ms: u64) -> i64 {
    guard::ffi_guard(-1, || todo!("aa_revset_purge"))
}

/// The number of revocations held, or -1 for a null set.
///
/// # Safety
/// `set` must be a valid set or null.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_len(_set: *const RevSetHandle) -> i64 {
    guard::ffi_guard(-1, || todo!("aa_revset_len"))
}

/// Free a revocation set (null is ignored).
///
/// # Safety
/// `set` must be null or a set returned by `aa_revset_new`, freed once.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_free(set: *mut RevSetHandle) {
    guard::ffi_guard((), || {
        if !set.is_null() {
            drop(Box::from_raw(set));
        }
    });
}
