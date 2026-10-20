//! FFI for the player module (player id, key chain, grants, revocations).
//!
//! Every function returns `AA_PLAYER_OK` (0) or the negative code of
//! [`GrantError::code`], sets `aa_last_error` on a refusal, and writes its outputs only on
//! success. A null argument is [`GrantError::Null`]. A length argument is checked against
//! the wire length (or, for rotation links, against the largest slice that can exist)
//! before the buffer is read, so a wrong length is [`GrantError::Length`], never a read
//! past the buffer.
//! Wire forms are passed as byte buffers of the lengths below.

use super::ffi::{guard, Handle};
use crate::player::*;
use crate::types::AliceId;
use std::boxed::Box;
use std::format;
use std::vec::Vec;
use zeroize::Zeroize;

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
pub unsafe extern "C" fn aa_from_seed(seed: *const u8) -> *mut Handle {
    guard::ffi_guard(core::ptr::null_mut(), || {
        if seed.is_null() {
            guard::set_last_error("aa_from_seed: null seed");
            return core::ptr::null_mut();
        }
        let mut s = rd::<32>(seed);
        let h = Box::into_raw(Box::new(Handle(crate::Identity::from_seed(&s))));
        s.zeroize();
        h
    })
}

/// Write the player id of the first key `genesis` (32 bytes) into `out` (32 bytes).
///
/// # Safety
/// `genesis` must point to 32 readable bytes and `out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_player_id_from_genesis(genesis: *const u8, out: *mut u8) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_player_id_from_genesis";
        if genesis.is_null() || out.is_null() {
            return fail(F, GrantError::Null);
        }
        let id = PlayerId::from_genesis(&AliceId(rd(genesis)));
        wr(&id.0, out);
        AA_PLAYER_OK
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
    old: *const Handle,
    player: *const u8,
    seq: u32,
    new_key: *const u8,
    issued_ms: u64,
    out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_rotation_link_issue";
        if old.is_null() || player.is_null() || new_key.is_null() || out.is_null() {
            return fail(F, GrantError::Null);
        }
        match RotationLink::issue(
            &(*old).0,
            PlayerId(rd(player)),
            seq,
            AliceId(rd(new_key)),
            issued_ms,
        ) {
            Ok(l) => {
                wr(&l.to_bytes(), out);
                AA_PLAYER_OK
            }
            Err(e) => fail(F, e),
        }
    })
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
    genesis: *const u8,
    links: *const u8,
    n_links: usize,
    out_player: *mut u8,
    out_key: *mut u8,
    out_since_ms: *mut u64,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_player_chain_resolve";
        if genesis.is_null()
            || (links.is_null() && n_links != 0)
            || out_player.is_null()
            || out_key.is_null()
            || out_since_ms.is_null()
        {
            return fail(F, GrantError::Null);
        }
        // a slice longer than isize::MAX bytes cannot exist: refuse before building one
        let Some(total) = n_links
            .checked_mul(ROTATION_LINK_LEN)
            .filter(|&t| isize::try_from(t).is_ok())
        else {
            return fail(F, GrantError::Length);
        };
        let raw: &[u8] = if n_links == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(links, total)
        };
        let parsed: Result<Vec<RotationLink>, GrantError> = raw
            .as_chunks::<ROTATION_LINK_LEN>()
            .0
            .iter()
            .map(|c| RotationLink::from_bytes(c))
            .collect();
        match parsed.and_then(|l| resolve_chain(&AliceId(rd(genesis)), &l)) {
            Ok(h) => {
                wr(&h.player.0, out_player);
                wr(&h.key.0, out_key);
                *out_since_ms = h.since_ms;
                AA_PLAYER_OK
            }
            Err(e) => fail(F, e),
        }
    })
}

/// Sign a grant from `game` and write it into `out` (`AA_GRANT_LEN` bytes).
///
/// # Safety
/// `game` must be a valid handle; `player` and `player_key` must point to 32 readable
/// bytes, `nonce` to 16; `out` to `AA_GRANT_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_grant_issue(
    game: *const Handle,
    player: *const u8,
    player_key: *const u8,
    scope: u64,
    now_ms: u64,
    ttl_ms: u64,
    nonce: *const u8,
    out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_grant_issue";
        if game.is_null()
            || player.is_null()
            || player_key.is_null()
            || nonce.is_null()
            || out.is_null()
        {
            return fail(F, GrantError::Null);
        }
        match Grant::issue(
            &(*game).0,
            PlayerId(rd(player)),
            AliceId(rd(player_key)),
            scope,
            now_ms,
            ttl_ms,
            rd(nonce),
        ) {
            Ok(g) => {
                wr(&g.to_bytes(), out);
                AA_PLAYER_OK
            }
            Err(e) => fail(F, e),
        }
    })
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
    grant: *const u8,
    grant_len: usize,
    expected_game: *const u8,
    head_player: *const u8,
    head_key: *const u8,
    head_since_ms: u64,
    now_ms: u64,
    revoked: *const RevSetHandle,
    out_player: *mut u8,
    out_scope: *mut u64,
    out_expires_ms: *mut u64,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_grant_verify";
        if grant.is_null()
            || expected_game.is_null()
            || head_player.is_null()
            || head_key.is_null()
            || revoked.is_null()
            || out_player.is_null()
            || out_scope.is_null()
            || out_expires_ms.is_null()
        {
            return fail(F, GrantError::Null);
        }
        if grant_len != GRANT_LEN {
            return fail(F, GrantError::Length);
        }
        let head = ChainHead {
            player: PlayerId(rd(head_player)),
            key: AliceId(rd(head_key)),
            since_ms: head_since_ms,
        };
        let checked = Grant::from_bytes(core::slice::from_raw_parts(grant, grant_len))
            .and_then(|g| g.verify(&AliceId(rd(expected_game)), &head, now_ms, &(*revoked).0));
        match checked {
            Ok(v) => {
                wr(&v.player.0, out_player);
                *out_scope = v.scope;
                *out_expires_ms = v.expires_ms;
                AA_PLAYER_OK
            }
            Err(e) => fail(F, e),
        }
    })
}

/// Sign the revocation of `grant` (`grant_len` bytes) by `game` and write it into `out`
/// (`AA_REVOCATION_LEN` bytes).
///
/// # Safety
/// `game` must be a valid handle; `grant` must point to `grant_len` readable bytes; `out`
/// to `AA_REVOCATION_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revocation_issue(
    game: *const Handle,
    grant: *const u8,
    grant_len: usize,
    revoked_ms: u64,
    out: *mut u8,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_revocation_issue";
        if game.is_null() || grant.is_null() || out.is_null() {
            return fail(F, GrantError::Null);
        }
        if grant_len != GRANT_LEN {
            return fail(F, GrantError::Length);
        }
        let issued = Grant::from_bytes(core::slice::from_raw_parts(grant, grant_len))
            .and_then(|g| Revocation::issue(&(*game).0, &g, revoked_ms));
        match issued {
            Ok(r) => {
                wr(&r.to_bytes(), out);
                AA_PLAYER_OK
            }
            Err(e) => fail(F, e),
        }
    })
}

/// A revocation set holding at most `capacity` revocations (null when `capacity` is 0).
#[no_mangle]
pub extern "C" fn aa_revset_new(capacity: usize) -> *mut RevSetHandle {
    guard::ffi_guard(core::ptr::null_mut(), || {
        match RevocationSet::new(capacity) {
            Ok(set) => Box::into_raw(Box::new(RevSetHandle(set))),
            Err(e) => {
                guard::set_last_error(format!("aa_revset_new: {e}"));
                core::ptr::null_mut()
            }
        }
    })
}

/// Add a revocation (`rev_len` bytes) after checking its signature.
///
/// `GrantError::Full` (-12) means the revocation was **not** stored and the grant it names
/// is still accepted: treat it as an emergency, not a retry (move the entries into a larger
/// set, or stop accepting grants from that game until the revocation is held). Adding a
/// revocation for a game and nonce the set already holds succeeds and keeps the later
/// grant expiry, so a nonce the game reused is held until its last grant has expired.
///
/// # Safety
/// `set` must be a valid set; `rev` must point to `rev_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_add(
    set: *mut RevSetHandle,
    rev: *const u8,
    rev_len: usize,
) -> i32 {
    guard::ffi_guard(GrantError::Null.code(), || {
        const F: &str = "aa_revset_add";
        if set.is_null() || rev.is_null() {
            return fail(F, GrantError::Null);
        }
        if rev_len != REVOCATION_LEN {
            return fail(F, GrantError::Length);
        }
        let added = Revocation::from_bytes(core::slice::from_raw_parts(rev, rev_len))
            .and_then(|r| (*set).0.add(&r));
        match added {
            Ok(()) => AA_PLAYER_OK,
            Err(e) => fail(F, e),
        }
    })
}

/// 1 when the grant `nonce` (16 bytes) of `game` (32 bytes) is revoked, else 0. A null
/// argument reads as revoked.
///
/// # Safety
/// `set` must be a valid set or null; `game` must point to 32 readable bytes, `nonce` to 16.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_contains(
    set: *const RevSetHandle,
    game: *const u8,
    nonce: *const u8,
) -> i32 {
    guard::ffi_guard(1, || {
        if set.is_null() || game.is_null() || nonce.is_null() {
            guard::set_last_error("aa_revset_contains: null argument (read as revoked)");
            return 1;
        }
        i32::from((*set).0.contains(&AliceId(rd(game)), &rd(nonce)))
    })
}

/// Drop the revocations whose grant has expired at `now_ms`; the number dropped, or -1 for
/// a null set.
///
/// # Safety
/// `set` must be a valid set or null.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_purge(set: *mut RevSetHandle, now_ms: u64) -> i64 {
    guard::ffi_guard(-1, || {
        if set.is_null() {
            guard::set_last_error("aa_revset_purge: null set");
            return -1;
        }
        i64::try_from((*set).0.purge(now_ms)).unwrap_or(i64::MAX)
    })
}

/// The number of revocations held, or -1 for a null set.
///
/// # Safety
/// `set` must be a valid set or null.
#[no_mangle]
pub unsafe extern "C" fn aa_revset_len(set: *const RevSetHandle) -> i64 {
    guard::ffi_guard(-1, || {
        if set.is_null() {
            guard::set_last_error("aa_revset_len: null set");
            return -1;
        }
        i64::try_from((*set).0.len()).unwrap_or(i64::MAX)
    })
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

/// Record the refusal of `func` for `aa_last_error` and return its code.
fn fail(func: &str, e: GrantError) -> i32 {
    guard::set_last_error(format!("{func}: {e}"));
    e.code()
}

/// Read `N` bytes from `p` (not null, `N` readable bytes).
unsafe fn rd<const N: usize>(p: *const u8) -> [u8; N] {
    let mut a = [0u8; N];
    core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), N);
    a
}

/// Write `src` to `dst` (not null, `src.len()` writable bytes).
unsafe fn wr(src: &[u8], dst: *mut u8) {
    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
}
