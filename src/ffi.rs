//! FFI (C-ABI exports).
#![allow(clippy::missing_safety_doc)]
use crate::identity::*;
use crate::trust_chain::*;
use crate::types::*;
use crate::verify::*;
use std::boxed::Box;
#[repr(C)]
pub struct Handle(pub(crate) Identity);
#[cold]
#[inline(never)]
const fn null_ptr() {}
#[inline(always)]
const unsafe fn r32(p: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
    a
}
#[inline(always)]
const unsafe fn r64(p: *const u8) -> [u8; 64] {
    let mut a = [0u8; 64];
    core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 64);
    a
}
#[inline(always)]
const unsafe fn w32(s: &[u8; 32], d: *mut u8) {
    core::ptr::copy_nonoverlapping(s.as_ptr(), d, 32);
}
#[inline(always)]
const unsafe fn w64(s: &[u8; 64], d: *mut u8) {
    core::ptr::copy_nonoverlapping(s.as_ptr(), d, 64);
}
#[no_mangle]
pub extern "C" fn aa_new() -> *mut Handle {
    if let Ok(i) = Identity::gen() {
        Box::into_raw(Box::new(Handle(i)))
    } else {
        null_ptr();
        core::ptr::null_mut()
    }
}
/// Write the 32-byte public identity into `o`.
///
/// # Safety
///
/// - `h` must be a valid pointer returned by [`aa_new`], or null.
/// - `o` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_id(h: *const Handle, o: *mut u8) {
    if h.is_null() || o.is_null() {
        null_ptr();
        return;
    }
    w32(&(*h).0.id().0, o);
}
/// Sign a 32-byte challenge and write the 64-byte signature into `o`.
///
/// # Safety
///
/// - `h` must be a valid pointer returned by [`aa_new`], or null.
/// - `c` must point to at least 32 readable bytes (challenge).
/// - `o` must point to at least 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_sign(h: *const Handle, c: *const u8, o: *mut u8) {
    if h.is_null() || c.is_null() || o.is_null() {
        null_ptr();
        return;
    }
    w64(&(*h).0.sign32(&r32(c)).0, o);
}
/// Verify an Ed25519 signature over a message.
///
/// # Safety
///
/// - `pk` must point to at least 32 readable bytes (public key).
/// - `m` must point to at least `ml` readable bytes (message).
/// - `ml` must not exceed `isize::MAX` and must match the actual
///   allocated size of the buffer at `m`.
/// - `s` must point to at least 64 readable bytes (signature).
/// - All pointers must remain valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn aa_verify(pk: *const u8, m: *const u8, ml: usize, s: *const u8) -> i32 {
    if pk.is_null() || m.is_null() || s.is_null() {
        null_ptr();
        return 0;
    }
    // Reject absurd lengths to prevent UB from from_raw_parts.
    // isize::MAX is the Rust safety invariant; 64 MiB is the practical cap.
    const MAX_MSG_LEN: usize = 64 * 1024 * 1024;
    if ml > MAX_MSG_LEN {
        return 0;
    }
    // SAFETY: m is non-null (checked above), ml is within MAX_MSG_LEN,
    // and the caller guarantees m points to at least ml valid bytes.
    ok(
        &AliceId(r32(pk)),
        core::slice::from_raw_parts(m, ml),
        &AliceSig(r64(s)),
    ) as i32
}
/// Free a handle previously created by [`aa_new`].
///
/// # Safety
///
/// - `h` must be a valid pointer returned by [`aa_new`], or null.
/// - Must not be called twice on the same pointer (double-free).
#[no_mangle]
pub unsafe extern "C" fn aa_free(h: *mut Handle) {
    if h.is_null() {
        null_ptr();
        return;
    }
    drop(Box::from_raw(h));
}
// ========================================================================
// Endorsement FFI
// ========================================================================
/// Endorse a target identity. Writes 176-byte endorsement to `out`.
///
/// Layout: endorser(32) || endorsed(32) || sig(64) || issued_ms(8) || expires_ms(8) || padding(32) = 176B
///
/// # Safety
///
/// - `h` must be a valid `Handle` pointer (the endorser).
/// - `target` must point to 32 readable bytes (the endorsed public key).
/// - `out` must point to at least 176 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_endorse(
    h: *const Handle,
    target: *const u8,
    now_ms: u64,
    ttl_ms: u64,
    out: *mut u8,
) {
    if h.is_null() || target.is_null() || out.is_null() {
        null_ptr();
        return;
    }
    let target_id = AliceId(r32(target));
    let e = super::endorse(&(*h).0, &target_id, now_ms, ttl_ms);
    let buf = core::slice::from_raw_parts_mut(out, 176);
    buf[0..32].copy_from_slice(&e.endorser.0);
    buf[32..64].copy_from_slice(&e.endorsed.0);
    buf[64..128].copy_from_slice(&e.sig.0);
    buf[128..136].copy_from_slice(&e.issued_ms.to_le_bytes());
    buf[136..144].copy_from_slice(&e.expires_ms.to_le_bytes());
    buf[144..176].fill(0);
}
/// Verify an endorsement. Returns 1 if valid, 0 otherwise.
///
/// # Safety
///
/// - `data` must point to at least 176 readable bytes (serialized endorsement).
#[no_mangle]
pub unsafe extern "C" fn aa_verify_endorsement(data: *const u8, now_ms: u64) -> i32 {
    if data.is_null() {
        null_ptr();
        return 0;
    }
    let buf = core::slice::from_raw_parts(data, 144);
    let e = Endorsement {
        endorser: AliceId(r32(buf.as_ptr())),
        endorsed: AliceId(r32(buf.as_ptr().add(32))),
        sig: AliceSig(r64(buf.as_ptr().add(64))),
        issued_ms: u64::from_le_bytes(buf[128..136].try_into().unwrap()),
        expires_ms: u64::from_le_bytes(buf[136..144].try_into().unwrap()),
    };
    super::verify_endorsement(&e, now_ms) as i32
}
// ========================================================================
// RotatingIdentity FFI
// ========================================================================
#[repr(C)]
pub struct RotHandle(super::RotatingIdentity);
/// Create a new RotatingIdentity. Returns null on RNG failure.
#[no_mangle]
pub extern "C" fn aa_rotating_new() -> *mut RotHandle {
    if let Ok(r) = super::RotatingIdentity::gen() {
        Box::into_raw(Box::new(RotHandle(r)))
    } else {
        null_ptr();
        core::ptr::null_mut()
    }
}
/// Rotate to a new keypair. Writes the new 32-byte public ID to `out`.
///
/// # Safety
///
/// - `h` must be a valid `RotHandle` pointer.
/// - `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_rotating_rotate(h: *mut RotHandle, now_ms: u64, out: *mut u8) -> i32 {
    if h.is_null() || out.is_null() {
        null_ptr();
        return 0;
    }
    match (*h).0.rotate(now_ms) {
        Ok(id) => {
            w32(&id.0, out);
            1
        }
        Err(_) => 0,
    }
}
/// Get the current public ID (32 bytes).
///
/// # Safety
///
/// - `h` must be a valid `RotHandle` pointer.
/// - `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_rotating_id(h: *const RotHandle, out: *mut u8) {
    if h.is_null() || out.is_null() {
        null_ptr();
        return;
    }
    w32(&(*h).0.id().0, out);
}
/// Verify a signature against any key (current + all previous).
///
/// # Safety
///
/// - `h` must be a valid `RotHandle` pointer.
/// - `pk` must point to 32 readable bytes, `m` to `ml` bytes, `s` to 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_rotating_verify(
    h: *const RotHandle,
    pk: *const u8,
    m: *const u8,
    ml: usize,
    s: *const u8,
) -> i32 {
    if h.is_null() || pk.is_null() || m.is_null() || s.is_null() {
        null_ptr();
        return 0;
    }
    const MAX_MSG_LEN: usize = 64 * 1024 * 1024;
    if ml > MAX_MSG_LEN {
        return 0;
    }
    let id = AliceId(r32(pk));
    let msg = core::slice::from_raw_parts(m, ml);
    let sig = AliceSig(r64(s));
    (*h).0.verify_any(&id, msg, &sig) as i32
}
/// Return the number of retained previous generations.
///
/// # Safety
///
/// - `h` must be a valid `RotHandle` pointer.
#[no_mangle]
pub unsafe extern "C" fn aa_rotating_generation_count(h: *const RotHandle) -> u32 {
    if h.is_null() {
        null_ptr();
        return 0;
    }
    (*h).0.generation_count() as u32
}
/// Free a RotatingIdentity handle.
///
/// # Safety
///
/// - `h` must be a valid pointer from `aa_rotating_new`, or null.
#[no_mangle]
pub unsafe extern "C" fn aa_rotating_free(h: *mut RotHandle) {
    if h.is_null() {
        null_ptr();
        return;
    }
    drop(Box::from_raw(h));
}
// ========================================================================
// AuthToken FFI
// ========================================================================
/// Create an AuthToken. Writes 17 bytes to `out`.
///
/// # Safety
///
/// - `out` must point to at least 17 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_token_create(now_ms: u64, ttl_ms: u64, out: *mut u8) {
    if out.is_null() {
        null_ptr();
        return;
    }
    let token = crate::api_bridge::AuthToken::new(now_ms, ttl_ms);
    let bytes = token.to_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 17);
}
/// Check if a token is expired. Returns 1 if expired, 0 if valid.
///
/// # Safety
///
/// - `data` must point to at least 17 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_token_is_expired(data: *const u8, now_ms: u64) -> i32 {
    if data.is_null() {
        null_ptr();
        return 1;
    }
    let buf = core::slice::from_raw_parts(data, 17);
    match crate::api_bridge::AuthToken::from_bytes(buf) {
        Some(t) => t.is_expired(now_ms) as i32,
        None => 1,
    }
}
// ========================================================================
// RevocationList FFI
// ========================================================================
#[repr(C)]
pub struct RevHandle(crate::api_bridge::RevocationList);
/// Create a new RevocationList with default capacity.
#[no_mangle]
pub extern "C" fn aa_revlist_new() -> *mut RevHandle {
    Box::into_raw(Box::new(
        RevHandle(crate::api_bridge::RevocationList::new()),
    ))
}
/// Revoke a 16-byte token.
///
/// # Safety
///
/// - `h` must be a valid `RevHandle` pointer.
/// - `token` must point to at least 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revlist_revoke(h: *mut RevHandle, token: *const u8, now_ms: u64) {
    if h.is_null() || token.is_null() {
        null_ptr();
        return;
    }
    let mut t = [0u8; 16];
    core::ptr::copy_nonoverlapping(token, t.as_mut_ptr(), 16);
    (*h).0.revoke(&t, now_ms);
}
/// Check if a 16-byte token is revoked. Returns 1 if revoked, 0 otherwise.
///
/// # Safety
///
/// - `h` must be a valid `RevHandle` pointer.
/// - `token` must point to at least 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_revlist_is_revoked(h: *const RevHandle, token: *const u8) -> i32 {
    if h.is_null() || token.is_null() {
        null_ptr();
        return 0;
    }
    let mut t = [0u8; 16];
    core::ptr::copy_nonoverlapping(token, t.as_mut_ptr(), 16);
    (*h).0.is_revoked(&t) as i32
}
/// Auto-purge expired tokens. Returns number purged.
///
/// # Safety
///
/// - `h` must be a valid `RevHandle` pointer.
#[no_mangle]
pub unsafe extern "C" fn aa_revlist_auto_purge(h: *mut RevHandle, now_ms: u64, ttl_ms: u64) -> u32 {
    if h.is_null() {
        null_ptr();
        return 0;
    }
    (*h).0.auto_purge(now_ms, ttl_ms) as u32
}
/// Free a RevocationList handle.
///
/// # Safety
///
/// - `h` must be a valid pointer from `aa_revlist_new`, or null.
#[no_mangle]
pub unsafe extern "C" fn aa_revlist_free(h: *mut RevHandle) {
    if h.is_null() {
        null_ptr();
        return;
    }
    drop(Box::from_raw(h));
}
// ========================================================================
// RBAC (PolicyEngine) FFI
// ========================================================================
#[repr(C)]
pub struct PolicyHandle(crate::api_bridge::PolicyEngine);
/// Create a PolicyEngine with read-only default role.
#[no_mangle]
pub extern "C" fn aa_policy_new() -> *mut PolicyHandle {
    Box::into_raw(Box::new(PolicyHandle(
        crate::api_bridge::PolicyEngine::new(crate::api_bridge::Role::READER),
    )))
}
/// Assign a role mask to an identity.
///
/// # Safety
///
/// - `h` must be a valid `PolicyHandle` pointer.
/// - `id` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_policy_assign(h: *mut PolicyHandle, id: *const u8, mask: u8) {
    if h.is_null() || id.is_null() {
        null_ptr();
        return;
    }
    let aid = AliceId(r32(id));
    (*h).0.assign(&aid, crate::api_bridge::Role { mask });
}
/// Check if an identity has a specific permission (0=Read,1=Write,2=Admin,3=Execute).
/// Returns 1 if authorized, 0 otherwise.
///
/// # Safety
///
/// - `h` must be a valid `PolicyHandle` pointer.
/// - `id` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aa_policy_check(h: *const PolicyHandle, id: *const u8, perm: u8) -> i32 {
    if h.is_null() || id.is_null() {
        null_ptr();
        return 0;
    }
    let aid = AliceId(r32(id));
    let permission = match perm {
        0 => crate::api_bridge::Permission::Read,
        1 => crate::api_bridge::Permission::Write,
        2 => crate::api_bridge::Permission::Admin,
        3 => crate::api_bridge::Permission::Execute,
        _ => return 0,
    };
    (*h).0.authorize(&aid, permission) as i32
}
/// Free a PolicyEngine handle.
///
/// # Safety
///
/// - `h` must be a valid pointer from `aa_policy_new`, or null.
#[no_mangle]
pub unsafe extern "C" fn aa_policy_free(h: *mut PolicyHandle) {
    if h.is_null() {
        null_ptr();
        return;
    }
    drop(Box::from_raw(h));
}
