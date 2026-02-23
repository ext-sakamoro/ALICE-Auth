//! ALICE-Auth: Ed25519 ZKP Authentication
//!
//! Zero-allocation, branchless Ed25519 challenge-response authentication
//! for the ALICE ecosystem.
//!
//! # Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | *(root)* | `Identity`, `AliceId`, `AliceSig`, challenge-response protocol |
//! | `crypto_bridge` | ALICE-Crypto token hashing + session encryption (feature `crypto`) |
//! | `db_bridge` | ALICE-DB audit-log persistence (feature `db`) |
//! | `api_bridge` | ALICE-API auth middleware bridge (feature `api`) |
//! | `python` | `PyO3` bindings (feature `pyo3`) |
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std`   | no      | Enables standard-library types. Required for testing. |
//! | `alloc` | no      | Enables `alloc` crate (subset of `std`). |
//! | `serde` | no      | Derive `Serialize` / `Deserialize` for wire types. |
//! | `ffi`   | no      | C-ABI exports (`aa_new`, `aa_sign`, `aa_verify`, `aa_free`). |
//! | `pyo3`  | no      | Python bindings via `PyO3`. |
//! | `crypto`| no      | ALICE-Crypto token hashing + session encryption. |
//! | `db`    | no      | ALICE-DB audit-log persistence. |
//! | `api`   | no      | ALICE-API auth middleware bridge. |
//!
//! # Quick Start
//!
//! ```rust
//! use alice_auth::{Identity, hello, make_challenge, respond, check, AuthResult, Challenge};
//!
//! // Generate identity
//! let id = Identity::gen().unwrap();
//!
//! // Challenge-response flow
//! let h = hello(&id);
//! let pending = make_challenge(h.id).unwrap();
//! let resp = respond(&id, &Challenge { n: pending.c });
//! assert!(matches!(check(&pending, &resp), AuthResult::Ok(_)));
//! ```
//!
//! # Protocol
//!
//! ```text
//! Client                          Server
//!   |-- Hello { id, v:1 } -------->|
//!   |<- Challenge { nonce:32B } ---|
//!   |-- Response { sig(nonce) } -->|
//!   |<- AuthResult::Ok(token:16B) -|
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::module_name_repetitions,
    clippy::inline_always,
    clippy::too_many_lines
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// ============================================================================
// Error (zero .rodata, no match)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthError {
    E1 = 1,
    E2 = 2,
    E3 = 3,
    E4 = 4,
    E5 = 5,
}

impl fmt::Display for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            let c = [b'E', b'0' + (*self as u8)];
            f.write_str(unsafe { core::str::from_utf8_unchecked(&c) })
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = f;
            Ok(())
        }
    }
}

impl fmt::Debug for AuthError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub type Result<T> = core::result::Result<T, AuthError>;

// ============================================================================
// Types
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AliceId(pub [u8; 32]);

impl AliceId {
    pub const N: usize = 32;
    pub const DID_N: usize = 84;

    #[inline(always)]
    #[must_use] 
    pub const fn new(b: [u8; 32]) -> Self {
        Self(b)
    }
    #[inline(always)]
    #[must_use] 
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    #[inline(always)]
    #[must_use] 
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn write_did<'a>(&self, buf: &'a mut [u8; 84]) -> &'a str {
        buf[0] = b'a';
        buf[1] = b'l';
        buf[2] = b'i';
        buf[3] = b'c';
        buf[4] = b'e';
        buf[5] = b':';
        buf[6] = b'/';
        buf[7] = b'/';
        buf[8] = b'd';
        buf[9] = b'i';
        buf[10] = b'd';
        buf[11] = b':';
        buf[12] = b'e';
        buf[13] = b'd';
        buf[14] = b'2';
        buf[15] = b'5';
        buf[16] = b'5';
        buf[17] = b'1';
        buf[18] = b'9';
        buf[19] = b':';
        let d = unsafe { &mut *buf.as_mut_ptr().add(20).cast::<[u8; 64]>() };
        hex32(&self.0, d);
        unsafe { core::str::from_utf8_unchecked(buf) }
    }

    #[inline(always)]
    #[must_use] 
    pub fn to_did_bytes(&self) -> [u8; 84] {
        let mut b = [0u8; 84];
        self.write_did(&mut b);
        b
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for AliceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = [0u8; 8];
        hex4(&self.0, &mut h);
        f.write_str("Id(")?;
        f.write_str(unsafe { core::str::from_utf8_unchecked(&h) })?;
        f.write_str(")")
    }
}
#[cfg(not(debug_assertions))]
impl fmt::Debug for AliceId {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl fmt::Display for AliceId {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = [0u8; 84];
        f.write_str(self.write_did(&mut b))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct AliceSig(pub [u8; 64]);

impl AliceSig {
    pub const N: usize = 64;
    #[inline(always)]
    #[must_use] 
    pub const fn new(b: [u8; 64]) -> Self {
        Self(b)
    }
    #[inline(always)]
    #[must_use] 
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    #[inline(always)]
    #[must_use] 
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for AliceSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = [0u8; 16];
        hex8(&self.0, &mut h);
        f.write_str("Sig(")?;
        f.write_str(unsafe { core::str::from_utf8_unchecked(&h) })?;
        f.write_str(")")
    }
}
#[cfg(not(debug_assertions))]
impl fmt::Debug for AliceSig {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AliceSig {
    #[inline(always)]
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AliceSig {
    #[inline(always)]
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = AliceSig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("64")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> core::result::Result<Self::Value, E> {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut a = [0u8; 64];
                a.copy_from_slice(v);
                Ok(AliceSig(a))
            }
        }
        d.deserialize_bytes(V)
    }
}

// ============================================================================
// Random
// ============================================================================

/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline(always)]
pub fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| AuthError::E5)?;
    Ok(b)
}

/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline(always)]
pub fn challenge() -> Result<[u8; 32]> {
    rand()
}

// ============================================================================
// Identity
// ============================================================================

pub struct Identity {
    sk: SigningKey,
    pk: VerifyingKey,
}

impl Identity {
    /// # Errors
    /// Returns `AuthError::E5` if the platform RNG fails.
    #[inline(always)]
    pub fn gen() -> Result<Self> {
        Ok(Self::from_seed(&rand()?))
    }
    #[inline(always)]
    #[must_use] 
    pub fn from_seed(s: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(s);
        Self {
            pk: VerifyingKey::from(&sk),
            sk,
        }
    }
    #[inline(always)]
    #[must_use] 
    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
    #[inline(always)]
    #[must_use] 
    pub fn id(&self) -> AliceId {
        AliceId(self.pk.to_bytes())
    }
    #[inline(always)]
    #[must_use] 
    pub fn sign(&self, m: &[u8]) -> AliceSig {
        AliceSig(self.sk.sign(m).to_bytes())
    }
    #[inline(always)]
    #[must_use] 
    pub fn sign32(&self, c: &[u8; 32]) -> AliceSig {
        self.sign(c)
    }
}

// ============================================================================
// Verify
// ============================================================================

/// # Errors
/// Returns `AuthError::E1` if the public key is invalid, or `AuthError::E3` if
/// the signature verification fails.
#[inline(always)]
pub fn verify(id: &AliceId, m: &[u8], s: &AliceSig) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&id.0).map_err(|_| AuthError::E1)?;
    pk.verify(m, &Signature::from_bytes(&s.0))
        .map_err(|_| AuthError::E3)
}

/// # Errors
/// Returns `AuthError::E1` if the public key is invalid, or `AuthError::E3` if
/// the signature verification fails.
#[inline(always)]
pub fn verify32(id: &AliceId, c: &[u8; 32], s: &AliceSig) -> Result<()> {
    verify(id, c, s)
}
#[inline(always)]
#[must_use] 
pub fn ok(id: &AliceId, m: &[u8], s: &AliceSig) -> bool {
    verify(id, m, s).is_ok()
}

// ============================================================================
// Protocol
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hello {
    pub id: AliceId,
    pub v: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Challenge {
    pub n: [u8; 32],
}

#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
    pub s: AliceSig,
}

#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthResult {
    Ok([u8; 16]),
    Fail,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Pending {
    pub id: AliceId,
    pub c: [u8; 32],
}

impl fmt::Debug for Hello {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl fmt::Debug for Challenge {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl fmt::Debug for Response {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl fmt::Debug for AuthResult {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl fmt::Debug for Pending {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline(always)]
pub fn make_challenge(id: AliceId) -> Result<Pending> {
    Ok(Pending {
        id,
        c: challenge()?,
    })
}
/// Returns `AuthResult::Fail` if the signature is invalid *or* if the RNG
/// cannot produce a session token — an all-zeros token would be a trivially
/// guessable secret, so we treat RNG failure as an authentication failure.
#[inline(always)]
#[must_use] 
pub fn check(p: &Pending, r: &Response) -> AuthResult {
    match verify32(&p.id, &p.c, &r.s) {
        Ok(()) => match rand::<16>() {
            Ok(tok) => AuthResult::Ok(tok),
            Err(_) => AuthResult::Fail,
        },
        Err(_) => AuthResult::Fail,
    }
}
#[inline(always)]
#[must_use] 
pub fn hello(i: &Identity) -> Hello {
    Hello { id: i.id(), v: 1 }
}
#[inline(always)]
#[must_use] 
pub fn respond(i: &Identity, c: &Challenge) -> Response {
    Response { s: i.sign32(&c.n) }
}

// ============================================================================
// Hex (fully unrolled, no loop, no branch)
// ============================================================================

const H: [u8; 16] = *b"0123456789abcdef";

#[cfg(debug_assertions)]
#[inline(always)]
fn hex4(s: &[u8], d: &mut [u8; 8]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
}

#[cfg(debug_assertions)]
#[inline(always)]
fn hex8(s: &[u8], d: &mut [u8; 16]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
    d[8] = H[(s[4] >> 4) as usize];
    d[9] = H[(s[4] & 0xf) as usize];
    d[10] = H[(s[5] >> 4) as usize];
    d[11] = H[(s[5] & 0xf) as usize];
    d[12] = H[(s[6] >> 4) as usize];
    d[13] = H[(s[6] & 0xf) as usize];
    d[14] = H[(s[7] >> 4) as usize];
    d[15] = H[(s[7] & 0xf) as usize];
}

#[inline(always)]
fn hex32(s: &[u8; 32], d: &mut [u8; 64]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
    d[8] = H[(s[4] >> 4) as usize];
    d[9] = H[(s[4] & 0xf) as usize];
    d[10] = H[(s[5] >> 4) as usize];
    d[11] = H[(s[5] & 0xf) as usize];
    d[12] = H[(s[6] >> 4) as usize];
    d[13] = H[(s[6] & 0xf) as usize];
    d[14] = H[(s[7] >> 4) as usize];
    d[15] = H[(s[7] & 0xf) as usize];
    d[16] = H[(s[8] >> 4) as usize];
    d[17] = H[(s[8] & 0xf) as usize];
    d[18] = H[(s[9] >> 4) as usize];
    d[19] = H[(s[9] & 0xf) as usize];
    d[20] = H[(s[10] >> 4) as usize];
    d[21] = H[(s[10] & 0xf) as usize];
    d[22] = H[(s[11] >> 4) as usize];
    d[23] = H[(s[11] & 0xf) as usize];
    d[24] = H[(s[12] >> 4) as usize];
    d[25] = H[(s[12] & 0xf) as usize];
    d[26] = H[(s[13] >> 4) as usize];
    d[27] = H[(s[13] & 0xf) as usize];
    d[28] = H[(s[14] >> 4) as usize];
    d[29] = H[(s[14] & 0xf) as usize];
    d[30] = H[(s[15] >> 4) as usize];
    d[31] = H[(s[15] & 0xf) as usize];
    d[32] = H[(s[16] >> 4) as usize];
    d[33] = H[(s[16] & 0xf) as usize];
    d[34] = H[(s[17] >> 4) as usize];
    d[35] = H[(s[17] & 0xf) as usize];
    d[36] = H[(s[18] >> 4) as usize];
    d[37] = H[(s[18] & 0xf) as usize];
    d[38] = H[(s[19] >> 4) as usize];
    d[39] = H[(s[19] & 0xf) as usize];
    d[40] = H[(s[20] >> 4) as usize];
    d[41] = H[(s[20] & 0xf) as usize];
    d[42] = H[(s[21] >> 4) as usize];
    d[43] = H[(s[21] & 0xf) as usize];
    d[44] = H[(s[22] >> 4) as usize];
    d[45] = H[(s[22] & 0xf) as usize];
    d[46] = H[(s[23] >> 4) as usize];
    d[47] = H[(s[23] & 0xf) as usize];
    d[48] = H[(s[24] >> 4) as usize];
    d[49] = H[(s[24] & 0xf) as usize];
    d[50] = H[(s[25] >> 4) as usize];
    d[51] = H[(s[25] & 0xf) as usize];
    d[52] = H[(s[26] >> 4) as usize];
    d[53] = H[(s[26] & 0xf) as usize];
    d[54] = H[(s[27] >> 4) as usize];
    d[55] = H[(s[27] & 0xf) as usize];
    d[56] = H[(s[28] >> 4) as usize];
    d[57] = H[(s[28] & 0xf) as usize];
    d[58] = H[(s[29] >> 4) as usize];
    d[59] = H[(s[29] & 0xf) as usize];
    d[60] = H[(s[30] >> 4) as usize];
    d[61] = H[(s[30] & 0xf) as usize];
    d[62] = H[(s[31] >> 4) as usize];
    d[63] = H[(s[31] & 0xf) as usize];
}

// ============================================================================
// FFI (cold error path, hot success path)
// ============================================================================

#[cfg(feature = "crypto")]
pub mod crypto_bridge;

#[cfg(feature = "db")]
pub mod db_bridge;

#[cfg(feature = "api")]
pub mod api_bridge;

#[cfg(feature = "pyo3")]
pub mod python;

#[cfg(feature = "ffi")]
mod ffi {
    use super::*;
    extern crate std;
    use std::boxed::Box;

    #[repr(C)]
    pub struct Handle(Identity);

    #[cold]
    #[inline(never)]
    fn null_ptr() {}

    #[inline(always)]
    unsafe fn r32(p: *const u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
        a
    }

    #[inline(always)]
    unsafe fn r64(p: *const u8) -> [u8; 64] {
        let mut a = [0u8; 64];
        core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 64);
        a
    }

    #[inline(always)]
    unsafe fn w32(s: &[u8; 32], d: *mut u8) {
        core::ptr::copy_nonoverlapping(s.as_ptr(), d, 32);
    }

    #[inline(always)]
    unsafe fn w64(s: &[u8; 64], d: *mut u8) {
        core::ptr::copy_nonoverlapping(s.as_ptr(), d, 64);
    }

    #[no_mangle]
    pub extern "C" fn aa_new() -> *mut Handle {
        match Identity::gen() {
            Ok(i) => Box::into_raw(Box::new(Handle(i))),
            Err(_) => {
                null_ptr();
                core::ptr::null_mut()
            }
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
    pub unsafe extern "C" fn aa_verify(
        pk: *const u8,
        m: *const u8,
        ml: usize,
        s: *const u8,
    ) -> i32 {
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
}

#[cfg(feature = "ffi")]
pub use ffi::*;

// ============================================================================
// no_std panic handler
// ============================================================================

/// In `no_std` builds there is no runtime to call `std::process::abort`, so we
/// provide a minimal panic handler that spins forever.  This satisfies the
/// linker's requirement for exactly one `#[panic_handler]` without pulling in
/// any allocator or OS dependency.  Builds with `feature = "std"` use the
/// standard library's built-in panic handler instead.
#[cfg(all(not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen() {
        assert_eq!(Identity::gen().unwrap().id().0.len(), 32);
    }
    #[test]
    fn sign_verify() {
        let i = Identity::gen().unwrap();
        assert!(ok(&i.id(), b"x", &i.sign(b"x")));
    }
    #[test]
    fn challenge_flow() {
        let i = Identity::gen().unwrap();
        let c = challenge().unwrap();
        assert!(verify32(&i.id(), &c, &i.sign32(&c)).is_ok());
    }
    #[test]
    fn wrong_signer() {
        let a = Identity::gen().unwrap();
        let b = Identity::gen().unwrap();
        assert!(!ok(&b.id(), b"x", &a.sign(b"x")));
    }
    #[test]
    fn tamper() {
        let i = Identity::gen().unwrap();
        assert!(!ok(&i.id(), b"y", &i.sign(b"x")));
    }
    #[test]
    fn seed_recovery() {
        let a = Identity::gen().unwrap();
        let b = Identity::from_seed(&a.seed());
        assert_eq!(a.id(), b.id());
    }
    #[test]
    fn full_flow() {
        let i = Identity::gen().unwrap();
        let h = hello(&i);
        let p = make_challenge(h.id).unwrap();
        let r = respond(&i, &Challenge { n: p.c });
        assert!(matches!(check(&p, &r), AuthResult::Ok(_)));
    }
    #[test]
    fn did() {
        let i = Identity::gen().unwrap();
        let mut b = [0u8; 84];
        assert!(i.id().write_did(&mut b).starts_with("alice://did:ed25519:"));
    }
    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<AliceId>(), 32);
        assert_eq!(core::mem::size_of::<AliceSig>(), 64);
    }

    // --- Additional tests ---

    #[test]
    fn alice_id_new_and_as_bytes() {
        let raw = [0x42u8; 32];
        let id = AliceId::new(raw);
        assert_eq!(*id.as_bytes(), raw);
    }

    #[test]
    fn alice_id_into_bytes() {
        let raw = [0xAB; 32];
        let id = AliceId::new(raw);
        assert_eq!(id.into_bytes(), raw);
    }

    #[test]
    fn alice_id_equality() {
        let a = AliceId::new([1u8; 32]);
        let b = AliceId::new([1u8; 32]);
        let c = AliceId::new([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn alice_sig_new_and_as_bytes() {
        let raw = [0xEE; 64];
        let sig = AliceSig::new(raw);
        assert_eq!(*sig.as_bytes(), raw);
    }

    #[test]
    fn alice_sig_into_bytes() {
        let raw = [0xDD; 64];
        let sig = AliceSig::new(raw);
        assert_eq!(sig.into_bytes(), raw);
    }

    #[test]
    fn alice_sig_equality() {
        let a = AliceSig::new([1u8; 64]);
        let b = AliceSig::new([1u8; 64]);
        let c = AliceSig::new([2u8; 64]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn verify_invalid_public_key_returns_e1() {
        let bad_id = AliceId::new([0xFF; 32]);
        let sig = AliceSig::new([0u8; 64]);
        let result = verify(&bad_id, b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify32_invalid_sig_returns_err() {
        let i = Identity::gen().unwrap();
        let bad_sig = AliceSig::new([0u8; 64]);
        assert!(verify32(&i.id(), &[0u8; 32], &bad_sig).is_err());
    }

    #[test]
    fn sign_empty_message() {
        let i = Identity::gen().unwrap();
        let sig = i.sign(b"");
        assert!(ok(&i.id(), b"", &sig));
    }

    #[test]
    fn sign_large_message() {
        let i = Identity::gen().unwrap();
        let msg = [0xAA; 256];
        let sig = i.sign(&msg);
        assert!(ok(&i.id(), &msg, &sig));
    }

    #[test]
    fn two_identities_different_ids() {
        let a = Identity::gen().unwrap();
        let b = Identity::gen().unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn did_length_84() {
        let i = Identity::gen().unwrap();
        let d = i.id().to_did_bytes();
        assert_eq!(d.len(), 84);
    }

    #[test]
    fn did_prefix_exact() {
        let i = Identity::gen().unwrap();
        let mut buf = [0u8; 84];
        let did = i.id().write_did(&mut buf);
        assert_eq!(&did[..20], "alice://did:ed25519:");
        assert_eq!(did.len(), 84);
    }

    #[test]
    fn hello_version() {
        let i = Identity::gen().unwrap();
        let h = hello(&i);
        assert_eq!(h.v, 1);
        assert_eq!(h.id, i.id());
    }

    #[test]
    fn check_wrong_response_fails() {
        let i = Identity::gen().unwrap();
        let other = Identity::gen().unwrap();
        let p = make_challenge(i.id()).unwrap();
        let r = respond(&other, &Challenge { n: p.c });
        assert!(matches!(check(&p, &r), AuthResult::Fail));
    }

    #[test]
    fn auth_error_repr() {
        assert_eq!(AuthError::E1 as u8, 1);
        assert_eq!(AuthError::E2 as u8, 2);
        assert_eq!(AuthError::E3 as u8, 3);
        assert_eq!(AuthError::E4 as u8, 4);
        assert_eq!(AuthError::E5 as u8, 5);
    }

    #[test]
    fn auth_error_eq() {
        assert_eq!(AuthError::E1, AuthError::E1);
        assert_ne!(AuthError::E1, AuthError::E2);
    }

    #[test]
    fn pending_layout() {
        assert_eq!(core::mem::size_of::<Pending>(), 64);
    }

    #[test]
    fn challenge_is_random() {
        let c1 = challenge().unwrap();
        let c2 = challenge().unwrap();
        assert_ne!(c1, c2);
    }
}
