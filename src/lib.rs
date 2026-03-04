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
//! | `nizk`  | no      | Schnorr NIZK proof (true ZKP) via `curve25519-dalek`. |
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
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

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
        let mut hex_buf = [0u8; 64];
        hex32(&self.0, &mut hex_buf);
        buf[20..84].copy_from_slice(&hex_buf);
        // SAFETY: buf contains only ASCII bytes (a-z, :, /, 0-9) — all valid UTF-8.
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

impl Drop for Identity {
    fn drop(&mut self) {
        // Overwrite the signing key with zeros to prevent secret key residue in memory.
        // SigningKey::from_bytes overwrites internal state; zeroize the temp buffer.
        let mut zero = [0u8; 32];
        self.sk = SigningKey::from_bytes(&zero);
        zero.zeroize();
    }
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
// Constant-time comparison
// ============================================================================

/// Constant-time byte slice comparison (no early exit on content).
/// Returns true only if both slices have the same length and content.
///
/// Uses the `subtle` crate's `ConstantTimeEq` to guarantee that the
/// compiler cannot optimize away the constant-time property.
///
/// **Note**: The length check is NOT constant-time — different lengths
/// return `false` immediately. This is standard practice (lengths are
/// typically public in authentication protocols). For comparisons where
/// the length must also be secret, use [`ct_eq_n`] with fixed-size arrays.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison for fixed-size byte arrays.
///
/// Both length and content comparisons are constant-time since the
/// length is statically known at compile time.
#[inline]
#[must_use]
pub fn ct_eq_n<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.as_slice().ct_eq(b.as_slice()).into()
}

// ============================================================================
// Key Rotation
// ============================================================================

/// Identity with key rotation support.
///
/// Maintains a current keypair and up to `max_generations` previous keys
/// (for graceful transition). Callers should verify signatures against
/// all retained keys during the rotation window.
#[cfg(feature = "std")]
pub struct RotatingIdentity {
    current: Identity,
    previous: Vec<(Identity, u64)>,
    max_generations: usize,
}

#[cfg(feature = "std")]
impl RotatingIdentity {
    /// Default maximum number of previous key generations to retain.
    pub const DEFAULT_MAX_GENERATIONS: usize = 2;

    /// Create a new rotating identity from a fresh keypair.
    /// # Errors
    /// Returns `AuthError::E5` if the platform RNG fails.
    pub fn gen() -> Result<Self> {
        Ok(Self {
            current: Identity::gen()?,
            previous: Vec::new(),
            max_generations: Self::DEFAULT_MAX_GENERATIONS,
        })
    }

    /// Create from an existing identity.
    #[must_use]
    pub fn from_identity(id: Identity) -> Self {
        Self {
            current: id,
            previous: Vec::new(),
            max_generations: Self::DEFAULT_MAX_GENERATIONS,
        }
    }

    /// Create with a custom maximum number of previous generations.
    #[must_use]
    pub fn with_max_generations(id: Identity, max: usize) -> Self {
        Self {
            current: id,
            previous: Vec::new(),
            max_generations: max.max(1),
        }
    }

    /// Rotate to a new keypair. The old key is archived with a timestamp.
    /// Oldest generations beyond `max_generations` are evicted (and zeroized).
    /// Returns the new public AliceId.
    /// # Errors
    /// Returns `AuthError::E5` if the platform RNG fails.
    pub fn rotate(&mut self, now_ms: u64) -> Result<AliceId> {
        let mut old_seed = self.current.seed();
        let old = Identity::from_seed(&old_seed);
        old_seed.zeroize();
        let new = Identity::gen()?;
        self.previous.push((old, now_ms));
        // Evict oldest generations beyond limit (dropped Identity runs Drop → zeroize)
        while self.previous.len() > self.max_generations {
            self.previous.remove(0);
        }
        self.current = new;
        Ok(self.current.id())
    }

    /// Get the current public identity.
    #[inline]
    #[must_use]
    pub fn id(&self) -> AliceId {
        self.current.id()
    }

    /// Get the most recent previous public identity (if rotation has occurred).
    #[must_use]
    pub fn previous_id(&self) -> Option<(AliceId, u64)> {
        self.previous.last().map(|(id, ts)| (id.id(), *ts))
    }

    /// Get all previous public identities (oldest first).
    #[must_use]
    pub fn previous_ids(&self) -> Vec<(AliceId, u64)> {
        self.previous
            .iter()
            .map(|(id, ts)| (id.id(), *ts))
            .collect()
    }

    /// Sign with the current key.
    #[inline]
    #[must_use]
    pub fn sign(&self, m: &[u8]) -> AliceSig {
        self.current.sign(m)
    }

    /// Verify a signature against the current key, falling back to all
    /// previous keys. Returns true if any key matches.
    #[must_use]
    pub fn verify_any(&self, id: &AliceId, m: &[u8], s: &AliceSig) -> bool {
        if ok(id, m, s) {
            return true;
        }
        for (prev, _) in &self.previous {
            if ok(&prev.id(), m, s) {
                return true;
            }
        }
        false
    }

    /// Clear all previous keys (after rotation window expires).
    pub fn clear_previous(&mut self) {
        self.previous.clear();
    }

    /// Check if rotation has occurred and previous keys exist.
    #[must_use]
    pub fn has_previous(&self) -> bool {
        !self.previous.is_empty()
    }

    /// Number of retained previous generations.
    #[must_use]
    pub fn generation_count(&self) -> usize {
        self.previous.len()
    }
}

// ============================================================================
// Challenge TTL (Timed Challenge-Response)
// ============================================================================

/// Challenge with a creation timestamp for TTL enforcement.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TimedPending {
    pub id: AliceId,
    pub c: [u8; 32],
    pub created_ms: u64,
}

impl fmt::Debug for TimedPending {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// Default challenge TTL: 30 seconds
pub const CHALLENGE_TTL_MS: u64 = 30_000;

/// Create a challenge with a timestamp for TTL enforcement.
/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
#[inline]
pub fn make_timed_challenge(id: AliceId, now_ms: u64) -> Result<TimedPending> {
    Ok(TimedPending {
        id,
        c: challenge()?,
        created_ms: now_ms,
    })
}

/// Verify a challenge-response with TTL enforcement.
///
/// Returns `AuthResult::Fail` if:
/// - The signature is invalid
/// - The challenge has expired (now_ms - created_ms > ttl_ms)
/// - The RNG fails to generate a session token
#[inline]
#[must_use]
pub fn check_timed(p: &TimedPending, r: &Response, now_ms: u64, ttl_ms: u64) -> AuthResult {
    if now_ms.saturating_sub(p.created_ms) > ttl_ms {
        return AuthResult::Fail;
    }
    let pending = Pending { id: p.id, c: p.c };
    check(&pending, r)
}

// ============================================================================
// Trust Chain (Identity Bootstrap / Endorsement)
// ============================================================================

/// An endorsement: a trust anchor (or intermediate) signs another identity's
/// public key to create a verifiable chain of trust.
///
/// Endorsements have an expiry time (`expires_ms`). Verification rejects
/// expired endorsements automatically.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Endorsement {
    pub endorser: AliceId,
    pub endorsed: AliceId,
    pub sig: AliceSig,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

impl fmt::Debug for Endorsement {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl Endorsement {
    /// Serialize the endorsement payload (endorsed_id || issued_ms || expires_ms)
    /// that gets signed by the endorser.
    #[inline]
    fn payload(endorsed: &AliceId, issued_ms: u64, expires_ms: u64) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..32].copy_from_slice(endorsed.as_bytes());
        buf[32..40].copy_from_slice(&issued_ms.to_le_bytes());
        buf[40..48].copy_from_slice(&expires_ms.to_le_bytes());
        buf
    }
}

/// Create an endorsement: the signer vouches for the target identity.
///
/// The endorsement is valid from `now_ms` until `now_ms + ttl_ms`.
#[inline]
#[must_use]
pub fn endorse(signer: &Identity, target: &AliceId, now_ms: u64, ttl_ms: u64) -> Endorsement {
    let expires_ms = now_ms + ttl_ms;
    let payload = Endorsement::payload(target, now_ms, expires_ms);
    Endorsement {
        endorser: signer.id(),
        endorsed: *target,
        sig: signer.sign(&payload),
        issued_ms: now_ms,
        expires_ms,
    }
}

/// Verify a single endorsement: check signature validity AND expiry.
///
/// Returns `false` if the signature is invalid or `now_ms > expires_ms`.
#[inline]
#[must_use]
pub fn verify_endorsement(e: &Endorsement, now_ms: u64) -> bool {
    if now_ms > e.expires_ms {
        return false;
    }
    let payload = Endorsement::payload(&e.endorsed, e.issued_ms, e.expires_ms);
    ok(&e.endorser, &payload, &e.sig)
}

/// Verify a chain of endorsements from a root trust anchor.
///
/// The chain must satisfy:
/// 1. The first endorsement's endorser must be the root.
/// 2. Each subsequent endorsement's endorser must be the previous endorsed.
/// 3. All signatures must be valid.
/// 4. No endorsement is expired at `now_ms`.
#[must_use]
pub fn verify_chain(chain: &[Endorsement], root: &AliceId, now_ms: u64) -> bool {
    if chain.is_empty() {
        return false;
    }
    if chain[0].endorser != *root {
        return false;
    }
    if !verify_endorsement(&chain[0], now_ms) {
        return false;
    }
    let mut i = 1;
    while i < chain.len() {
        if chain[i].endorser != chain[i - 1].endorsed {
            return false;
        }
        if !verify_endorsement(&chain[i], now_ms) {
            return false;
        }
        i += 1;
    }
    true
}

// ============================================================================
// Social Recovery (Guardian-based Key Migration)
// ============================================================================

/// Configuration for social recovery: a set of guardian identities and
/// the minimum number of approvals needed to authorize key migration.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct RecoveryConfig {
    pub guardians: Vec<AliceId>,
    pub threshold: u8,
}

/// A guardian's approval for migrating from old_id to new_id.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RecoveryApproval {
    pub guardian: AliceId,
    pub old_id: AliceId,
    pub new_id: AliceId,
    pub sig: AliceSig,
    pub approved_ms: u64,
}

impl fmt::Debug for RecoveryApproval {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl RecoveryApproval {
    /// Serialize the recovery payload that gets signed:
    /// "recover" || old_id(32) || new_id(32) || timestamp(8) = 79 bytes
    fn payload(old_id: &AliceId, new_id: &AliceId, approved_ms: u64) -> [u8; 79] {
        let mut buf = [0u8; 79];
        buf[0..7].copy_from_slice(b"recover");
        buf[7..39].copy_from_slice(old_id.as_bytes());
        buf[39..71].copy_from_slice(new_id.as_bytes());
        buf[71..79].copy_from_slice(&approved_ms.to_le_bytes());
        buf
    }
}

/// Guardian signs an approval for key migration.
///
/// The guardian vouches that `old_id` should be replaced by `new_id`.
#[must_use]
pub fn approve_recovery(
    guardian: &Identity,
    old_id: &AliceId,
    new_id: &AliceId,
    now_ms: u64,
) -> RecoveryApproval {
    let payload = RecoveryApproval::payload(old_id, new_id, now_ms);
    RecoveryApproval {
        guardian: guardian.id(),
        old_id: *old_id,
        new_id: *new_id,
        sig: guardian.sign(&payload),
        approved_ms: now_ms,
    }
}

/// Verify a single guardian's recovery approval.
#[must_use]
pub fn verify_recovery_approval(approval: &RecoveryApproval) -> bool {
    let payload =
        RecoveryApproval::payload(&approval.old_id, &approval.new_id, approval.approved_ms);
    ok(&approval.guardian, &payload, &approval.sig)
}

/// Validate a complete recovery request against a config.
///
/// Returns true if:
/// 1. At least `threshold` valid approvals from registered guardians
/// 2. All approvals agree on the same old_id and new_id
/// 3. All signatures verify correctly
#[cfg(feature = "std")]
#[must_use]
pub fn validate_recovery(
    config: &RecoveryConfig,
    old_id: &AliceId,
    new_id: &AliceId,
    approvals: &[RecoveryApproval],
) -> bool {
    if config.threshold == 0 || config.guardians.is_empty() {
        return false;
    }

    let mut valid_count: u8 = 0;
    let mut seen_guardians = Vec::new();

    for approval in approvals {
        // Must match the target migration
        if approval.old_id != *old_id || approval.new_id != *new_id {
            continue;
        }
        // Must be a registered guardian
        if !config.guardians.contains(&approval.guardian) {
            continue;
        }
        // Reject duplicate guardian approvals (same guardian cannot vote twice)
        if seen_guardians.contains(&approval.guardian) {
            continue;
        }
        // Signature must verify
        if !verify_recovery_approval(approval) {
            continue;
        }
        seen_guardians.push(approval.guardian);
        valid_count = valid_count.saturating_add(1);
    }

    valid_count >= config.threshold
}

// ============================================================================
// FFI (cold error path, hot success path)
// ============================================================================

#[cfg(feature = "crypto")]
pub mod crypto_bridge;

#[cfg(feature = "nizk")]
pub mod nizk;

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
    pub struct Handle(pub(crate) Identity);

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
        match super::RotatingIdentity::gen() {
            Ok(r) => Box::into_raw(Box::new(RotHandle(r))),
            Err(_) => {
                null_ptr();
                core::ptr::null_mut()
            }
        }
    }

    /// Rotate to a new keypair. Writes the new 32-byte public ID to `out`.
    ///
    /// # Safety
    ///
    /// - `h` must be a valid `RotHandle` pointer.
    /// - `out` must point to at least 32 writable bytes.
    #[no_mangle]
    pub unsafe extern "C" fn aa_rotating_rotate(
        h: *mut RotHandle,
        now_ms: u64,
        out: *mut u8,
    ) -> i32 {
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
        let token = super::api_bridge::AuthToken::new(now_ms, ttl_ms);
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
        match super::api_bridge::AuthToken::from_bytes(buf) {
            Some(t) => t.is_expired(now_ms) as i32,
            None => 1,
        }
    }

    // ========================================================================
    // RevocationList FFI
    // ========================================================================

    #[repr(C)]
    pub struct RevHandle(super::api_bridge::RevocationList);

    /// Create a new RevocationList with default capacity.
    #[no_mangle]
    pub extern "C" fn aa_revlist_new() -> *mut RevHandle {
        Box::into_raw(Box::new(
            RevHandle(super::api_bridge::RevocationList::new()),
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
    pub unsafe extern "C" fn aa_revlist_auto_purge(
        h: *mut RevHandle,
        now_ms: u64,
        ttl_ms: u64,
    ) -> u32 {
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
    pub struct PolicyHandle(super::api_bridge::PolicyEngine);

    /// Create a PolicyEngine with read-only default role.
    #[no_mangle]
    pub extern "C" fn aa_policy_new() -> *mut PolicyHandle {
        Box::into_raw(Box::new(PolicyHandle(
            super::api_bridge::PolicyEngine::new(super::api_bridge::Role::READER),
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
        (*h).0.assign(&aid, super::api_bridge::Role { mask });
    }

    /// Check if an identity has a specific permission (0=Read,1=Write,2=Admin,3=Execute).
    /// Returns 1 if authorized, 0 otherwise.
    ///
    /// # Safety
    ///
    /// - `h` must be a valid `PolicyHandle` pointer.
    /// - `id` must point to 32 readable bytes.
    #[no_mangle]
    pub unsafe extern "C" fn aa_policy_check(
        h: *const PolicyHandle,
        id: *const u8,
        perm: u8,
    ) -> i32 {
        if h.is_null() || id.is_null() {
            null_ptr();
            return 0;
        }
        let aid = AliceId(r32(id));
        let permission = match perm {
            0 => super::api_bridge::Permission::Read,
            1 => super::api_bridge::Permission::Write,
            2 => super::api_bridge::Permission::Admin,
            3 => super::api_bridge::Permission::Execute,
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
}

#[cfg(feature = "ffi")]
pub use ffi::*;

// ============================================================================
// NIZK FFI (requires both "ffi" and "nizk" features)
// ============================================================================

#[cfg(all(feature = "ffi", feature = "nizk"))]
mod ffi_nizk {
    use super::*;

    #[inline(always)]
    unsafe fn r32(p: *const u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
        a
    }

    #[cold]
    #[inline(never)]
    fn null_ptr() {}

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
        match nizk::prove(&(*h).0, msg) {
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
        let p = nizk::SchnorrProof::from_bytes(&proof_bytes);
        nizk::verify_proof(&id, msg, &p) as i32
    }
}

#[cfg(all(feature = "ffi", feature = "nizk"))]
pub use ffi_nizk::*;

// ============================================================================
// Crypto FFI (requires both "ffi" and "crypto" features)
// ============================================================================

#[cfg(all(feature = "ffi", feature = "crypto"))]
mod ffi_crypto {
    use super::*;
    extern crate std;
    use std::boxed::Box;

    #[inline(always)]
    unsafe fn r32(p: *const u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32);
        a
    }

    #[cold]
    #[inline(never)]
    fn null_ptr() {}

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
        let child = crypto_bridge::derive_child(&(*h).0, index);
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
        let key = crypto_bridge::derive_session_key(&a, &b, s);
        core::ptr::copy_nonoverlapping(key.as_bytes().as_ptr(), out, 32);
    }
}

#[cfg(all(feature = "ffi", feature = "crypto"))]
pub use ffi_crypto::*;

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

#[cfg(all(test, feature = "std"))]
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

    // --- Key Rotation tests (require std for RotatingIdentity) ---

    #[cfg(feature = "std")]
    mod rotation_tests {
        use super::super::*;

        #[test]
        fn rotating_identity_gen() {
            let ri = RotatingIdentity::gen().unwrap();
            assert!(!ri.has_previous());
            assert_eq!(ri.id().0.len(), 32);
        }

        #[test]
        fn rotating_identity_rotate() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let old_id = ri.id();
        let new_id = ri.rotate(1000).unwrap();
        assert_ne!(old_id, new_id);
        assert!(ri.has_previous());
        let (prev_id, ts) = ri.previous_id().unwrap();
        assert_eq!(prev_id, old_id);
        assert_eq!(ts, 1000);
    }

    #[test]
    fn rotating_identity_verify_any_current() {
        let ri = RotatingIdentity::gen().unwrap();
        let sig = ri.sign(b"msg");
        assert!(ri.verify_any(&ri.id(), b"msg", &sig));
    }

    #[test]
    fn rotating_identity_verify_any_previous() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let old_id = ri.id();
        let sig = ri.sign(b"msg");
        ri.rotate(1000).unwrap();
        // Old signature still verifiable via verify_any
        assert!(ri.verify_any(&old_id, b"msg", &sig));
    }

    #[test]
    fn rotating_identity_clear_previous() {
        let mut ri = RotatingIdentity::gen().unwrap();
        ri.rotate(1000).unwrap();
        assert!(ri.has_previous());
        ri.clear_previous();
        assert!(!ri.has_previous());
    }

    #[test]
    fn rotating_identity_double_rotate() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let id1 = ri.id();
        ri.rotate(1000).unwrap();
        let id2 = ri.id();
        ri.rotate(2000).unwrap();
        let id3 = ri.id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        // Most recent previous key
        let (prev, ts) = ri.previous_id().unwrap();
        assert_eq!(prev, id2);
        assert_eq!(ts, 2000);
        // Both previous generations retained (max_generations=2)
        assert_eq!(ri.generation_count(), 2);
    }

    #[test]
    fn rotating_identity_n_generations() {
        let mut ri = RotatingIdentity::gen().unwrap();
        let id0 = ri.id();
        ri.rotate(1000).unwrap();
        let id1 = ri.id();
        ri.rotate(2000).unwrap();
        let id2 = ri.id();
        ri.rotate(3000).unwrap();
        // max_generations=2: oldest (id0) should be evicted
        assert_eq!(ri.generation_count(), 2);
        let prev_ids = ri.previous_ids();
        assert_eq!(prev_ids[0].0, id1);
        assert_eq!(prev_ids[1].0, id2);
        // Evicted id0 not in previous_ids
        assert!(prev_ids.iter().all(|(id, _)| *id != id0));
    }

    #[test]
    fn rotating_identity_custom_max_generations() {
        let base = Identity::gen().unwrap();
        let mut ri = RotatingIdentity::with_max_generations(base, 4);
        for i in 0..6 {
            ri.rotate(i * 1000).unwrap();
        }
        // Should retain at most 4 previous generations
        assert_eq!(ri.generation_count(), 4);
    }
    } // mod rotation_tests

    // --- Challenge TTL tests ---

    #[test]
    fn timed_challenge_valid() {
        let i = Identity::gen().unwrap();
        let tp = make_timed_challenge(i.id(), 1000).unwrap();
        let r = respond(&i, &Challenge { n: tp.c });
        assert!(matches!(
            check_timed(&tp, &r, 2000, CHALLENGE_TTL_MS),
            AuthResult::Ok(_)
        ));
    }

    #[test]
    fn timed_challenge_expired() {
        let i = Identity::gen().unwrap();
        let tp = make_timed_challenge(i.id(), 1000).unwrap();
        let r = respond(&i, &Challenge { n: tp.c });
        // 31 seconds later → expired (TTL = 30s)
        assert!(matches!(
            check_timed(&tp, &r, 32_000, CHALLENGE_TTL_MS),
            AuthResult::Fail
        ));
    }

    #[test]
    fn timed_challenge_at_boundary() {
        let i = Identity::gen().unwrap();
        let tp = make_timed_challenge(i.id(), 0).unwrap();
        let r = respond(&i, &Challenge { n: tp.c });
        // Exactly at TTL boundary → still valid (not >)
        assert!(matches!(
            check_timed(&tp, &r, CHALLENGE_TTL_MS, CHALLENGE_TTL_MS),
            AuthResult::Ok(_)
        ));
        // 1ms over → expired
        assert!(matches!(
            check_timed(&tp, &r, CHALLENGE_TTL_MS + 1, CHALLENGE_TTL_MS),
            AuthResult::Fail
        ));
    }

    #[test]
    fn timed_challenge_wrong_signer() {
        let i = Identity::gen().unwrap();
        let other = Identity::gen().unwrap();
        let tp = make_timed_challenge(i.id(), 1000).unwrap();
        let r = respond(&other, &Challenge { n: tp.c });
        assert!(matches!(
            check_timed(&tp, &r, 1500, CHALLENGE_TTL_MS),
            AuthResult::Fail
        ));
    }

    // --- Trust Chain / Endorsement tests ---

    #[test]
    fn endorsement_basic() {
        let root = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let e = endorse(&root, &user.id(), 1000, 60_000);
        assert!(verify_endorsement(&e, 2000));
        assert_eq!(e.endorser, root.id());
        assert_eq!(e.endorsed, user.id());
        assert_eq!(e.issued_ms, 1000);
        assert_eq!(e.expires_ms, 61_000);
    }

    #[test]
    fn endorsement_tampered() {
        let root = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let mut e = endorse(&root, &user.id(), 1000, 60_000);
        // Tamper with the endorsed identity
        e.endorsed = AliceId::new([0xFF; 32]);
        assert!(!verify_endorsement(&e, 2000));
    }

    #[test]
    fn endorsement_wrong_signer() {
        let root = Identity::gen().unwrap();
        let fake = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let mut e = endorse(&root, &user.id(), 1000, 60_000);
        e.endorser = fake.id();
        assert!(!verify_endorsement(&e, 2000));
    }

    #[test]
    fn endorsement_expired() {
        let root = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let e = endorse(&root, &user.id(), 1000, 5000);
        // Valid before expiry
        assert!(verify_endorsement(&e, 5000));
        // Expired after expiry
        assert!(!verify_endorsement(&e, 6001));
    }

    #[test]
    fn verify_chain_single() {
        let root = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let e = endorse(&root, &user.id(), 1000, 60_000);
        assert!(verify_chain(&[e], &root.id(), 2000));
    }

    #[test]
    fn verify_chain_multi_hop() {
        let root = Identity::gen().unwrap();
        let intermediate = Identity::gen().unwrap();
        let leaf = Identity::gen().unwrap();
        let e1 = endorse(&root, &intermediate.id(), 1000, 60_000);
        let e2 = endorse(&intermediate, &leaf.id(), 2000, 60_000);
        assert!(verify_chain(&[e1, e2], &root.id(), 3000));
    }

    #[test]
    fn verify_chain_wrong_root() {
        let root = Identity::gen().unwrap();
        let fake_root = Identity::gen().unwrap();
        let user = Identity::gen().unwrap();
        let e = endorse(&root, &user.id(), 1000, 60_000);
        assert!(!verify_chain(&[e], &fake_root.id(), 2000));
    }

    #[test]
    fn verify_chain_broken_link() {
        let root = Identity::gen().unwrap();
        let a = Identity::gen().unwrap();
        let b = Identity::gen().unwrap();
        let unrelated = Identity::gen().unwrap();
        let e1 = endorse(&root, &a.id(), 1000, 60_000);
        let e2 = endorse(&unrelated, &b.id(), 2000, 60_000);
        assert!(!verify_chain(&[e1, e2], &root.id(), 3000));
    }

    #[test]
    fn verify_chain_empty() {
        let root = Identity::gen().unwrap();
        assert!(!verify_chain(&[], &root.id(), 1000));
    }

    #[test]
    fn verify_chain_expired_link() {
        let root = Identity::gen().unwrap();
        let intermediate = Identity::gen().unwrap();
        let leaf = Identity::gen().unwrap();
        let e1 = endorse(&root, &intermediate.id(), 1000, 5000); // expires at 6000
        let e2 = endorse(&intermediate, &leaf.id(), 2000, 60_000);
        // At 3000: both valid
        assert!(verify_chain(&[e1, e2], &root.id(), 3000));
        // At 7000: e1 expired → chain fails
        assert!(!verify_chain(&[e1, e2], &root.id(), 7000));
    }

    // --- Constant-time timing tests (require std for Vec/Instant) ---

    #[cfg(feature = "std")]
    mod timing_tests {
        use super::super::*;

        #[test]
        fn verify_timing_consistency() {
        let i = Identity::gen().unwrap();
        let msg = [0xAA; 64];
        let valid_sig = i.sign(&msg);
        let invalid_sig = AliceSig::new([0u8; 64]);

        // Run multiple rounds to check variance is bounded
        let rounds = 100;
        let mut valid_times = Vec::with_capacity(rounds);
        let mut invalid_times = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = verify(&i.id(), &msg, &valid_sig);
            valid_times.push(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = verify(&i.id(), &msg, &invalid_sig);
            invalid_times.push(start.elapsed().as_nanos());
        }

        let valid_avg: u128 = valid_times.iter().sum::<u128>() / rounds as u128;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / rounds as u128;

        // The ratio between valid and invalid verification times should be
        // within 10x of each other (loose bound to avoid flaky CI).
        // A non-constant-time implementation would show much larger divergence.
        let ratio = if valid_avg > invalid_avg {
            valid_avg / invalid_avg.max(1)
        } else {
            invalid_avg / valid_avg.max(1)
        };
        assert!(
            ratio < 10,
            "timing ratio {ratio} too large (valid_avg={valid_avg}ns, invalid_avg={invalid_avg}ns)"
        );
    }

    #[test]
    fn ct_eq_16_timing_consistency() {
        let a = [0xAAu8; 16];
        let b_same = [0xAAu8; 16];
        let mut b_diff = [0xAAu8; 16];
        b_diff[0] = 0xBB;
        let mut b_last = [0xAAu8; 16];
        b_last[15] = 0xBB;

        let rounds = 200;
        let mut same_times = Vec::with_capacity(rounds);
        let mut diff_first_times = Vec::with_capacity(rounds);
        let mut diff_last_times = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_same);
            same_times.push(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_diff);
            diff_first_times.push(start.elapsed().as_nanos());
        }
        for _ in 0..rounds {
            let start = std::time::Instant::now();
            let _ = ct_eq(&a, &b_last);
            diff_last_times.push(start.elapsed().as_nanos());
        }

        // Difference at first byte vs last byte should produce similar timing
        let df_avg: u128 = diff_first_times.iter().sum::<u128>() / rounds as u128;
        let dl_avg: u128 = diff_last_times.iter().sum::<u128>() / rounds as u128;
        let ratio = if df_avg > dl_avg {
            df_avg / dl_avg.max(1)
        } else {
            dl_avg / df_avg.max(1)
        };
        assert!(
            ratio < 10,
            "timing ratio {ratio} too large (first={df_avg}ns, last={dl_avg}ns)"
        );
    }
    } // mod timing_tests

    #[test]
    fn ct_eq_correctness() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
        assert!(!ct_eq(&[], &[1]));
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn ct_eq_n_fixed_size() {
        assert!(ct_eq_n(&[1u8, 2, 3, 4], &[1, 2, 3, 4]));
        assert!(!ct_eq_n(&[1u8, 2, 3, 4], &[1, 2, 3, 5]));
        assert!(ct_eq_n(&[0xAAu8; 32], &[0xAAu8; 32]));
        assert!(!ct_eq_n(&[0xAAu8; 32], &[0xBBu8; 32]));
    }

    // --- Social Recovery tests ---

    #[test]
    fn recovery_approval_basic() {
        let guardian = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();
        let approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
        assert!(verify_recovery_approval(&approval));
        assert_eq!(approval.guardian, guardian.id());
        assert_eq!(approval.old_id, old.id());
        assert_eq!(approval.new_id, new.id());
    }

    #[test]
    fn recovery_approval_tampered_fails() {
        let guardian = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();
        let mut approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
        // Tamper with new_id
        approval.new_id = AliceId::new([0xFF; 32]);
        assert!(!verify_recovery_approval(&approval));
    }

    #[cfg(feature = "std")]
    mod recovery_validate_tests {
        use super::super::*;

        #[test]
        fn validate_recovery_threshold_met() {
            let g1 = Identity::gen().unwrap();
        let g2 = Identity::gen().unwrap();
        let g3 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id(), g2.id(), g3.id()],
            threshold: 2,
        };

        let a1 = approve_recovery(&g1, &old.id(), &new.id(), 1000);
        let a2 = approve_recovery(&g2, &old.id(), &new.id(), 2000);

        assert!(validate_recovery(&config, &old.id(), &new.id(), &[a1, a2],));
    }

    #[test]
    fn validate_recovery_threshold_not_met() {
        let g1 = Identity::gen().unwrap();
        let g2 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id(), g2.id()],
            threshold: 2,
        };

        let a1 = approve_recovery(&g1, &old.id(), &new.id(), 1000);
        // Only 1 approval, need 2
        assert!(!validate_recovery(&config, &old.id(), &new.id(), &[a1],));
    }

    #[test]
    fn validate_recovery_unregistered_guardian() {
        let g1 = Identity::gen().unwrap();
        let stranger = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id()],
            threshold: 1,
        };

        // Stranger's approval should not count
        let a = approve_recovery(&stranger, &old.id(), &new.id(), 1000);
        assert!(!validate_recovery(&config, &old.id(), &new.id(), &[a],));
    }

    #[test]
    fn validate_recovery_empty_config() {
        let config = RecoveryConfig {
            guardians: vec![],
            threshold: 0,
        };
        assert!(!validate_recovery(
            &config,
            &AliceId::new([0; 32]),
            &AliceId::new([1; 32]),
            &[],
        ));
    }

    #[test]
    fn validate_recovery_duplicate_guardian_rejected() {
        let g1 = Identity::gen().unwrap();
        let old = Identity::gen().unwrap();
        let new_id = Identity::gen().unwrap();

        let config = RecoveryConfig {
            guardians: vec![g1.id()],
            threshold: 2,
        };

        // Same guardian approves twice — should count as 1, not 2
        let a1 = approve_recovery(&g1, &old.id(), &new_id.id(), 1000);
        let a2 = approve_recovery(&g1, &old.id(), &new_id.id(), 2000);
        assert!(!validate_recovery(
            &config,
            &old.id(),
            &new_id.id(),
            &[a1, a2],
        ));
    }
    } // mod recovery_validate_tests
}
