//! protocol.

use crate::errors::*;
use crate::identity::*;
use crate::random::*;
use crate::types::*;
use crate::verify::*;
use core::fmt;

// Protocol
// ============================================================================

/// Client greeting containing the public identity and protocol version.
#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hello {
    pub id: AliceId,
    pub v: u8,
}

/// Server-issued 32-byte random challenge nonce.
#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Challenge {
    pub n: [u8; 32],
}

/// Client response: Ed25519 signature over the challenge nonce.
#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
    pub s: AliceSig,
}

/// Authentication result: `Ok(session_token)` or `Fail`.
#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthResult {
    Ok([u8; 16]),
    Fail,
}

/// Server-side pending challenge state (identity + nonce).
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
/// Returns `AuthResult::Fail` if the signature is invalid or RNG fails.
///
/// An all-zeros token would be a trivially
/// guessable secret, so we treat RNG failure as an authentication failure.
#[inline(always)]
#[must_use]
pub fn check(p: &Pending, r: &Response) -> AuthResult {
    verify32(&p.id, &p.c, &r.s).map_or(AuthResult::Fail, |()| {
        rand::<16>().map_or(AuthResult::Fail, AuthResult::Ok)
    })
}
/// Create a `Hello` greeting from an identity.
#[inline(always)]
#[must_use]
pub fn hello(i: &Identity) -> Hello {
    Hello { id: i.id(), v: 1 }
}
/// Sign a challenge nonce, producing a `Response`.
#[inline(always)]
#[must_use]
pub fn respond(i: &Identity, c: &Challenge) -> Response {
    Response { s: i.sign32(&c.n) }
}
