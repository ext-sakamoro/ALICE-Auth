//! identity.

use crate::errors::*;
use crate::random::*;
use crate::types::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

// Identity
// ============================================================================

/// Ed25519 signing identity. Secret key is zeroized on drop.
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
    /// Sign `m`.
    ///
    /// # Errors
    ///
    /// [`SignError::ReservedPrefix`] when `m` starts with [`RESERVED_PREFIX`]
    /// (the crate's own signed formats); nothing is signed.
    #[inline]
    pub fn sign(&self, m: &[u8]) -> core::result::Result<AliceSig, SignError> {
        if m.starts_with(RESERVED_PREFIX) {
            return Err(SignError::ReservedPrefix);
        }
        Ok(self.sign_reserved(m))
    }
    /// Sign a 32-byte challenge.
    ///
    /// # Errors
    ///
    /// [`SignError::ReservedPrefix`] as for [`Identity::sign`] (the prefix fits
    /// in 32 bytes).
    #[inline]
    pub fn sign32(&self, c: &[u8; 32]) -> core::result::Result<AliceSig, SignError> {
        self.sign(c)
    }
    /// Sign without the reserved-prefix check: the path for the crate's own
    /// formats (endorsements, recovery approvals, JWTs, and the tagged formats
    /// under [`RESERVED_PREFIX`]). Crate-private, and not reachable from the C
    /// ABI or Python.
    ///
    /// ```compile_fail
    /// let i = alice_auth::Identity::from_seed(&[1u8; 32]);
    /// let _ = i.sign_reserved(b"alice-auth/x");
    /// ```
    ///
    /// ```
    /// let i = alice_auth::Identity::from_seed(&[1u8; 32]);
    /// let _ = i.sign(b"x");
    /// ```
    #[inline(always)]
    #[must_use]
    pub(crate) fn sign_reserved(&self, m: &[u8]) -> AliceSig {
        AliceSig(self.sk.sign(m).to_bytes())
    }
}
