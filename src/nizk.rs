//! Schnorr Non-Interactive Zero-Knowledge Proof (NIZK)
//!
//! A genuine ZKP implementation using the Fiat-Shamir heuristic over
//! Curve25519 (Ed25519 base point). This proves knowledge of a discrete
//! logarithm (secret key) without revealing any information about it.
//!
//! # Protocol (Sigma Protocol + Fiat-Shamir)
//!
//! ```text
//! Prover (knows secret x, public P = x*G):
//!   1. Pick random r, compute R = r*G          (commitment)
//!   2. e = BLAKE3(R || P || message)            (Fiat-Shamir challenge)
//!   3. s = r + e*x  (mod l)                    (response)
//!   4. Send proof = (R, s)
//!
//! Verifier (knows P, message):
//!   1. Receive (R, s)
//!   2. e = BLAKE3(R || P || message)
//!   3. Check: s*G == R + e*P
//! ```
//!
//! # Zero-Knowledge Property
//!
//! A simulator can produce indistinguishable (R, s) pairs without knowing x,
//! proving that the proof reveals zero information about the secret key.
//! (Schnorr, "Efficient Signature Generation by Smart Cards", J. Cryptology, 1991)
//!
//! # Soundness
//!
//! Two accepting transcripts with different challenges yield the secret key
//! (special soundness), ensuring the prover truly knows x.
//! (Fiat & Shamir, "How to Prove Yourself", CRYPTO '86)
//!
//! # Batch Verification
//!
//! Multiple proofs are verified in a single multi-scalar multiplication using
//! the Schwartz-Zippel lemma with random linear combination weights.
//! (Bellare, Garay, Rabin, "Fast Batch Verification for Modular Exponentiation
//! and Digital Signatures", EUROCRYPT '98)
//! See also RFC 8235 §4 (Schnorr NIZK Proof for Discrete Log).
//!
//! # Security Hardening
//!
//! - **Hedged randomness**: Nonce = BLAKE3_KDF(seed || message || random).
//!   Even if the RNG is compromised, the deterministic component prevents
//!   nonce reuse (which would leak the secret key).
//! - **Wide reduction**: 64-byte hash → `from_bytes_mod_order_wide` for
//!   statistically uniform scalar distribution (no modular bias).
//!   The 64-byte output is constructed from two independent BLAKE3 KDF
//!   evaluations with distinct domain separators ("lo"/"hi"), analogous
//!   to HKDF-Expand producing multiple blocks with different counters.
//!   Since BLAKE3 KDF is a PRF, each 32-byte half is independently
//!   pseudorandom, and their concatenation is a valid 64-byte PRF output.
//! - **Canonical scalars**: Verifier rejects non-canonical response s ≥ l
//!   to prevent proof malleability.
//! - **Constant-time verification**: Uses `subtle::ConstantTimeEq` to
//!   prevent timing side-channels.
//! - **Zeroization**: Secret scalar and nonce are zeroized after use.
//!
//! Author: Moroya Sakamoto

extern crate std;

use crate::{AliceId, AliceSig, Identity};
use alice_crypto as crypto;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// ============================================================================
// Types
// ============================================================================

/// Schnorr NIZK proof: proves knowledge of the discrete log of a public key.
///
/// Layout: commitment R (32 bytes) + response s (32 bytes) = 64 bytes.
/// Fits in the same wire format as AliceSig for protocol compatibility.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SchnorrProof {
    /// Commitment R = r*G (compressed Edwards point)
    pub commitment: [u8; 32],
    /// Response s = r + e*x (mod l)
    pub response: [u8; 32],
}

impl core::fmt::Debug for SchnorrProof {
    #[inline(always)]
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl SchnorrProof {
    pub const N: usize = 64;

    /// Convert to flat 64-byte array.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment);
        out[32..].copy_from_slice(&self.response);
        out
    }

    /// Parse from 64-byte array.
    #[must_use]
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        commitment.copy_from_slice(&b[..32]);
        response.copy_from_slice(&b[32..]);
        Self {
            commitment,
            response,
        }
    }

    /// Convert to AliceSig for wire compatibility.
    #[inline]
    #[must_use]
    pub fn to_sig(&self) -> AliceSig {
        AliceSig::new(self.to_bytes())
    }
}

// ============================================================================
// Fiat-Shamir Challenge
// ============================================================================

/// Compute the Fiat-Shamir challenge: e = BLAKE3(R || P || message)
///
/// Uses BLAKE3 KDF with domain separator "alice-schnorr-nizk-v1"
/// to prevent cross-protocol attacks.
#[inline]
fn fiat_shamir(commitment_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> Scalar {
    let mut input = std::vec::Vec::with_capacity(64 + message.len());
    input.extend_from_slice(commitment_r);
    input.extend_from_slice(public_key);
    input.extend_from_slice(message);

    // 64-byte wide hash for uniform scalar (no modular bias)
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&crypto::derive_key("alice-schnorr-challenge-lo", &input));
    wide[32..].copy_from_slice(&crypto::derive_key("alice-schnorr-challenge-hi", &input));
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ============================================================================
// Hedged Nonce Generation
// ============================================================================

/// Generate a hedged nonce scalar.
///
/// Combines deterministic (seed + message) and random components:
///   nonce = BLAKE3_KDF(seed || message || random)
///
/// This provides:
/// - **Uniform distribution** via 64-byte wide reduction
/// - **RNG failure resilience**: even if `random` is constant, different
///   messages still produce different nonces (preventing nonce reuse attacks)
/// - **Forward secrecy**: random component ensures nonces are unpredictable
///   even if seed is later compromised
fn hedged_nonce(identity: &Identity, message: &[u8]) -> crate::Result<Scalar> {
    let random: [u8; 32] = crate::rand()?;
    let mut seed = identity.seed();

    let mut nonce_input = std::vec::Vec::with_capacity(64 + message.len());
    nonce_input.extend_from_slice(&seed);
    nonce_input.extend_from_slice(message);
    nonce_input.extend_from_slice(&random);

    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&crypto::derive_key(
        "alice-schnorr-nonce-v1-lo",
        &nonce_input,
    ));
    wide[32..].copy_from_slice(&crypto::derive_key(
        "alice-schnorr-nonce-v1-hi",
        &nonce_input,
    ));

    // Zeroize sensitive material
    seed.zeroize();
    nonce_input.zeroize();

    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

// ============================================================================
// Prove / Verify
// ============================================================================

/// Generate a Schnorr NIZK proof that the prover knows the secret key
/// corresponding to `identity.id()`.
///
/// The proof binds to `message`, so the same proof cannot be replayed
/// for a different message (context binding).
///
/// Uses hedged randomness for nonce generation: even if the platform
/// RNG returns identical bytes, different messages produce different nonces.
///
/// # Errors
/// Returns `AuthError::E5` if the platform RNG fails.
pub fn prove(identity: &Identity, message: &[u8]) -> crate::Result<SchnorrProof> {
    // 1. Hedged nonce: BLAKE3_KDF(seed || message || random) → 64B → mod l
    let mut r = hedged_nonce(identity, message)?;

    // 2. Compute commitment R = r * G
    let big_r = EdwardsPoint::mul_base(&r);
    let big_r_compressed = big_r.compress();

    // 3. Fiat-Shamir challenge: e = BLAKE3(R || P || message) (wide reduction)
    let public_key = identity.id();
    let e = fiat_shamir(&big_r_compressed.0, public_key.as_bytes(), message);

    // 4. Response: s = r + e * x (mod l)
    let mut x = secret_scalar(identity);
    let s = r + e * x;

    // Zeroize secret material
    r.zeroize();
    x.zeroize();

    Ok(SchnorrProof {
        commitment: big_r_compressed.0,
        response: s.to_bytes(),
    })
}

/// Verify a Schnorr NIZK proof.
///
/// Checks that the prover knows the secret key for `id` by verifying:
///   s*G == R + e*P
///
/// where e = BLAKE3(R || P || message).
///
/// Rejects non-canonical response scalars (s ≥ l) to prevent malleability.
/// Uses constant-time comparison to prevent timing side-channels.
#[must_use]
pub fn verify_proof(id: &AliceId, message: &[u8], proof: &SchnorrProof) -> bool {
    // Decompress R
    let big_r = match CompressedEdwardsY(proof.commitment).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Decompress P (public key)
    let big_p = match CompressedEdwardsY(*id.as_bytes()).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Reject non-canonical response scalar (s >= l → malleability)
    let s: Option<Scalar> = Scalar::from_canonical_bytes(proof.response).into();
    let s = match s {
        Some(s) => s,
        None => return false,
    };

    // Recompute challenge (wide reduction, uniform)
    let e = fiat_shamir(&proof.commitment, id.as_bytes(), message);

    // Verify: s*G == R + e*P (constant-time comparison)
    let lhs = EdwardsPoint::mul_base(&s);
    let rhs = big_r + big_p * e;

    lhs.compress()
        .as_bytes()
        .ct_eq(rhs.compress().as_bytes())
        .into()
}

/// Batch-verify multiple Schnorr NIZK proofs.
///
/// Uses randomized linear combination to reduce n individual verifications
/// to a single multi-scalar multiplication (Schwartz-Zippel lemma):
///
///   sum(z_i * s_i) * G == sum(z_i * R_i) + sum(z_i * e_i * P_i)
///
/// Random weights z_i are derived deterministically from all proofs
/// (no additional RNG calls needed).
///
/// Returns `false` if any proof is invalid. Approximately 2x faster
/// than individual verification for large batches.
#[must_use]
pub fn verify_batch(items: &[(&AliceId, &[u8], &SchnorrProof)]) -> bool {
    if items.is_empty() {
        return true;
    }
    if items.len() == 1 {
        return verify_proof(items[0].0, items[0].1, items[0].2);
    }

    // Derive deterministic random weights from all proofs (Schwartz-Zippel)
    let mut weight_seed_input = std::vec::Vec::with_capacity(items.len() * 64);
    for (id, msg, proof) in items {
        weight_seed_input.extend_from_slice(id.as_bytes());
        weight_seed_input.extend_from_slice(&proof.commitment);
        weight_seed_input.extend_from_slice(&proof.response);
        weight_seed_input.extend_from_slice(msg);
    }
    let weight_seed = crypto::derive_key("alice-schnorr-batch-v1", &weight_seed_input);

    let mut total_s = Scalar::ZERO;
    let mut scalars = std::vec::Vec::with_capacity(items.len() * 2);
    let mut points = std::vec::Vec::with_capacity(items.len() * 2);

    for (i, (id, msg, proof)) in items.iter().enumerate() {
        // Decompress R
        let big_r = match CompressedEdwardsY(proof.commitment).decompress() {
            Some(p) => p,
            None => return false,
        };
        // Decompress P
        let big_p = match CompressedEdwardsY(*id.as_bytes()).decompress() {
            Some(p) => p,
            None => return false,
        };
        // Reject non-canonical s
        let s: Option<Scalar> = Scalar::from_canonical_bytes(proof.response).into();
        let s = match s {
            Some(s) => s,
            None => return false,
        };

        // Derive per-proof weight: z_i = BLAKE3(weight_seed || index)
        // Uses wide reduction (64B → mod l) for uniform distribution,
        // consistent with nonce and challenge generation.
        let mut idx_input = [0u8; 36];
        idx_input[..32].copy_from_slice(&weight_seed);
        idx_input[32..36].copy_from_slice(&(i as u32).to_le_bytes());
        let mut z_wide = [0u8; 64];
        z_wide[..32].copy_from_slice(&crypto::derive_key(
            "alice-schnorr-batch-weight-lo",
            &idx_input,
        ));
        z_wide[32..].copy_from_slice(&crypto::derive_key(
            "alice-schnorr-batch-weight-hi",
            &idx_input,
        ));
        let z = Scalar::from_bytes_mod_order_wide(&z_wide);

        let e = fiat_shamir(&proof.commitment, id.as_bytes(), msg);

        total_s += z * s;
        scalars.push(z);
        points.push(big_r);
        scalars.push(z * e);
        points.push(big_p);
    }

    // Check: total_s * G == sum(z_i * R_i + z_i * e_i * P_i)
    let lhs = EdwardsPoint::mul_base(&total_s);
    let rhs =
        <EdwardsPoint as curve25519_dalek::traits::VartimeMultiscalarMul>::vartime_multiscalar_mul(
            scalars.iter(),
            points.iter(),
        );

    lhs.compress()
        .as_bytes()
        .ct_eq(rhs.compress().as_bytes())
        .into()
}

/// Extract the Ed25519 secret scalar from an Identity.
///
/// Ed25519 derives the scalar by SHA-512 hashing the seed, then clamping
/// the lower 32 bytes. We replicate this process.
fn secret_scalar(identity: &Identity) -> Scalar {
    use ed25519_dalek::hazmat::ExpandedSecretKey;

    let mut seed = identity.seed();
    let expanded = ExpandedSecretKey::from(&seed);
    seed.zeroize();
    expanded.scalar
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_verify_basic() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"hello world").unwrap();
        assert!(verify_proof(&id.id(), b"hello world", &proof));
    }

    #[test]
    fn wrong_message_fails() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"hello").unwrap();
        assert!(!verify_proof(&id.id(), b"goodbye", &proof));
    }

    #[test]
    fn wrong_identity_fails() {
        let alice = Identity::gen().unwrap();
        let bob = Identity::gen().unwrap();
        let proof = prove(&alice, b"msg").unwrap();
        assert!(!verify_proof(&bob.id(), b"msg", &proof));
    }

    #[test]
    fn empty_message() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"").unwrap();
        assert!(verify_proof(&id.id(), b"", &proof));
    }

    #[test]
    fn large_message() {
        let id = Identity::gen().unwrap();
        let msg = vec![0xAA; 4096];
        let proof = prove(&id, &msg).unwrap();
        assert!(verify_proof(&id.id(), &msg, &proof));
    }

    #[test]
    fn proof_to_bytes_roundtrip() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"roundtrip").unwrap();
        let bytes = proof.to_bytes();
        let restored = SchnorrProof::from_bytes(&bytes);
        assert_eq!(proof, restored);
        assert!(verify_proof(&id.id(), b"roundtrip", &restored));
    }

    #[test]
    fn proof_to_sig_compatibility() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"wire").unwrap();
        let sig = proof.to_sig();
        assert_eq!(sig.as_bytes().len(), 64);
        let restored = SchnorrProof::from_bytes(sig.as_bytes());
        assert!(verify_proof(&id.id(), b"wire", &restored));
    }

    #[test]
    fn two_proofs_differ() {
        let id = Identity::gen().unwrap();
        let p1 = prove(&id, b"same").unwrap();
        let p2 = prove(&id, b"same").unwrap();
        // Different random nonces → different proofs
        assert_ne!(p1.commitment, p2.commitment);
        assert!(verify_proof(&id.id(), b"same", &p1));
        assert!(verify_proof(&id.id(), b"same", &p2));
    }

    #[test]
    fn tampered_commitment_fails() {
        let id = Identity::gen().unwrap();
        let mut proof = prove(&id, b"tamper").unwrap();
        proof.commitment[0] ^= 0xFF;
        assert!(!verify_proof(&id.id(), b"tamper", &proof));
    }

    #[test]
    fn tampered_response_fails() {
        let id = Identity::gen().unwrap();
        let mut proof = prove(&id, b"tamper").unwrap();
        proof.response[0] ^= 0xFF;
        assert!(!verify_proof(&id.id(), b"tamper", &proof));
    }

    #[test]
    fn proof_size_is_64() {
        assert_eq!(SchnorrProof::N, 64);
        assert_eq!(core::mem::size_of::<SchnorrProof>(), 64);
    }

    // --- Non-canonical scalar rejection ---

    #[test]
    fn non_canonical_response_rejected() {
        let id = Identity::gen().unwrap();
        let mut proof = prove(&id, b"canonical").unwrap();
        // Set response to all 0xFF (definitely >= l)
        proof.response = [0xFF; 32];
        assert!(!verify_proof(&id.id(), b"canonical", &proof));
    }

    // --- Batch verification ---

    #[test]
    fn batch_verify_empty() {
        assert!(verify_batch(&[]));
    }

    #[test]
    fn batch_verify_single() {
        let id = Identity::gen().unwrap();
        let proof = prove(&id, b"single").unwrap();
        assert!(verify_batch(&[(&id.id(), &b"single"[..], &proof)]));
    }

    #[test]
    fn batch_verify_multiple_valid() {
        let ids: Vec<_> = (0..5).map(|_| Identity::gen().unwrap()).collect();
        let messages: Vec<&[u8]> = vec![b"msg0", b"msg1", b"msg2", b"msg3", b"msg4"];
        let proofs: Vec<_> = ids
            .iter()
            .zip(messages.iter())
            .map(|(id, msg)| prove(id, msg).unwrap())
            .collect();

        let pub_ids: Vec<_> = ids.iter().map(|id| id.id()).collect();
        let items: Vec<_> = pub_ids
            .iter()
            .zip(messages.iter())
            .zip(proofs.iter())
            .map(|((id, msg), proof)| (id, *msg, proof))
            .collect();

        assert!(verify_batch(&items));
    }

    #[test]
    fn batch_verify_one_invalid_fails() {
        let ids: Vec<_> = (0..3).map(|_| Identity::gen().unwrap()).collect();
        let messages: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let mut proofs: Vec<_> = ids
            .iter()
            .zip(messages.iter())
            .map(|(id, msg)| prove(id, msg).unwrap())
            .collect();

        // Tamper with one proof
        proofs[1].response[0] ^= 0xFF;

        let pub_ids: Vec<_> = ids.iter().map(|id| id.id()).collect();
        let items: Vec<_> = pub_ids
            .iter()
            .zip(messages.iter())
            .zip(proofs.iter())
            .map(|((id, msg), proof)| (id, *msg, proof))
            .collect();

        assert!(!verify_batch(&items));
    }

    #[test]
    fn batch_verify_consistent_with_individual() {
        let ids: Vec<_> = (0..4).map(|_| Identity::gen().unwrap()).collect();
        let messages: Vec<&[u8]> = vec![b"w", b"x", b"y", b"z"];
        let proofs: Vec<_> = ids
            .iter()
            .zip(messages.iter())
            .map(|(id, msg)| prove(id, msg).unwrap())
            .collect();

        let pub_ids: Vec<_> = ids.iter().map(|id| id.id()).collect();

        // Individual verification
        for ((id, msg), proof) in pub_ids.iter().zip(messages.iter()).zip(proofs.iter()) {
            assert!(verify_proof(id, msg, proof));
        }

        // Batch verification
        let items: Vec<_> = pub_ids
            .iter()
            .zip(messages.iter())
            .zip(proofs.iter())
            .map(|((id, msg), proof)| (id, *msg, proof))
            .collect();
        assert!(verify_batch(&items));
    }
}
