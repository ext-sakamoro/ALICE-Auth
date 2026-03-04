//! ALICE-Crypto bridge: BLAKE3 token hashing + XChaCha20 session encryption
//!
//! Provides cryptographic operations for authentication tokens using
//! ALICE-Crypto's BLAKE3 hashing and XChaCha20-Poly1305 encryption.

use crate::{AliceId, AliceSig};
use alice_crypto::{self as crypto, Key};
use zeroize::Zeroize;

/// Hash an AliceId into a compact BLAKE3 fingerprint.
///
/// Useful for indexing, logging, and token caching without exposing
/// the full public key.
pub fn id_fingerprint(id: &AliceId) -> crypto::Hash {
    crypto::hash(id.as_bytes())
}

/// Hash a message with a key for HMAC-like authentication.
///
/// Uses BLAKE3 keyed hash (not HMAC, but equally secure).
pub fn keyed_token_hash(key: &[u8; 32], message: &[u8]) -> crypto::Hash {
    crypto::keyed_hash(key, message)
}

/// Encrypt a session token (e.g. the 16-byte AuthResult::Ok payload).
///
/// Returns nonce + ciphertext + auth tag.
pub fn seal_session(key: &Key, token: &[u8]) -> Result<Vec<u8>, crypto::CipherError> {
    crypto::seal(key, token)
}

/// Decrypt a session token.
pub fn open_session(key: &Key, sealed: &[u8]) -> Result<Vec<u8>, crypto::CipherError> {
    crypto::open(key, sealed)
}

/// Derive a session encryption key from a shared secret and peer IDs.
///
/// Both peers derive the same key from (id_a XOR id_b) + BLAKE3(shared_secret).
/// The shared secret is hashed to normalize any input length uniformly into
/// 32 bytes, preventing silent zero-padding of short secrets.
pub fn derive_session_key(id_a: &AliceId, id_b: &AliceId, shared_secret: &[u8]) -> Key {
    let mut context = [0u8; 64];
    for (i, byte) in context[..32].iter_mut().enumerate() {
        *byte = id_a.0[i] ^ id_b.0[i];
    }
    // Hash the shared secret to handle any length uniformly.
    // Short secrets get entropy-preserving hashing; long secrets get compressed.
    let secret_hash = crypto::hash(shared_secret);
    context[32..64].copy_from_slice(secret_hash.as_bytes());
    let raw = crypto::derive_key("alice-auth-session-v1", &context);
    Key::from_bytes(raw)
}

/// Hash a signature for compact logging (avoids exposing full sig).
pub fn sig_fingerprint(sig: &AliceSig) -> crypto::Hash {
    crypto::hash(sig.as_bytes())
}

// ============================================================================
// Seed Recovery (Shamir SSS Integration)
// ============================================================================

/// Split an Identity's secret seed into K-of-N Shamir shards.
///
/// Distribute shards to different devices/locations. Any K shards
/// can reconstruct the original Identity.
///
/// # Example
///
/// ```rust
/// # use alice_auth::Identity;
/// # use alice_auth::crypto_bridge::split_seed;
/// let identity = Identity::gen().unwrap();
/// let shards = split_seed(&identity, 5, 3).unwrap();
/// assert_eq!(shards.len(), 5);
/// ```
pub fn split_seed(
    identity: &crate::Identity,
    n: u8,
    k: u8,
) -> Result<Vec<crypto::Shard>, crypto::SssError> {
    crypto::split(&identity.seed(), n, k)
}

/// Recover an Identity from K or more Shamir shards.
///
/// Returns the original Identity with the same public key and signing
/// capability as the one that was split.
pub fn recover_identity(shards: &[crypto::Shard]) -> Result<crate::Identity, crypto::SssError> {
    let mut seed_vec = crypto::recover(shards)?;
    if seed_vec.len() != 32 {
        seed_vec.zeroize();
        return Err(crypto::SssError::EmptySecret);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    seed_vec.zeroize();
    let identity = crate::Identity::from_seed(&seed);
    seed.zeroize();
    Ok(identity)
}

// ============================================================================
// HD Key Derivation (Hierarchical Deterministic)
// ============================================================================

/// Derive a child Identity from a parent Identity using an index.
///
/// Uses BLAKE3 KDF with the parent seed + index as context, producing
/// a deterministic child key. One master seed backup recovers all children.
///
/// # Usage
///
/// ```rust
/// # use alice_auth::Identity;
/// # use alice_auth::crypto_bridge::derive_child;
/// let master = Identity::gen().unwrap();
/// let auth_key = derive_child(&master, 0);
/// let sign_key = derive_child(&master, 1);
/// assert_ne!(auth_key.id(), sign_key.id());
/// ```
pub fn derive_child(parent: &crate::Identity, index: u32) -> crate::Identity {
    let mut context = [0u8; 36];
    context[..32].copy_from_slice(&parent.seed());
    context[32..36].copy_from_slice(&index.to_le_bytes());
    let mut child_seed = crypto::derive_key("alice-auth-hd-child-v1", &context);
    context.zeroize();
    let identity = crate::Identity::from_seed(&child_seed);
    child_seed.zeroize();
    identity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_fingerprint_deterministic() {
        let id = AliceId::new([42u8; 32]);
        let h1 = id_fingerprint(&id);
        let h2 = id_fingerprint(&id);
        assert_eq!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn test_session_seal_open() {
        let key = Key::generate().unwrap();
        let token = b"session-token-16";
        let sealed = seal_session(&key, token).unwrap();
        let opened = open_session(&key, &sealed).unwrap();
        assert_eq!(&opened, token);
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = Key::generate().unwrap();
        let k2 = Key::generate().unwrap();
        let sealed = seal_session(&k1, b"secret").unwrap();
        assert!(open_session(&k2, &sealed).is_err());
    }

    #[test]
    fn test_derive_session_key_symmetric() {
        let id_a = AliceId::new([1u8; 32]);
        let id_b = AliceId::new([2u8; 32]);
        let secret = b"shared-secret-bytes";
        let k1 = derive_session_key(&id_a, &id_b, secret);
        let k2 = derive_session_key(&id_a, &id_b, secret);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_id_fingerprint_different_ids() {
        let a = id_fingerprint(&AliceId::new([1u8; 32]));
        let b = id_fingerprint(&AliceId::new([2u8; 32]));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_sig_fingerprint_deterministic() {
        let sig = AliceSig::new([0xAB; 64]);
        let h1 = sig_fingerprint(&sig);
        let h2 = sig_fingerprint(&sig);
        assert_eq!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn test_sig_fingerprint_different_sigs() {
        let a = sig_fingerprint(&AliceSig::new([1u8; 64]));
        let b = sig_fingerprint(&AliceSig::new([2u8; 64]));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_keyed_token_hash_deterministic() {
        let key = [0x42u8; 32];
        let h1 = keyed_token_hash(&key, b"message");
        let h2 = keyed_token_hash(&key, b"message");
        assert_eq!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn test_keyed_token_hash_different_keys() {
        let h1 = keyed_token_hash(&[1u8; 32], b"msg");
        let h2 = keyed_token_hash(&[2u8; 32], b"msg");
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_secrets() {
        let id_a = AliceId::new([1u8; 32]);
        let id_b = AliceId::new([2u8; 32]);
        let k1 = derive_session_key(&id_a, &id_b, &[0xAAu8; 32]);
        let k2 = derive_session_key(&id_a, &id_b, &[0xBBu8; 32]);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_derive_key_short_secret() {
        let id_a = AliceId::new([1u8; 32]);
        let id_b = AliceId::new([2u8; 32]);
        let k = derive_session_key(&id_a, &id_b, b"short");
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn test_seal_empty_payload() {
        let key = Key::generate().unwrap();
        let sealed = seal_session(&key, b"").unwrap();
        let opened = open_session(&key, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    // --- Seed Recovery tests ---

    #[test]
    fn test_split_recover_identity() {
        let id = crate::Identity::gen().unwrap();
        let original_pub = id.id();
        let shards = split_seed(&id, 5, 3).unwrap();
        assert_eq!(shards.len(), 5);
        let recovered =
            recover_identity(&[shards[0].clone(), shards[2].clone(), shards[4].clone()]).unwrap();
        assert_eq!(recovered.id(), original_pub);
    }

    #[test]
    fn test_recovered_identity_can_sign() {
        let id = crate::Identity::gen().unwrap();
        let shards = split_seed(&id, 3, 2).unwrap();
        let recovered = recover_identity(&[shards[0].clone(), shards[1].clone()]).unwrap();
        let sig = recovered.sign(b"test message");
        assert!(crate::ok(&id.id(), b"test message", &sig));
    }

    #[test]
    fn test_split_different_combinations() {
        let id = crate::Identity::gen().unwrap();
        let shards = split_seed(&id, 5, 3).unwrap();
        let r1 =
            recover_identity(&[shards[0].clone(), shards[1].clone(), shards[2].clone()]).unwrap();
        let r2 =
            recover_identity(&[shards[2].clone(), shards[3].clone(), shards[4].clone()]).unwrap();
        assert_eq!(r1.id(), r2.id());
    }

    // --- HD Key Derivation tests ---

    #[test]
    fn test_derive_child_deterministic() {
        let parent = crate::Identity::gen().unwrap();
        let c1 = derive_child(&parent, 0);
        let c2 = derive_child(&parent, 0);
        assert_eq!(c1.id(), c2.id());
    }

    #[test]
    fn test_derive_child_different_indices() {
        let parent = crate::Identity::gen().unwrap();
        let c0 = derive_child(&parent, 0);
        let c1 = derive_child(&parent, 1);
        let c2 = derive_child(&parent, 2);
        assert_ne!(c0.id(), c1.id());
        assert_ne!(c1.id(), c2.id());
        assert_ne!(c0.id(), parent.id());
    }

    #[test]
    fn test_derive_child_can_sign() {
        let parent = crate::Identity::gen().unwrap();
        let child = derive_child(&parent, 42);
        let sig = child.sign(b"child signed");
        assert!(crate::ok(&child.id(), b"child signed", &sig));
        // Child signature should NOT verify against parent
        assert!(!crate::ok(&parent.id(), b"child signed", &sig));
    }

    #[test]
    fn test_derive_child_recoverable_from_parent_seed() {
        let parent = crate::Identity::gen().unwrap();
        let child = derive_child(&parent, 7);

        // Simulate recovery: recreate parent from seed, then re-derive child
        let parent_recovered = crate::Identity::from_seed(&parent.seed());
        let child_recovered = derive_child(&parent_recovered, 7);
        assert_eq!(child.id(), child_recovered.id());
    }
}
