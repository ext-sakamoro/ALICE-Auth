//! ALICE-Crypto bridge: BLAKE3 token hashing + XChaCha20 session encryption
//!
//! Provides cryptographic operations for authentication tokens using
//! ALICE-Crypto's BLAKE3 hashing and XChaCha20-Poly1305 encryption.

use alice_crypto::{self as crypto, Key};
use crate::{AliceId, AliceSig};

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
/// Both peers derive the same key from (id_a XOR id_b) + shared_secret.
pub fn derive_session_key(id_a: &AliceId, id_b: &AliceId, shared_secret: &[u8]) -> Key {
    let mut context = [0u8; 64];
    for i in 0..32 {
        context[i] = id_a.0[i] ^ id_b.0[i];
    }
    context[32..64].copy_from_slice(shared_secret.get(..32).unwrap_or(&[0u8; 32]));
    let raw = crypto::derive_key("alice-auth-session-v1", &context);
    Key::from_bytes(raw)
}

/// Hash a signature for compact logging (avoids exposing full sig).
pub fn sig_fingerprint(sig: &AliceSig) -> crypto::Hash {
    crypto::hash(sig.as_bytes())
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
}
