//! PyO3 Python Bindings for ALICE-Auth
//!
//! Ed25519 ZKP authentication for Python API servers.
//! Opaque handle pattern: private keys never leave Rust.

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};

use crate::{AliceId, AliceSig, AuthResult, Identity, Pending};

// ============================================================================
// Identity (opaque handle — secret key stays in Rust)
// ============================================================================

/// Ed25519 identity (keypair). Secret key never leaves Rust.
#[pyclass(name = "Identity")]
pub struct PyIdentity {
    inner: Identity,
}

#[pymethods]
impl PyIdentity {
    /// Generate a new random identity.
    #[new]
    fn new() -> PyResult<Self> {
        let inner = Identity::gen().map_err(|e| PyRuntimeError::new_err(format!("keygen failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Recover identity from 32-byte seed.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err("seed must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        Ok(Self {
            inner: Identity::from_seed(&arr),
        })
    }

    /// Export secret seed (32 bytes). Keep private!
    fn seed(&self) -> Vec<u8> {
        self.inner.seed().to_vec()
    }

    /// Get public ID (32 bytes, safe to share).
    fn id(&self) -> PyAliceId {
        PyAliceId {
            inner: self.inner.id(),
        }
    }

    /// Sign arbitrary message. Returns 64-byte signature.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).0.to_vec()
    }

    /// Sign 32-byte challenge (optimized path).
    fn sign32(&self, challenge: &[u8]) -> PyResult<Vec<u8>> {
        if challenge.len() != 32 {
            return Err(PyValueError::new_err("challenge must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(challenge);
        Ok(self.inner.sign32(&arr).0.to_vec())
    }

    fn __repr__(&self) -> String {
        format!("Identity(id={})", self.inner.id())
    }
}

// ============================================================================
// AliceId (public key)
// ============================================================================

/// Public identity (Ed25519 public key, 32 bytes).
#[pyclass(name = "AliceId")]
#[derive(Clone)]
pub struct PyAliceId {
    pub(crate) inner: AliceId,
}

#[pymethods]
impl PyAliceId {
    /// Create from 32-byte public key.
    #[new]
    fn new(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 32 {
            return Err(PyValueError::new_err("AliceId must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self {
            inner: AliceId::new(arr),
        })
    }

    /// Get raw bytes.
    fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Get DID string: "alice://did:ed25519:<hex>"
    fn did(&self) -> String {
        let mut buf = [0u8; 84];
        self.inner.write_did(&mut buf).to_string()
    }

    fn __repr__(&self) -> String {
        format!("AliceId({})", self.inner)
    }

    fn __eq__(&self, other: &PyAliceId) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }
}

// ============================================================================
// Verification Functions
// ============================================================================

/// Verify Ed25519 signature.
///
/// Args:
///   id: 32-byte public key (or AliceId)
///   message: arbitrary bytes
///   signature: 64-byte signature
///
/// Returns: True if valid.
#[pyfunction]
fn verify(id: &PyAliceId, message: &[u8], signature: &[u8]) -> PyResult<bool> {
    if signature.len() != 64 {
        return Err(PyValueError::new_err("signature must be exactly 64 bytes"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);
    Ok(crate::ok(&id.inner, message, &AliceSig::new(sig_arr)))
}

/// Verify signature on 32-byte challenge.
#[pyfunction]
fn verify32(id: &PyAliceId, challenge: &[u8], signature: &[u8]) -> PyResult<bool> {
    if challenge.len() != 32 {
        return Err(PyValueError::new_err("challenge must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(PyValueError::new_err("signature must be 64 bytes"));
    }
    let mut c = [0u8; 32];
    c.copy_from_slice(challenge);
    let mut s = [0u8; 64];
    s.copy_from_slice(signature);
    Ok(crate::verify32(&id.inner, &c, &AliceSig::new(s)).is_ok())
}

// ============================================================================
// Protocol Functions
// ============================================================================

/// Generate a random 32-byte challenge nonce.
#[pyfunction]
fn challenge() -> PyResult<Vec<u8>> {
    crate::challenge()
        .map(|c| c.to_vec())
        .map_err(|e| PyRuntimeError::new_err(format!("RNG failed: {}", e)))
}

/// Server: create challenge for a client ID.
/// Returns (id_bytes, challenge_nonce).
#[pyfunction]
fn make_challenge(id: &PyAliceId) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let pending = crate::make_challenge(id.inner)
        .map_err(|e| PyRuntimeError::new_err(format!("challenge failed: {}", e)))?;
    Ok((pending.id.as_bytes().to_vec(), pending.c.to_vec()))
}

/// Server: verify response and get session token.
/// Returns 16-byte session token or None on failure.
#[pyfunction]
fn check(id_bytes: &[u8], challenge_nonce: &[u8], signature: &[u8]) -> PyResult<Option<Vec<u8>>> {
    if id_bytes.len() != 32 || challenge_nonce.len() != 32 || signature.len() != 64 {
        return Err(PyValueError::new_err("invalid input lengths (id=32, challenge=32, sig=64)"));
    }
    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(id_bytes);
    let mut c_arr = [0u8; 32];
    c_arr.copy_from_slice(challenge_nonce);
    let mut s_arr = [0u8; 64];
    s_arr.copy_from_slice(signature);

    let pending = Pending {
        id: AliceId::new(id_arr),
        c: c_arr,
    };
    let response = crate::Response {
        s: AliceSig::new(s_arr),
    };

    match crate::check(&pending, &response) {
        AuthResult::Ok(token) => Ok(Some(token.to_vec())),
        AuthResult::Fail => Ok(None),
    }
}

/// Batch verify multiple signatures (GIL released).
#[pyfunction]
fn verify_batch(
    py: Python<'_>,
    ids: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
) -> PyResult<Vec<bool>> {
    if ids.len() != messages.len() || ids.len() != signatures.len() {
        return Err(PyValueError::new_err("all arrays must have same length"));
    }

    // Pre-validate and convert
    let mut items = Vec::with_capacity(ids.len());
    for i in 0..ids.len() {
        if ids[i].len() != 32 || signatures[i].len() != 64 {
            return Err(PyValueError::new_err(format!(
                "item {}: id must be 32 bytes, sig must be 64 bytes",
                i
            )));
        }
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&ids[i]);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&signatures[i]);
        items.push((AliceId::new(id_arr), AliceSig::new(sig_arr)));
    }

    let msgs = &messages;
    let result = py.detach(|| {
        items
            .iter()
            .enumerate()
            .map(|(i, (id, sig))| crate::ok(id, &msgs[i], sig))
            .collect::<Vec<bool>>()
    });

    Ok(result)
}

// ============================================================================
// Module
// ============================================================================

#[pymodule]
pub fn alice_auth(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyAliceId>()?;

    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify32, m)?)?;
    m.add_function(wrap_pyfunction!(challenge, m)?)?;
    m.add_function(wrap_pyfunction!(make_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(verify_batch, m)?)?;

    Ok(())
}
