//! PyO3 Python Bindings for ALICE-Auth
//!
//! Ed25519 ZKP authentication for Python API servers.
//! Opaque handle pattern: private keys never leave Rust.
//!
//! Exposes: Identity, AliceId, NIZK, Endorsement, RotatingIdentity,
//! AuthToken, RevocationList, PolicyEngine, Shamir SSS, HD derivation.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

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
        let inner =
            Identity::gen().map_err(|e| PyRuntimeError::new_err(format!("keygen failed: {e}")))?;
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
    ///
    /// Raises `ValueError` when the message starts with the reserved prefix
    /// `alice-auth/`.
    fn sign(&self, message: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .sign(message)
            .map(|s| s.0.to_vec())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Sign 32-byte challenge (optimized path).
    fn sign32(&self, challenge: &[u8]) -> PyResult<Vec<u8>> {
        if challenge.len() != 32 {
            return Err(PyValueError::new_err("challenge must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(challenge);
        self.inner
            .sign32(&arr)
            .map(|s| s.0.to_vec())
            .map_err(|e| PyValueError::new_err(e.to_string()))
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

    fn __eq__(&self, other: &Self) -> bool {
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
        .map_err(|e| PyRuntimeError::new_err(format!("RNG failed: {e}")))
}

/// Server: create challenge for a client ID.
/// Returns (id_bytes, challenge_nonce).
#[pyfunction]
fn make_challenge(id: &PyAliceId) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let pending = crate::make_challenge(id.inner)
        .map_err(|e| PyRuntimeError::new_err(format!("challenge failed: {e}")))?;
    Ok((pending.id.as_bytes().to_vec(), pending.c.to_vec()))
}

/// Server: verify response and get session token.
/// Returns 16-byte session token or None on failure.
#[pyfunction]
fn check(id_bytes: &[u8], challenge_nonce: &[u8], signature: &[u8]) -> PyResult<Option<Vec<u8>>> {
    if id_bytes.len() != 32 || challenge_nonce.len() != 32 || signature.len() != 64 {
        return Err(PyValueError::new_err(
            "invalid input lengths (id=32, challenge=32, sig=64)",
        ));
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

    let mut items = Vec::with_capacity(ids.len());
    for i in 0..ids.len() {
        if ids[i].len() != 32 || signatures[i].len() != 64 {
            return Err(PyValueError::new_err(format!(
                "item {i}: id must be 32 bytes, sig must be 64 bytes"
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
// Schnorr NIZK Proof
// ============================================================================

/// Generate a Schnorr NIZK proof (true ZKP). Returns 64-byte proof.
#[pyfunction]
fn nizk_prove(identity: &PyIdentity, message: &[u8]) -> PyResult<Vec<u8>> {
    let proof = crate::nizk::prove(&identity.inner, message)
        .map_err(|e| PyRuntimeError::new_err(format!("NIZK prove failed: {e}")))?;
    Ok(proof.to_bytes().to_vec())
}

/// Verify a Schnorr NIZK proof. Returns True if valid.
#[pyfunction]
fn nizk_verify(id: &PyAliceId, message: &[u8], proof_bytes: &[u8]) -> PyResult<bool> {
    if proof_bytes.len() != 64 {
        return Err(PyValueError::new_err("proof must be exactly 64 bytes"));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(proof_bytes);
    let proof = crate::nizk::SchnorrProof::from_bytes(&arr);
    Ok(crate::nizk::verify_proof(&id.inner, message, &proof))
}

/// Batch-verify Schnorr NIZK proofs (GIL released).
#[pyfunction]
fn nizk_verify_batch(
    py: Python<'_>,
    ids: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    proofs: Vec<Vec<u8>>,
) -> PyResult<bool> {
    if ids.len() != messages.len() || ids.len() != proofs.len() {
        return Err(PyValueError::new_err("all arrays must have same length"));
    }

    let mut alice_ids = Vec::with_capacity(ids.len());
    let mut schnorr_proofs = Vec::with_capacity(ids.len());
    for i in 0..ids.len() {
        if ids[i].len() != 32 {
            return Err(PyValueError::new_err(format!(
                "item {i}: id must be 32 bytes"
            )));
        }
        if proofs[i].len() != 64 {
            return Err(PyValueError::new_err(format!(
                "item {i}: proof must be 64 bytes"
            )));
        }
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&ids[i]);
        alice_ids.push(AliceId::new(id_arr));
        let mut p_arr = [0u8; 64];
        p_arr.copy_from_slice(&proofs[i]);
        schnorr_proofs.push(crate::nizk::SchnorrProof::from_bytes(&p_arr));
    }

    let msgs = &messages;
    let aids = &alice_ids;
    let sps = &schnorr_proofs;
    let result = py.detach(|| {
        let items: Vec<(&AliceId, &[u8], &crate::nizk::SchnorrProof)> = aids
            .iter()
            .enumerate()
            .map(|(i, id)| (id, msgs[i].as_slice(), &sps[i]))
            .collect();
        crate::nizk::verify_batch(&items)
    });

    Ok(result)
}

// ============================================================================
// Endorsement (Trust Chain with Expiry)
// ============================================================================

/// Endorse a target identity. Returns (endorser, endorsed, sig, issued_ms, expires_ms).
#[pyfunction]
fn endorse(
    signer: &PyIdentity,
    target: &PyAliceId,
    now_ms: u64,
    ttl_ms: u64,
) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, u64, u64)> {
    let e = crate::endorse(&signer.inner, &target.inner, now_ms, ttl_ms).map_err(|e| {
        PyValueError::new_err(if e == crate::AuthError::E7 {
            "the target starts with the reserved prefix alice-auth/"
        } else {
            "now_ms + ttl_ms exceeds u64::MAX"
        })
    })?;
    Ok((
        e.endorser.0.to_vec(),
        e.endorsed.0.to_vec(),
        e.sig.0.to_vec(),
        e.issued_ms,
        e.expires_ms,
    ))
}

/// Verify an endorsement. Returns True if valid and not expired.
#[pyfunction]
fn verify_endorsement(
    endorser: &[u8],
    endorsed: &[u8],
    signature: &[u8],
    issued_ms: u64,
    expires_ms: u64,
    now_ms: u64,
) -> PyResult<bool> {
    if endorser.len() != 32 || endorsed.len() != 32 || signature.len() != 64 {
        return Err(PyValueError::new_err(
            "endorser=32, endorsed=32, sig=64 bytes required",
        ));
    }
    let mut er = [0u8; 32];
    er.copy_from_slice(endorser);
    let mut ed = [0u8; 32];
    ed.copy_from_slice(endorsed);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    let e = crate::Endorsement {
        endorser: AliceId(er),
        endorsed: AliceId(ed),
        sig: AliceSig(sig),
        issued_ms,
        expires_ms,
    };
    Ok(crate::verify_endorsement(&e, now_ms))
}

// ============================================================================
// RotatingIdentity
// ============================================================================

/// Identity with automatic key rotation and N-generation grace period.
#[pyclass(name = "RotatingIdentity")]
pub struct PyRotatingIdentity {
    inner: crate::RotatingIdentity,
}

#[pymethods]
impl PyRotatingIdentity {
    /// Create a new RotatingIdentity.
    #[new]
    fn new() -> PyResult<Self> {
        let inner = crate::RotatingIdentity::gen()
            .map_err(|e| PyRuntimeError::new_err(format!("keygen failed: {e}")))?;
        Ok(Self { inner })
    }

    /// Rotate to a new keypair. Returns the new public ID bytes.
    fn rotate(&mut self, now_ms: u64) -> PyResult<Vec<u8>> {
        let id = self
            .inner
            .rotate(now_ms)
            .map_err(|e| PyRuntimeError::new_err(format!("rotation failed: {e}")))?;
        Ok(id.0.to_vec())
    }

    /// Get the current public ID.
    fn current_id(&self) -> PyAliceId {
        PyAliceId {
            inner: self.inner.id(),
        }
    }

    /// Get all previous public IDs as list of (id_bytes, timestamp_ms).
    fn previous_ids(&self) -> Vec<(Vec<u8>, u64)> {
        self.inner
            .previous_ids()
            .into_iter()
            .map(|(id, ts)| (id.0.to_vec(), ts))
            .collect()
    }

    /// True when `id` is the current key or a retained previous key and the
    /// signature is that key's valid signature of the message.
    fn verify_any(&self, id: &PyAliceId, message: &[u8], signature: &[u8]) -> PyResult<bool> {
        if signature.len() != 64 {
            return Err(PyValueError::new_err("signature must be 64 bytes"));
        }
        let mut s = [0u8; 64];
        s.copy_from_slice(signature);
        Ok(self.inner.verify_any(&id.inner, message, &AliceSig(s)))
    }

    /// Number of retained previous generations.
    const fn generation_count(&self) -> usize {
        self.inner.generation_count()
    }

    fn __repr__(&self) -> String {
        format!(
            "RotatingIdentity(id={}, generations={})",
            self.inner.id(),
            self.inner.generation_count()
        )
    }
}

// ============================================================================
// AuthToken
// ============================================================================

/// Create an auth token. Returns 17 bytes.
#[pyfunction]
fn token_create(now_ms: u64, ttl_ms: u64) -> PyResult<Vec<u8>> {
    crate::api_bridge::AuthToken::new(now_ms, ttl_ms)
        .map(|t| t.to_bytes().to_vec())
        .map_err(|_| PyValueError::new_err("now_ms + ttl_ms exceeds u64::MAX"))
}

/// Parse an auth token. Returns (version, expires_ms, nonce_ms) or None.
#[pyfunction]
fn token_parse(data: &[u8]) -> Option<(u8, u64, u64)> {
    crate::api_bridge::AuthToken::from_bytes(data).map(|t| (t.version, t.expires_ms, t.nonce_ms))
}

/// Check if a token is expired.
#[pyfunction]
fn token_is_expired(data: &[u8], now_ms: u64) -> bool {
    match crate::api_bridge::AuthToken::from_bytes(data) {
        Some(t) => t.is_expired(now_ms),
        None => true,
    }
}

// ============================================================================
// RevocationList
// ============================================================================

/// Session token revocation list with constant-time checks.
#[pyclass(name = "RevocationList")]
pub struct PyRevocationList {
    inner: crate::api_bridge::RevocationList,
}

#[pymethods]
impl PyRevocationList {
    /// `capacity`: the most entries the list holds (default 10,000).
    #[new]
    #[pyo3(signature = (capacity=None))]
    fn new(capacity: Option<usize>) -> Self {
        Self {
            inner: capacity.map_or_else(
                crate::api_bridge::RevocationList::new,
                crate::api_bridge::RevocationList::with_capacity,
            ),
        }
    }

    /// Revoke a 16-byte session token.
    ///
    /// Raises RuntimeError when the list is full: the token is then not
    /// revoked, and no earlier entry is dropped.
    fn revoke(&mut self, token: &[u8], now_ms: u64) -> PyResult<()> {
        if token.len() != 16 {
            return Err(PyValueError::new_err("token must be 16 bytes"));
        }
        let mut t = [0u8; 16];
        t.copy_from_slice(token);
        self.inner
            .revoke(&t, now_ms)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Check if a token is revoked (constant-time).
    fn is_revoked(&self, token: &[u8]) -> PyResult<bool> {
        if token.len() != 16 {
            return Err(PyValueError::new_err("token must be 16 bytes"));
        }
        let mut t = [0u8; 16];
        t.copy_from_slice(token);
        Ok(self.inner.is_revoked(&t))
    }

    /// Purge tokens revoked more than ttl_ms ago. Returns count purged.
    fn auto_purge(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        self.inner.auto_purge(now_ms, ttl_ms)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!("RevocationList(len={})", self.inner.len())
    }
}

// ============================================================================
// PolicyEngine (RBAC)
// ============================================================================

/// Role-based access control engine.
#[pyclass(name = "PolicyEngine")]
pub struct PyPolicyEngine {
    inner: crate::api_bridge::PolicyEngine,
}

#[pymethods]
impl PyPolicyEngine {
    /// Create with read-only default role.
    #[new]
    fn new() -> Self {
        Self {
            inner: crate::api_bridge::PolicyEngine::new(crate::api_bridge::Role::READER),
        }
    }

    /// Assign a role mask to an identity (0=Read,1=Write,2=Admin,3=Execute bits).
    fn assign(&mut self, id: &PyAliceId, mask: u8) {
        self.inner
            .assign(&id.inner, crate::api_bridge::Role { mask });
    }

    /// Check if an identity has a permission (0=Read,1=Write,2=Admin,3=Execute).
    fn check_permission(&self, id: &PyAliceId, perm: u8) -> PyResult<bool> {
        let permission = match perm {
            0 => crate::api_bridge::Permission::Read,
            1 => crate::api_bridge::Permission::Write,
            2 => crate::api_bridge::Permission::Admin,
            3 => crate::api_bridge::Permission::Execute,
            _ => return Err(PyValueError::new_err("perm must be 0-3")),
        };
        Ok(self.inner.authorize(&id.inner, permission))
    }

    /// Revoke an identity's role (falls back to default).
    fn revoke_role(&mut self, id: &PyAliceId) {
        self.inner.revoke_role(&id.inner);
    }

    fn __repr__(&self) -> String {
        "PolicyEngine()".to_string()
    }
}

// ============================================================================
// HD Derivation
// ============================================================================

/// Derive a child identity from a parent + index.
#[pyfunction]
fn derive_child(parent: &PyIdentity, index: u32) -> PyIdentity {
    let child = crate::crypto_bridge::derive_child(&parent.inner, index);
    PyIdentity { inner: child }
}

// ============================================================================
// Player: id, key chain, grants, revocations
// ============================================================================

pyo3::create_exception!(
    alice_auth,
    GrantError,
    pyo3::exceptions::PyValueError,
    "A player value was refused; args are (code, reason), the code being GrantError::code."
);

fn grant_err(e: crate::GrantError) -> PyErr {
    GrantError::new_err((e.code(), e.to_string()))
}

fn arr<const N: usize>(b: &[u8], name: &str) -> PyResult<[u8; N]> {
    b.try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be {N} bytes")))
}

/// The 32-byte player id of the first key `genesis`.
#[pyfunction]
fn player_id_from_genesis(genesis: &[u8]) -> PyResult<Vec<u8>> {
    let g = AliceId(arr(genesis, "genesis")?);
    Ok(crate::PlayerId::from_genesis(&g).0.to_vec())
}

/// A rotation link (173 bytes) from `old`'s key to `new_key` at `issued_ms`.
#[pyfunction]
fn rotation_link_issue(
    old: &PyIdentity,
    player: &[u8],
    seq: u32,
    new_key: &[u8],
    issued_ms: u64,
) -> PyResult<Vec<u8>> {
    let link = crate::RotationLink::issue(
        &old.inner,
        crate::PlayerId(arr(player, "player")?),
        seq,
        AliceId(arr(new_key, "new_key")?),
        issued_ms,
    )
    .map_err(grant_err)?;
    Ok(link.to_bytes().to_vec())
}

/// Check rotation links (each 173 bytes) from the first key `genesis`; returns
/// `(player, current_key, since_ms)` or raises GrantError.
#[pyfunction]
fn player_chain_resolve(genesis: &[u8], links: Vec<Vec<u8>>) -> PyResult<(Vec<u8>, Vec<u8>, u64)> {
    let parsed = links
        .iter()
        .map(|l| crate::RotationLink::from_bytes(l))
        .collect::<Result<Vec<_>, _>>()
        .map_err(grant_err)?;
    let h = crate::resolve_chain(&AliceId(arr(genesis, "genesis")?), &parsed).map_err(grant_err)?;
    Ok((h.player.0.to_vec(), h.key.0.to_vec(), h.since_ms))
}

/// A grant (201 bytes) from `game` to `player` under `player_key`, valid
/// `now_ms <= t < now_ms + ttl_ms`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn grant_issue(
    game: &PyIdentity,
    player: &[u8],
    player_key: &[u8],
    scope: u64,
    now_ms: u64,
    ttl_ms: u64,
    nonce: &[u8],
) -> PyResult<Vec<u8>> {
    let g = crate::Grant::issue(
        &game.inner,
        crate::PlayerId(arr(player, "player")?),
        AliceId(arr(player_key, "player_key")?),
        scope,
        now_ms,
        ttl_ms,
        arr(nonce, "nonce")?,
    )
    .map_err(grant_err)?;
    Ok(g.to_bytes().to_vec())
}

/// Check a grant for `expected_game` at `now_ms` against the chain end and `revoked`;
/// returns `(player, scope, expires_ms)` or raises GrantError (the expiry itself is outside
/// the window).
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn grant_verify(
    grant: &[u8],
    expected_game: &[u8],
    head_player: &[u8],
    head_key: &[u8],
    head_since_ms: u64,
    now_ms: u64,
    revoked: &PyRevocationSet,
) -> PyResult<(Vec<u8>, u64, u64)> {
    let head = crate::ChainHead {
        player: crate::PlayerId(arr(head_player, "head_player")?),
        key: AliceId(arr(head_key, "head_key")?),
        since_ms: head_since_ms,
    };
    let expected = AliceId(arr(expected_game, "expected_game")?);
    let v = crate::Grant::from_bytes(grant)
        .and_then(|g| g.verify(&expected, &head, now_ms, &revoked.inner))
        .map_err(grant_err)?;
    Ok((v.player.0.to_vec(), v.scope, v.expires_ms))
}

/// The revocation (129 bytes) of `grant` by `game`, the game that issued it.
#[pyfunction]
fn revocation_issue(game: &PyIdentity, grant: &[u8], revoked_ms: u64) -> PyResult<Vec<u8>> {
    let r = crate::Grant::from_bytes(grant)
        .and_then(|g| crate::Revocation::issue(&game.inner, &g, revoked_ms))
        .map_err(grant_err)?;
    Ok(r.to_bytes().to_vec())
}

/// The revocations a verifier knows, with a fixed capacity.
#[pyclass(name = "RevocationSet")]
pub struct PyRevocationSet {
    inner: crate::RevocationSet,
}

#[pymethods]
impl PyRevocationSet {
    /// A set holding at most `capacity` revocations (at least 1).
    #[new]
    fn new(capacity: usize) -> PyResult<Self> {
        Ok(Self {
            inner: crate::RevocationSet::new(capacity).map_err(grant_err)?,
        })
    }

    /// Add a revocation (129 bytes) after checking its signature. Raises GrantError when it
    /// is not held. Full (-12) means it was NOT stored and the grant is still accepted:
    /// treat it as an emergency (a larger set, or stop accepting that game's grants).
    fn add(&mut self, revocation: &[u8]) -> PyResult<()> {
        let r = crate::Revocation::from_bytes(revocation).map_err(grant_err)?;
        self.inner.add(&r).map_err(grant_err)
    }

    /// Whether the grant `nonce` (16 bytes) of `game` (32 bytes) is revoked.
    fn contains(&self, game: &[u8], nonce: &[u8]) -> PyResult<bool> {
        Ok(self
            .inner
            .contains(&AliceId(arr(game, "game")?), &arr(nonce, "nonce")?))
    }

    /// Drop the revocations of grants expired at `now_ms`; returns how many.
    fn purge(&mut self, now_ms: u64) -> usize {
        self.inner.purge(now_ms)
    }

    #[getter]
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "RevocationSet(len={}, capacity={})",
            self.inner.len(),
            self.inner.capacity()
        )
    }
}

// ============================================================================
// Module
// ============================================================================

#[pymodule]
pub fn alice_auth(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // 型
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyAliceId>()?;
    m.add_class::<PyRotatingIdentity>()?;
    m.add_class::<PyRevocationList>()?;
    m.add_class::<PyPolicyEngine>()?;

    // 基本認証
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify32, m)?)?;
    m.add_function(wrap_pyfunction!(challenge, m)?)?;
    m.add_function(wrap_pyfunction!(make_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(verify_batch, m)?)?;

    // NIZK
    m.add_function(wrap_pyfunction!(nizk_prove, m)?)?;
    m.add_function(wrap_pyfunction!(nizk_verify, m)?)?;
    m.add_function(wrap_pyfunction!(nizk_verify_batch, m)?)?;

    // Endorsement
    m.add_function(wrap_pyfunction!(endorse, m)?)?;
    m.add_function(wrap_pyfunction!(verify_endorsement, m)?)?;

    // AuthToken
    m.add_function(wrap_pyfunction!(token_create, m)?)?;
    m.add_function(wrap_pyfunction!(token_parse, m)?)?;
    m.add_function(wrap_pyfunction!(token_is_expired, m)?)?;

    // HD鍵導出
    m.add_function(wrap_pyfunction!(derive_child, m)?)?;

    // player (id、鍵の鎖、grant、取消)
    m.add_class::<PyRevocationSet>()?;
    m.add("GrantError", m.py().get_type::<GrantError>())?;
    m.add_function(wrap_pyfunction!(player_id_from_genesis, m)?)?;
    m.add_function(wrap_pyfunction!(rotation_link_issue, m)?)?;
    m.add_function(wrap_pyfunction!(player_chain_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(grant_issue, m)?)?;
    m.add_function(wrap_pyfunction!(grant_verify, m)?)?;
    m.add_function(wrap_pyfunction!(revocation_issue, m)?)?;

    Ok(())
}
