//! ALICE-Auth × ALICE-API bridge
//!
//! Zero-trust middleware: token verification, ZKP-based authorization,
//! session revocation, RBAC, and distributed rate limiting.
//!
//! Author: Moroya Sakamoto

extern crate std;

use crate::{verify, AliceId, AliceSig};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

// ============================================================================
// Auth Token (structured, versioned)
// ============================================================================

/// Structured authentication token.
///
/// Layout: version(1) || expires_ms(8) || nonce(8) = 17 bytes.
/// Version byte allows future format evolution without breaking changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken {
    pub version: u8,
    pub expires_ms: u64,
    pub nonce_ms: u64,
}

impl AuthToken {
    pub const V1: u8 = 1;
    pub const SIZE: usize = 17;

    /// Create a new auth token with explicit timestamp.
    ///
    /// # Errors
    ///
    /// [`crate::AuthError::E6`] when `now_ms + ttl_ms` exceeds `u64::MAX`.
    pub const fn new(now_ms: u64, ttl_ms: u64) -> crate::Result<Self> {
        match now_ms.checked_add(ttl_ms) {
            Some(expires_ms) => Ok(Self {
                version: Self::V1,
                expires_ms,
                nonce_ms: now_ms,
            }),
            None => Err(crate::AuthError::E6),
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.version;
        buf[1..9].copy_from_slice(&self.expires_ms.to_le_bytes());
        buf[9..17].copy_from_slice(&self.nonce_ms.to_le_bytes());
        buf
    }

    /// Parse from bytes.
    #[must_use]
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let version = buf[0];
        if version != Self::V1 {
            return None;
        }
        let expires_ms = u64::from_le_bytes(buf[1..9].try_into().ok()?);
        let nonce_ms = u64::from_le_bytes(buf[9..17].try_into().ok()?);
        Some(Self {
            version,
            expires_ms,
            nonce_ms,
        })
    }

    /// Check if the token has expired.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_ms
    }
}

// ============================================================================
// Auth Request / Response
// ============================================================================

/// Authentication request from client
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub token: Vec<u8>,
    pub signature: AliceSig,
    pub identity: AliceId,
}

/// Authentication response
#[derive(Debug, Clone)]
pub enum AuthResponse {
    Authorized { identity: AliceId, expires_ms: u64 },
    Denied { reason: &'static str },
}

// ============================================================================
// Session Revocation List
// ============================================================================

/// Revocation list for invalidating session tokens before TTL expiry.
///
/// Stores revoked 16-byte session tokens with timestamps. Check before
/// accepting any token. Uses `subtle::ConstantTimeEq` to guarantee
/// timing-attack resistance.
///
/// Holds at most `max_capacity` entries and never forgets one to make room:
/// when the list is full, [`Self::revoke`] refuses the new token with
/// [`RevokeError::Full`] and leaves the list unchanged, so a token that was
/// revoked stays revoked. An entry leaves the list only through
/// [`Self::purge`] (by value) or [`Self::auto_purge`] (by age), both called
/// explicitly by the owner of the list.
pub struct RevocationList {
    revoked: Vec<([u8; 16], u64)>,
    pub max_capacity: usize,
}

/// Default maximum capacity for the revocation list.
pub const DEFAULT_REVOCATION_CAPACITY: usize = 10_000;

/// Why [`RevocationList::revoke`] did not record a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevokeError {
    /// The list holds `capacity` entries. The token is not revoked: remove
    /// entries that can no longer be presented ([`RevocationList::auto_purge`])
    /// or raise `max_capacity`, then revoke it again.
    Full { capacity: usize },
}

impl core::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full { capacity } => write!(
                f,
                "revocation list is full ({capacity} entries); the token was not revoked"
            ),
        }
    }
}

impl std::error::Error for RevokeError {}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationList {
    pub const fn new() -> Self {
        Self {
            revoked: Vec::new(),
            max_capacity: DEFAULT_REVOCATION_CAPACITY,
        }
    }

    /// Create with a custom maximum capacity.
    #[must_use]
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            revoked: Vec::new(),
            max_capacity: max_capacity.max(1),
        }
    }

    /// Revoke a session token immediately with a timestamp.
    ///
    /// Revoking a token that is already revoked succeeds and keeps its first
    /// timestamp.
    ///
    /// # Errors
    ///
    /// [`RevokeError::Full`] when the list already holds `max_capacity`
    /// entries. The list is unchanged and the token is **not** revoked; no
    /// earlier entry is dropped to make room.
    pub fn revoke(&mut self, token: &[u8; 16], now_ms: u64) -> Result<(), RevokeError> {
        if self.is_revoked(token) {
            return Ok(());
        }
        if self.revoked.len() >= self.max_capacity {
            return Err(RevokeError::Full {
                capacity: self.max_capacity,
            });
        }
        self.revoked.push((*token, now_ms));
        Ok(())
    }

    /// Check if a session token has been revoked.
    /// Uses `subtle::ConstantTimeEq` to prevent timing attacks.
    pub fn is_revoked(&self, token: &[u8; 16]) -> bool {
        let token_bytes: &[u8] = token;
        self.revoked
            .iter()
            .any(|(r, _)| token_bytes.ct_eq(r.as_slice()).into())
    }

    /// Purge specific revoked tokens by value.
    pub fn purge(&mut self, expired_tokens: &[[u8; 16]]) {
        self.revoked.retain(|(r, _)| {
            let r_bytes: &[u8] = r;
            !expired_tokens
                .iter()
                .any(|e| r_bytes.ct_eq(e.as_slice()).into())
        });
    }

    /// Remove the entries revoked more than `ttl_ms` before `now_ms`.
    ///
    /// Pass the longest lifetime a token can have: a token revoked more than
    /// that long ago has expired and is refused by its expiry check, so its
    /// entry is no longer needed. A shorter `ttl_ms` makes still-valid revoked
    /// tokens valid again. An entry whose timestamp is after `now_ms` is kept.
    /// This is the only removal by age; the list never removes an entry on its
    /// own. Returns the number of entries removed.
    pub fn auto_purge(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.revoked.len();
        self.revoked
            .retain(|(_, revoked_at)| now_ms.saturating_sub(*revoked_at) <= ttl_ms);
        before - self.revoked.len()
    }

    pub const fn len(&self) -> usize {
        self.revoked.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

// ============================================================================
// RBAC (Role-Based Access Control)
// ============================================================================

/// Permission flags (bitfield, up to 8 permissions in u8)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    Read = 0,
    Write = 1,
    Admin = 2,
    Execute = 3,
}

/// Role with a set of permissions encoded as a bitmask
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    pub mask: u8,
}

impl Role {
    pub const NONE: Self = Self { mask: 0 };
    pub const READER: Self = Self {
        mask: 1 << Permission::Read as u8,
    };
    pub const WRITER: Self = Self {
        mask: (1 << Permission::Read as u8) | (1 << Permission::Write as u8),
    };
    pub const ADMIN: Self = Self { mask: 0b0000_1111 };

    #[inline]
    pub const fn has(&self, perm: Permission) -> bool {
        (self.mask & (1 << perm as u8)) != 0
    }

    #[inline]
    pub const fn with(mut self, perm: Permission) -> Self {
        self.mask |= 1 << perm as u8;
        self
    }
}

/// Policy engine mapping AliceId → Role.
///
/// Uses `HashMap<[u8; 32], Role>` for O(1) identity lookup.
pub struct PolicyEngine {
    policies: HashMap<[u8; 32], Role>,
    pub default_role: Role,
}

impl PolicyEngine {
    pub fn new(default_role: Role) -> Self {
        Self {
            policies: HashMap::new(),
            default_role,
        }
    }

    /// Assign a role to an identity
    pub fn assign(&mut self, id: &AliceId, role: Role) {
        self.policies.insert(*id.as_bytes(), role);
    }

    /// Remove an identity's role assignment (falls back to default)
    pub fn revoke_role(&mut self, id: &AliceId) {
        self.policies.remove(id.as_bytes());
    }

    /// Get the role for an identity
    pub fn role_of(&self, id: &AliceId) -> Role {
        self.policies
            .get(id.as_bytes())
            .copied()
            .unwrap_or(self.default_role)
    }

    /// Check if an identity has a specific permission
    pub fn authorize(&self, id: &AliceId, perm: Permission) -> bool {
        self.role_of(id).has(perm)
    }
}

// ============================================================================
// Rate Limiting (with distributed state export/import)
// ============================================================================

/// Serializable rate limit state for distributed coordination: `count`
/// requests of `identity` seen since `window_start_ms`, which matter to the
/// limit until `expires_ms` (the moment the last of them leaves its window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitState {
    pub identity: [u8; 32],
    pub count: u32,
    pub window_start_ms: u64,
    pub expires_ms: u64,
}

/// The identifier of a node that reports rate limit state.
pub type NodeId = [u8; 32];

/// Why rate limit state from another node was not taken as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateSyncError {
    /// The reported count is above the configured `max_remote_count`.
    OverCap { count: u32, cap: u32 },
    /// The identity already has reports from `max_remote_nodes` other nodes.
    TooManyNodes { cap: usize },
    /// A sum of counts would exceed `u32::MAX`.
    Overflow,
    /// The states to merge are for different identities.
    MixedIdentity,
    /// There are no states to merge.
    Empty,
    /// A configuration bound is zero or above its limit.
    InvalidConfig,
}

/// Bounds on what other nodes can make the limiter store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSyncConfig {
    remote_count: u32,
    remote_nodes: usize,
    report_ttl_ms: u64,
}

impl RateSyncConfig {
    /// The largest accepted `max_remote_count`.
    pub const MAX_REMOTE_COUNT: u32 = 1_000_000;
    /// The largest accepted `max_remote_nodes`.
    pub const MAX_REMOTE_NODES: usize = 4_096;
    /// The largest accepted `max_report_ttl_ms` (one day).
    pub const MAX_REPORT_TTL_MS: u64 = 86_400_000;

    /// A configuration accepting at most `max_remote_count` requests per report,
    /// reports from at most `max_remote_nodes` nodes per identity, and counting a
    /// report (or holding an identity for a refused one) for at most
    /// `max_report_ttl_ms` after it is received, whatever `expires_ms` it carries.
    ///
    /// # Errors
    ///
    /// [`RateSyncError::InvalidConfig`] when a bound is 0 or above its limit.
    pub const fn new(
        max_remote_count: u32,
        max_remote_nodes: usize,
        max_report_ttl_ms: u64,
    ) -> Result<Self, RateSyncError> {
        if max_remote_count == 0
            || max_remote_count > Self::MAX_REMOTE_COUNT
            || max_remote_nodes == 0
            || max_remote_nodes > Self::MAX_REMOTE_NODES
            || max_report_ttl_ms == 0
            || max_report_ttl_ms > Self::MAX_REPORT_TTL_MS
        {
            return Err(RateSyncError::InvalidConfig);
        }
        Ok(Self {
            remote_count: max_remote_count,
            remote_nodes: max_remote_nodes,
            report_ttl_ms: max_report_ttl_ms,
        })
    }

    #[must_use]
    pub const fn max_report_ttl_ms(&self) -> u64 {
        self.report_ttl_ms
    }

    #[must_use]
    pub const fn max_remote_count(&self) -> u32 {
        self.remote_count
    }

    #[must_use]
    pub const fn max_remote_nodes(&self) -> usize {
        self.remote_nodes
    }
}

impl Default for RateSyncConfig {
    /// 10,000 requests per report, 64 reporting nodes per identity, a report
    /// counted for at most 10 minutes after it is received.
    fn default() -> Self {
        Self {
            remote_count: 10_000,
            remote_nodes: 64,
            report_ttl_ms: 600_000,
        }
    }
}

/// A request count as u32, saturating (a count past `u32::MAX` reads as over any limit).
fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// What other nodes reported for one identity.
#[derive(Debug, Default)]
struct RemoteLoad {
    /// node -> (count, expires_ms)
    nodes: HashMap<NodeId, (u32, u64)>,
    /// Over the limit until this moment (a refused report), fail-closed.
    held_until_ms: u64,
}

impl RemoteLoad {
    /// Drop the reports whose counted requests no longer matter at `now_ms`.
    fn prune(&mut self, now_ms: u64) {
        self.nodes
            .retain(|_, &mut (_, expires_ms)| now_ms < expires_ms);
    }

    /// The reported requests that still matter at `now_ms`, or `None` when the
    /// identity is held over its limit or the sum would overflow.
    fn count(&self, now_ms: u64) -> Option<u32> {
        if now_ms < self.held_until_ms {
            return None;
        }
        self.nodes
            .values()
            .filter(|&&(_, expires_ms)| now_ms < expires_ms)
            .try_fold(0u32, |sum, &(count, _)| sum.checked_add(count))
    }
}

// ============================================================================
// Auth Middleware
// ============================================================================

/// Auth middleware for ALICE-API request verification.
///
/// Uses `HashMap<[u8; 32], Vec<u64>>` for O(1) rate limit lookup per identity.
pub struct AuthMiddleware {
    rate_limits: HashMap<[u8; 32], Vec<u64>>,
    remote: HashMap<[u8; 32], RemoteLoad>,
    rate_sync: RateSyncConfig,
    pub revocation: RevocationList,
    pub verified_count: u64,
    pub denied_count: u64,
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self::with_rate_sync(RateSyncConfig::default())
    }

    /// A middleware whose rate limiter accepts other nodes' state within `rate_sync`.
    #[must_use]
    pub fn with_rate_sync(rate_sync: RateSyncConfig) -> Self {
        Self {
            rate_limits: HashMap::new(),
            remote: HashMap::new(),
            rate_sync,
            revocation: RevocationList::new(),
            verified_count: 0,
            denied_count: 0,
        }
    }

    /// Verify an authentication request using Ed25519 signature.
    ///
    /// Checks: (1) signature validity, (2) token format, (3) revocation list,
    /// (4) token expiry, (5) returns authorized identity.
    pub fn verify_request(&mut self, req: &AuthRequest, now_ms: u64) -> AuthResponse {
        // Verify Ed25519 signature over token
        if verify(&req.identity, &req.token, &req.signature).is_err() {
            self.denied_count += 1;
            return AuthResponse::Denied {
                reason: "Invalid signature",
            };
        }

        // Token must carry at least 8 bytes encoding the expiry timestamp
        if req.token.len() < 8 {
            self.denied_count += 1;
            return AuthResponse::Denied {
                reason: "Token too short",
            };
        }

        // Check revocation list (if token is 16+ bytes, check first 16 as session token)
        if req.token.len() >= 16 {
            let mut tok16 = [0u8; 16];
            tok16.copy_from_slice(&req.token[..16]);
            if self.revocation.is_revoked(&tok16) {
                self.denied_count += 1;
                return AuthResponse::Denied {
                    reason: "Token revoked",
                };
            }
        }

        // Try structured token (v1) first, fallback to legacy
        let expires_ms = if let Some(token) = AuthToken::from_bytes(&req.token) {
            token.expires_ms
        } else {
            let expires_bytes: [u8; 8] = if let Ok(b) = req.token[0..8].try_into() {
                b
            } else {
                self.denied_count += 1;
                return AuthResponse::Denied {
                    reason: "Token byte conversion failed",
                };
            };
            u64::from_le_bytes(expires_bytes)
        };

        // Check token expiry
        if now_ms > expires_ms {
            self.denied_count += 1;
            return AuthResponse::Denied {
                reason: "Token expired",
            };
        }

        self.verified_count += 1;
        AuthResponse::Authorized {
            identity: req.identity,
            expires_ms,
        }
    }

    /// Create a structured auth token with explicit timestamp.
    ///
    /// # Errors
    ///
    /// [`crate::AuthError::E6`] when `now_ms + ttl_ms` exceeds `u64::MAX`.
    pub fn create_auth_token(now_ms: u64, ttl_ms: u64) -> crate::Result<Vec<u8>> {
        AuthToken::new(now_ms, ttl_ms).map(|t| t.to_bytes().to_vec())
    }

    /// Sliding window rate limiter: admits a request of `identity` at `now_ms`
    /// when its local requests in the last `window_ms` plus the requests other
    /// nodes reported that still matter are below `max_requests`. An identity
    /// held over its limit by a refused report, or whose reported total would
    /// overflow, is not admitted.
    pub fn validate_rate_limit(
        &mut self,
        identity: &[u8; 32],
        now_ms: u64,
        window_ms: u64,
        max_requests: u32,
    ) -> bool {
        let cutoff = now_ms.saturating_sub(window_ms);
        let remote = match self.remote.get_mut(identity) {
            Some(load) => {
                load.prune(now_ms);
                load.count(now_ms)
            }
            None => Some(0),
        };
        let timestamps = self.rate_limits.entry(*identity).or_default();
        timestamps.retain(|&t| t >= cutoff);
        let local = count_u32(timestamps.len());
        match remote.and_then(|r| r.checked_add(local)) {
            Some(total) if total < max_requests => {
                timestamps.push(now_ms);
                true
            }
            _ => false,
        }
    }

    /// Export this node's own requests of `identity` in the last `window_ms`
    /// (reports received from other nodes are not re-exported).
    pub fn export_rate_state(
        &self,
        identity: &[u8; 32],
        window_ms: u64,
        now_ms: u64,
    ) -> Option<RateLimitState> {
        let cutoff = now_ms.saturating_sub(window_ms);
        self.rate_limits.get(identity).map(|timestamps| {
            let count = timestamps.iter().filter(|&&t| t >= cutoff).count();
            RateLimitState {
                identity: *identity,
                count: count_u32(count),
                window_start_ms: cutoff,
                expires_ms: now_ms.saturating_add(window_ms),
            }
        })
    }

    /// Take `node`'s report of `state.identity`, replacing that node's earlier
    /// report (a replay is not added twice). A report counts until its
    /// `expires_ms`, but never beyond `now_ms + max_report_ttl_ms`; one that has
    /// already expired at `now_ms` is ignored.
    ///
    /// # Errors
    ///
    /// [`RateSyncError::OverCap`] when the count is above `max_remote_count`, or
    /// [`RateSyncError::TooManyNodes`] when the identity already has reports
    /// from `max_remote_nodes` other nodes. Nothing is stored, no earlier report
    /// is dropped, and the identity is held over its limit until the refused
    /// report's `expires_ms`, bounded the same way (fail-closed: refused load is
    /// not forgotten, but cannot hold the identity indefinitely).
    pub fn import_rate_state(
        &mut self,
        node: &NodeId,
        state: &RateLimitState,
        now_ms: u64,
    ) -> Result<(), RateSyncError> {
        // the receiver bounds how long any report can count: a report cannot
        // lock an identity beyond now + max_report_ttl_ms
        let expires_ms = state
            .expires_ms
            .min(now_ms.saturating_add(self.rate_sync.report_ttl_ms));
        if now_ms >= expires_ms {
            return Ok(());
        }
        let cap = self.rate_sync.remote_count;
        let max_nodes = self.rate_sync.remote_nodes;
        let load = self.remote.entry(state.identity).or_default();
        load.prune(now_ms);
        let refusal = if state.count > cap {
            Some(RateSyncError::OverCap {
                count: state.count,
                cap,
            })
        } else if !load.nodes.contains_key(node) && load.nodes.len() >= max_nodes {
            Some(RateSyncError::TooManyNodes { cap: max_nodes })
        } else {
            None
        };
        if let Some(e) = refusal {
            load.held_until_ms = load.held_until_ms.max(expires_ms);
            return Err(e);
        }
        load.nodes.insert(*node, (state.count, expires_ms));
        Ok(())
    }

    /// Merge rate limit states of one identity from several nodes: the sum of
    /// the counts, the earliest window start and the latest expiry.
    ///
    /// # Errors
    ///
    /// [`RateSyncError::Empty`], [`RateSyncError::MixedIdentity`], or
    /// [`RateSyncError::Overflow`] when the counts sum past `u32::MAX`.
    pub fn merge_rate_states(states: &[RateLimitState]) -> Result<RateLimitState, RateSyncError> {
        let first = states.first().ok_or(RateSyncError::Empty)?;
        let mut merged = first.clone();
        for s in &states[1..] {
            if s.identity != first.identity {
                return Err(RateSyncError::MixedIdentity);
            }
            merged.count = merged
                .count
                .checked_add(s.count)
                .ok_or(RateSyncError::Overflow)?;
            merged.window_start_ms = merged.window_start_ms.min(s.window_start_ms);
            merged.expires_ms = merged.expires_ms.max(s.expires_ms);
        }
        Ok(merged)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- AuthToken tests ---

    #[test]
    fn test_auth_token_roundtrip() {
        let token = AuthToken::new(1000, 60_000).unwrap();
        assert_eq!(token.version, 1);
        assert_eq!(token.expires_ms, 61_000);
        assert_eq!(token.nonce_ms, 1000);

        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), AuthToken::SIZE);

        let restored = AuthToken::from_bytes(&bytes).unwrap();
        assert_eq!(restored, token);
    }

    #[test]
    fn test_auth_token_expired() {
        let token = AuthToken::new(1000, 5000).unwrap();
        assert!(!token.is_expired(3000));
        assert!(!token.is_expired(6000));
        assert!(token.is_expired(6001));
    }

    #[test]
    fn test_auth_token_invalid_version() {
        let mut bytes = AuthToken::new(1000, 5000).unwrap().to_bytes();
        bytes[0] = 99;
        assert!(AuthToken::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_auth_token_too_short() {
        assert!(AuthToken::from_bytes(&[1, 2, 3]).is_none());
    }

    // --- Token & Middleware tests ---

    #[test]
    fn test_create_auth_token() {
        let token = AuthMiddleware::create_auth_token(1000, 60_000).unwrap();
        assert_eq!(token.len(), AuthToken::SIZE);
        let parsed = AuthToken::from_bytes(&token).unwrap();
        assert_eq!(parsed.expires_ms, 61_000);
    }

    #[test]
    fn test_rate_limit() {
        let mut mw = AuthMiddleware::new();
        let id = [0xAA; 32];
        assert!(mw.validate_rate_limit(&id, 1000, 5000, 3));
        assert!(mw.validate_rate_limit(&id, 2000, 5000, 3));
        assert!(mw.validate_rate_limit(&id, 3000, 5000, 3));
        assert!(!mw.validate_rate_limit(&id, 4000, 5000, 3));
    }

    #[test]
    fn test_rate_limit_window_expiry() {
        let mut mw = AuthMiddleware::new();
        let id = [0xBB; 32];
        assert!(mw.validate_rate_limit(&id, 1000, 2000, 2));
        assert!(mw.validate_rate_limit(&id, 1500, 2000, 2));
        assert!(!mw.validate_rate_limit(&id, 1800, 2000, 2));
        assert!(mw.validate_rate_limit(&id, 4000, 2000, 2));
    }

    #[test]
    fn test_middleware_counters() {
        let mw = AuthMiddleware::new();
        assert_eq!(mw.verified_count, 0);
        assert_eq!(mw.denied_count, 0);
    }

    #[test]
    fn test_verify_valid_request() {
        let i = crate::Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000).unwrap();
        let sig = i.sign(&token);
        let req = AuthRequest {
            token,
            signature: sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        let resp = mw.verify_request(&req, 2000);
        assert!(matches!(resp, AuthResponse::Authorized { .. }));
        assert_eq!(mw.verified_count, 1);
        assert_eq!(mw.denied_count, 0);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let i = crate::Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000).unwrap();
        let bad_sig = crate::AliceSig::new([0u8; 64]);
        let req = AuthRequest {
            token,
            signature: bad_sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        let resp = mw.verify_request(&req, 2000);
        assert!(matches!(
            resp,
            AuthResponse::Denied {
                reason: "Invalid signature"
            }
        ));
        assert_eq!(mw.denied_count, 1);
    }

    #[test]
    fn test_verify_short_token() {
        let i = crate::Identity::gen().unwrap();
        let short_token = vec![1, 2, 3];
        let sig = i.sign(&short_token);
        let req = AuthRequest {
            token: short_token,
            signature: sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        let resp = mw.verify_request(&req, 2000);
        assert!(matches!(
            resp,
            AuthResponse::Denied {
                reason: "Token too short"
            }
        ));
    }

    #[test]
    fn test_verify_expired_token() {
        let i = crate::Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 5000).unwrap(); // expires at 6000
        let sig = i.sign(&token);
        let req = AuthRequest {
            token,
            signature: sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        // Before expiry: OK
        let resp = mw.verify_request(&req, 5000);
        assert!(matches!(resp, AuthResponse::Authorized { .. }));
        // After expiry: denied
        let resp = mw.verify_request(&req, 6001);
        assert!(matches!(
            resp,
            AuthResponse::Denied {
                reason: "Token expired"
            }
        ));
    }

    #[test]
    fn test_rate_limit_separate_identities() {
        let mut mw = AuthMiddleware::new();
        let id_a = [0xAA; 32];
        let id_b = [0xBB; 32];
        assert!(mw.validate_rate_limit(&id_a, 1000, 5000, 1));
        assert!(!mw.validate_rate_limit(&id_a, 2000, 5000, 1));
        assert!(mw.validate_rate_limit(&id_b, 2000, 5000, 1));
    }

    #[test]
    fn test_auth_response_variants() {
        let auth = AuthResponse::Authorized {
            identity: crate::AliceId::new([0; 32]),
            expires_ms: 1000,
        };
        assert!(matches!(
            auth,
            AuthResponse::Authorized {
                expires_ms: 1000,
                ..
            }
        ));
        let denied = AuthResponse::Denied { reason: "test" };
        assert!(matches!(denied, AuthResponse::Denied { reason: "test" }));
    }

    #[test]
    fn test_create_auth_token_zero_ttl() {
        let token = AuthMiddleware::create_auth_token(1000, 0).unwrap();
        assert_eq!(token.len(), AuthToken::SIZE);
    }

    // --- Revocation List tests ---

    #[test]
    fn test_revocation_basic() {
        let mut rl = RevocationList::new();
        let tok = [0xAA; 16];
        assert!(!rl.is_revoked(&tok));
        rl.revoke(&tok, 1000).unwrap();
        assert!(rl.is_revoked(&tok));
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn test_revocation_no_duplicate() {
        let mut rl = RevocationList::new();
        let tok = [0xBB; 16];
        rl.revoke(&tok, 1000).unwrap();
        rl.revoke(&tok, 2000).unwrap();
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn test_revocation_different_tokens() {
        let mut rl = RevocationList::new();
        let tok_a = [0x11; 16];
        let tok_b = [0x22; 16];
        rl.revoke(&tok_a, 1000).unwrap();
        assert!(rl.is_revoked(&tok_a));
        assert!(!rl.is_revoked(&tok_b));
    }

    #[test]
    fn test_revocation_purge() {
        let mut rl = RevocationList::new();
        let tok_a = [0x11; 16];
        let tok_b = [0x22; 16];
        rl.revoke(&tok_a, 1000).unwrap();
        rl.revoke(&tok_b, 2000).unwrap();
        assert_eq!(rl.len(), 2);
        rl.purge(&[tok_a]);
        assert_eq!(rl.len(), 1);
        assert!(!rl.is_revoked(&tok_a));
        assert!(rl.is_revoked(&tok_b));
    }

    #[test]
    fn test_revocation_auto_purge() {
        let mut rl = RevocationList::new();
        rl.revoke(&[0x11; 16], 1000).unwrap();
        rl.revoke(&[0x22; 16], 5000).unwrap();
        rl.revoke(&[0x33; 16], 9000).unwrap();
        // Purge entries older than 5000ms from now_ms=10000
        let purged = rl.auto_purge(10_000, 5000);
        assert_eq!(purged, 1); // [0x11] at 1000 is >5000ms old
        assert_eq!(rl.len(), 2);
        assert!(!rl.is_revoked(&[0x11; 16]));
        assert!(rl.is_revoked(&[0x22; 16]));
        assert!(rl.is_revoked(&[0x33; 16]));
    }

    #[test]
    fn test_revocation_max_capacity() {
        let mut rl = RevocationList::with_capacity(3);
        rl.revoke(&[0x01; 16], 1000).unwrap();
        rl.revoke(&[0x02; 16], 2000).unwrap();
        rl.revoke(&[0x03; 16], 3000).unwrap();
        assert_eq!(rl.len(), 3);
        // A 4th token is refused; no earlier entry is dropped
        assert_eq!(
            rl.revoke(&[0x04; 16], 4000),
            Err(RevokeError::Full { capacity: 3 })
        );
        assert_eq!(rl.len(), 3);
        assert!(rl.is_revoked(&[0x01; 16]));
        assert!(!rl.is_revoked(&[0x04; 16]));
        // An already revoked token still succeeds when the list is full
        assert_eq!(rl.revoke(&[0x02; 16], 5000), Ok(()));
    }

    #[test]
    fn test_revocation_in_middleware() {
        let i = crate::Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000).unwrap();
        let sig = i.sign(&token);

        let mut tok16 = [0u8; 16];
        tok16.copy_from_slice(&token[..16]);

        let mut mw = AuthMiddleware::new();
        mw.revocation.revoke(&tok16, 1000).unwrap();

        let req = AuthRequest {
            token,
            signature: sig,
            identity: i.id(),
        };
        let resp = mw.verify_request(&req, 2000);
        assert!(matches!(
            resp,
            AuthResponse::Denied {
                reason: "Token revoked"
            }
        ));
    }

    // --- RBAC tests ---

    #[test]
    fn test_role_presets() {
        assert!(!Role::NONE.has(Permission::Read));
        assert!(Role::READER.has(Permission::Read));
        assert!(!Role::READER.has(Permission::Write));
        assert!(Role::WRITER.has(Permission::Read));
        assert!(Role::WRITER.has(Permission::Write));
        assert!(Role::ADMIN.has(Permission::Read));
        assert!(Role::ADMIN.has(Permission::Write));
        assert!(Role::ADMIN.has(Permission::Admin));
        assert!(Role::ADMIN.has(Permission::Execute));
    }

    #[test]
    fn test_role_with() {
        let role = Role::NONE.with(Permission::Read).with(Permission::Execute);
        assert!(role.has(Permission::Read));
        assert!(!role.has(Permission::Write));
        assert!(role.has(Permission::Execute));
    }

    #[test]
    fn test_policy_engine_assign_and_authorize() {
        let mut engine = PolicyEngine::new(Role::NONE);
        let i = crate::Identity::gen().unwrap();
        let id = i.id();

        assert!(!engine.authorize(&id, Permission::Read));

        engine.assign(&id, Role::WRITER);
        assert!(engine.authorize(&id, Permission::Read));
        assert!(engine.authorize(&id, Permission::Write));
        assert!(!engine.authorize(&id, Permission::Admin));
    }

    #[test]
    fn test_policy_engine_default_role() {
        let engine = PolicyEngine::new(Role::READER);
        let i = crate::Identity::gen().unwrap();
        assert!(engine.authorize(&i.id(), Permission::Read));
        assert!(!engine.authorize(&i.id(), Permission::Write));
    }

    #[test]
    fn test_policy_engine_revoke_role() {
        let mut engine = PolicyEngine::new(Role::NONE);
        let i = crate::Identity::gen().unwrap();
        let id = i.id();
        engine.assign(&id, Role::ADMIN);
        assert!(engine.authorize(&id, Permission::Admin));
        engine.revoke_role(&id);
        assert!(!engine.authorize(&id, Permission::Admin));
    }

    #[test]
    fn test_policy_engine_reassign() {
        let mut engine = PolicyEngine::new(Role::NONE);
        let i = crate::Identity::gen().unwrap();
        let id = i.id();
        engine.assign(&id, Role::ADMIN);
        engine.assign(&id, Role::READER);
        assert!(engine.authorize(&id, Permission::Read));
        assert!(!engine.authorize(&id, Permission::Admin));
    }

    // --- Distributed Rate Limiting tests ---

    #[test]
    fn test_export_rate_state() {
        let mut mw = AuthMiddleware::new();
        let id = [0xDD; 32];
        mw.validate_rate_limit(&id, 1000, 5000, 10);
        mw.validate_rate_limit(&id, 2000, 5000, 10);
        mw.validate_rate_limit(&id, 3000, 5000, 10);
        let state = mw.export_rate_state(&id, 5000, 5000).unwrap();
        assert_eq!(state.identity, id);
        assert_eq!(state.count, 3);
    }

    #[test]
    fn test_import_rate_state() {
        let mut mw = AuthMiddleware::new();
        let id = [0xEE; 32];
        mw.import_rate_state(
            &[1; 32],
            &RateLimitState {
                identity: id,
                count: 5,
                window_start_ms: 1000,
                expires_ms: 6000,
            },
            1000,
        )
        .unwrap();
        assert!(!mw.validate_rate_limit(&id, 1500, 5000, 5));
    }

    #[test]
    fn test_merge_rate_states() {
        let id = [0xFF; 32];
        let st = |count, window_start_ms, expires_ms| RateLimitState {
            identity: id,
            count,
            window_start_ms,
            expires_ms,
        };
        let states = vec![st(3, 1000, 6000), st(2, 500, 5500), st(1, 2000, 7000)];
        let merged = AuthMiddleware::merge_rate_states(&states).unwrap();
        assert_eq!(merged.count, 6);
        assert_eq!(merged.window_start_ms, 500);
        assert_eq!(merged.expires_ms, 7000);
    }

    /// `RateSyncConfig` bounds keep the reported total below `u32::MAX`
    /// (4,096 nodes x 1,000,000), so the checked sum is reached here only with
    /// entries built past those bounds: an overflowing total holds the identity
    #[test]
    fn test_remote_total_overflow_is_none() {
        let mut load = RemoteLoad::default();
        load.nodes.insert([1; 32], (u32::MAX, 100));
        load.nodes.insert([2; 32], (1, 100));
        assert_eq!(load.count(0), None);
        load.nodes.remove(&[2; 32]);
        assert_eq!(load.count(0), Some(u32::MAX));
    }

    #[test]
    fn test_count_u32_saturates() {
        assert_eq!(count_u32(7), 7);
        assert_eq!(count_u32(u32::MAX as usize), u32::MAX);
        // one past u32::MAX truncates to 0 with `as`: it must saturate instead
        #[cfg(target_pointer_width = "64")]
        assert_eq!(count_u32(u32::MAX as usize + 1), u32::MAX);
        assert_eq!(count_u32(usize::MAX), u32::MAX);
    }

    #[test]
    fn test_merge_rate_states_empty() {
        assert_eq!(
            AuthMiddleware::merge_rate_states(&[]),
            Err(RateSyncError::Empty)
        );
    }
}
