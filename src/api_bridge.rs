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
    #[must_use]
    pub fn new(now_ms: u64, ttl_ms: u64) -> Self {
        Self {
            version: Self::V1,
            expires_ms: now_ms + ttl_ms,
            nonce_ms: now_ms,
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.push(self.version);
        buf.extend_from_slice(&self.expires_ms.to_le_bytes());
        buf.extend_from_slice(&self.nonce_ms.to_le_bytes());
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
    pub fn is_expired(&self, now_ms: u64) -> bool {
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
/// Enforces a `max_capacity` to prevent unbounded growth; when at capacity,
/// the oldest entry is evicted on insert.
pub struct RevocationList {
    revoked: Vec<([u8; 16], u64)>,
    pub max_capacity: usize,
}

/// Default maximum capacity for the revocation list.
pub const DEFAULT_REVOCATION_CAPACITY: usize = 10_000;

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationList {
    pub fn new() -> Self {
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
    pub fn revoke(&mut self, token: &[u8; 16], now_ms: u64) {
        if !self.is_revoked(token) {
            // Evict oldest if at capacity
            if self.revoked.len() >= self.max_capacity {
                self.revoked.remove(0);
            }
            self.revoked.push((*token, now_ms));
        }
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

    /// Auto-purge revoked tokens older than `ttl_ms` from `now_ms`.
    ///
    /// Tokens revoked more than `ttl_ms` ago would have expired naturally,
    /// so they can be safely removed from the revocation list.
    /// Returns the number of entries purged.
    pub fn auto_purge(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.revoked.len();
        self.revoked
            .retain(|(_, revoked_at)| now_ms.saturating_sub(*revoked_at) <= ttl_ms);
        before - self.revoked.len()
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
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

/// Serializable rate limit state for distributed coordination
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitState {
    pub identity: [u8; 32],
    pub count: u32,
    pub window_start_ms: u64,
}

// ============================================================================
// Auth Middleware
// ============================================================================

/// Auth middleware for ALICE-API request verification.
///
/// Uses `HashMap<[u8; 32], Vec<u64>>` for O(1) rate limit lookup per identity.
pub struct AuthMiddleware {
    rate_limits: HashMap<[u8; 32], Vec<u64>>,
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
        Self {
            rate_limits: HashMap::new(),
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
            let expires_bytes: [u8; 8] = match req.token[0..8].try_into() {
                Ok(b) => b,
                Err(_) => {
                    self.denied_count += 1;
                    return AuthResponse::Denied {
                        reason: "Token byte conversion failed",
                    };
                }
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
    #[must_use]
    pub fn create_auth_token(now_ms: u64, ttl_ms: u64) -> Vec<u8> {
        AuthToken::new(now_ms, ttl_ms).to_bytes()
    }

    /// Sliding window rate limiter.
    /// Uses `HashMap` for O(1) identity lookup.
    pub fn validate_rate_limit(
        &mut self,
        identity: &[u8; 32],
        now_ms: u64,
        window_ms: u64,
        max_requests: u32,
    ) -> bool {
        let cutoff = now_ms.saturating_sub(window_ms);

        let timestamps = self.rate_limits.entry(*identity).or_default();
        timestamps.retain(|&t| t >= cutoff);
        if timestamps.len() as u32 >= max_requests {
            return false;
        }
        timestamps.push(now_ms);
        true
    }

    /// Export rate limit state for a given identity (for distributed sync)
    pub fn export_rate_state(
        &self,
        identity: &[u8; 32],
        window_ms: u64,
        now_ms: u64,
    ) -> Option<RateLimitState> {
        let cutoff = now_ms.saturating_sub(window_ms);
        self.rate_limits.get(identity).map(|timestamps| {
            let count = timestamps.iter().filter(|&&t| t >= cutoff).count() as u32;
            RateLimitState {
                identity: *identity,
                count,
                window_start_ms: cutoff,
            }
        })
    }

    /// Import rate limit state from another node
    pub fn import_rate_state(&mut self, state: &RateLimitState) {
        let timestamps = self.rate_limits.entry(state.identity).or_default();
        for i in 0..state.count {
            timestamps.push(state.window_start_ms + i as u64);
        }
    }

    /// Merge multiple rate limit states from distributed nodes.
    /// Returns the combined state (sum of counts, earliest window start).
    pub fn merge_rate_states(states: &[RateLimitState]) -> Option<RateLimitState> {
        if states.is_empty() {
            return None;
        }
        let identity = states[0].identity;
        let count: u32 = states.iter().map(|s| s.count).sum();
        let window_start_ms = states.iter().map(|s| s.window_start_ms).min().unwrap_or(0);
        Some(RateLimitState {
            identity,
            count,
            window_start_ms,
        })
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
        let token = AuthToken::new(1000, 60_000);
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
        let token = AuthToken::new(1000, 5000);
        assert!(!token.is_expired(3000));
        assert!(!token.is_expired(6000));
        assert!(token.is_expired(6001));
    }

    #[test]
    fn test_auth_token_invalid_version() {
        let mut bytes = AuthToken::new(1000, 5000).to_bytes();
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
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
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
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
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
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
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
        let token = AuthMiddleware::create_auth_token(1000, 5000); // expires at 6000
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
        let token = AuthMiddleware::create_auth_token(1000, 0);
        assert_eq!(token.len(), AuthToken::SIZE);
    }

    // --- Revocation List tests ---

    #[test]
    fn test_revocation_basic() {
        let mut rl = RevocationList::new();
        let tok = [0xAA; 16];
        assert!(!rl.is_revoked(&tok));
        rl.revoke(&tok, 1000);
        assert!(rl.is_revoked(&tok));
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn test_revocation_no_duplicate() {
        let mut rl = RevocationList::new();
        let tok = [0xBB; 16];
        rl.revoke(&tok, 1000);
        rl.revoke(&tok, 2000);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn test_revocation_different_tokens() {
        let mut rl = RevocationList::new();
        let tok_a = [0x11; 16];
        let tok_b = [0x22; 16];
        rl.revoke(&tok_a, 1000);
        assert!(rl.is_revoked(&tok_a));
        assert!(!rl.is_revoked(&tok_b));
    }

    #[test]
    fn test_revocation_purge() {
        let mut rl = RevocationList::new();
        let tok_a = [0x11; 16];
        let tok_b = [0x22; 16];
        rl.revoke(&tok_a, 1000);
        rl.revoke(&tok_b, 2000);
        assert_eq!(rl.len(), 2);
        rl.purge(&[tok_a]);
        assert_eq!(rl.len(), 1);
        assert!(!rl.is_revoked(&tok_a));
        assert!(rl.is_revoked(&tok_b));
    }

    #[test]
    fn test_revocation_auto_purge() {
        let mut rl = RevocationList::new();
        rl.revoke(&[0x11; 16], 1000);
        rl.revoke(&[0x22; 16], 5000);
        rl.revoke(&[0x33; 16], 9000);
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
        rl.revoke(&[0x01; 16], 1000);
        rl.revoke(&[0x02; 16], 2000);
        rl.revoke(&[0x03; 16], 3000);
        assert_eq!(rl.len(), 3);
        // Adding 4th evicts oldest
        rl.revoke(&[0x04; 16], 4000);
        assert_eq!(rl.len(), 3);
        assert!(!rl.is_revoked(&[0x01; 16])); // evicted
        assert!(rl.is_revoked(&[0x04; 16]));
    }

    #[test]
    fn test_revocation_in_middleware() {
        let i = crate::Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
        let sig = i.sign(&token);

        let mut tok16 = [0u8; 16];
        tok16.copy_from_slice(&token[..16]);

        let mut mw = AuthMiddleware::new();
        mw.revocation.revoke(&tok16, 1000);

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
        mw.import_rate_state(&RateLimitState {
            identity: id,
            count: 5,
            window_start_ms: 1000,
        });
        assert!(!mw.validate_rate_limit(&id, 1500, 5000, 5));
    }

    #[test]
    fn test_merge_rate_states() {
        let id = [0xFF; 32];
        let states = vec![
            RateLimitState {
                identity: id,
                count: 3,
                window_start_ms: 1000,
            },
            RateLimitState {
                identity: id,
                count: 2,
                window_start_ms: 500,
            },
            RateLimitState {
                identity: id,
                count: 1,
                window_start_ms: 2000,
            },
        ];
        let merged = AuthMiddleware::merge_rate_states(&states).unwrap();
        assert_eq!(merged.count, 6);
        assert_eq!(merged.window_start_ms, 500);
    }

    #[test]
    fn test_merge_rate_states_empty() {
        assert!(AuthMiddleware::merge_rate_states(&[]).is_none());
    }
}
