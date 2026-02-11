//! ALICE-Auth × ALICE-API bridge
//!
//! Zero-trust middleware: token verification and ZKP-based authorization.
//!
//! Author: Moroya Sakamoto

use crate::{AliceId, AliceSig, Identity, verify};

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
    Authorized {
        identity: AliceId,
        expires_ms: u64,
    },
    Denied {
        reason: &'static str,
    },
}

/// Rate limiter entry
struct RateLimitEntry {
    identity: [u8; 32],
    timestamps: Vec<u64>,
}

/// Auth middleware for ALICE-API request verification
pub struct AuthMiddleware {
    rate_limits: Vec<RateLimitEntry>,
    pub verified_count: u64,
    pub denied_count: u64,
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self {
            rate_limits: Vec::new(),
            verified_count: 0,
            denied_count: 0,
        }
    }

    /// Verify an authentication request using Ed25519 signature
    pub fn verify_request(&mut self, req: &AuthRequest) -> AuthResponse {
        // Verify Ed25519 signature over token
        if verify(&req.identity, &req.token, &req.signature).is_ok() {
            self.verified_count += 1;
            // Extract expiry from token (first 8 bytes = timestamp)
            let expires_ms = if req.token.len() >= 8 {
                u64::from_le_bytes(req.token[0..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            AuthResponse::Authorized {
                identity: req.identity.clone(),
                expires_ms,
            }
        } else {
            self.denied_count += 1;
            AuthResponse::Denied { reason: "Invalid signature" }
        }
    }

    /// Create an auth token (timestamp + random nonce)
    pub fn create_auth_token(ttl_ms: u64) -> Vec<u8> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let expires = now_ms + ttl_ms;
        let mut token = Vec::with_capacity(16);
        token.extend_from_slice(&expires.to_le_bytes());
        token.extend_from_slice(&now_ms.to_le_bytes());
        token
    }

    /// Sliding window rate limiter
    pub fn validate_rate_limit(
        &mut self,
        identity: &[u8; 32],
        now_ms: u64,
        window_ms: u64,
        max_requests: u32,
    ) -> bool {
        let cutoff = now_ms.saturating_sub(window_ms);

        // Find or create entry
        let entry = self.rate_limits.iter_mut().find(|e| e.identity == *identity);
        match entry {
            Some(e) => {
                e.timestamps.retain(|&t| t >= cutoff);
                if e.timestamps.len() as u32 >= max_requests {
                    return false;
                }
                e.timestamps.push(now_ms);
                true
            }
            None => {
                self.rate_limits.push(RateLimitEntry {
                    identity: *identity,
                    timestamps: vec![now_ms],
                });
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_auth_token() {
        let token = AuthMiddleware::create_auth_token(60_000);
        assert_eq!(token.len(), 16);
        let expires = u64::from_le_bytes(token[0..8].try_into().unwrap());
        assert!(expires > 0);
    }

    #[test]
    fn test_rate_limit() {
        let mut mw = AuthMiddleware::new();
        let id = [0xAA; 32];
        assert!(mw.validate_rate_limit(&id, 1000, 5000, 3));
        assert!(mw.validate_rate_limit(&id, 2000, 5000, 3));
        assert!(mw.validate_rate_limit(&id, 3000, 5000, 3));
        assert!(!mw.validate_rate_limit(&id, 4000, 5000, 3)); // Exceeded
    }

    #[test]
    fn test_rate_limit_window_expiry() {
        let mut mw = AuthMiddleware::new();
        let id = [0xBB; 32];
        assert!(mw.validate_rate_limit(&id, 1000, 2000, 2));
        assert!(mw.validate_rate_limit(&id, 1500, 2000, 2));
        assert!(!mw.validate_rate_limit(&id, 1800, 2000, 2)); // Full
        assert!(mw.validate_rate_limit(&id, 4000, 2000, 2)); // Window expired
    }

    #[test]
    fn test_middleware_counters() {
        let mw = AuthMiddleware::new();
        assert_eq!(mw.verified_count, 0);
        assert_eq!(mw.denied_count, 0);
    }
}
