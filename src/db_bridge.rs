//! ALICE-Auth audit log persistence
//!
//! Self-contained BTreeMap-backed audit store with binary serialization.
//! No external DB dependency — suitable for embedding in any ALICE service.
//!
//! Author: Moroya Sakamoto

extern crate std;
use std::collections::BTreeMap;
use std::vec::Vec;

/// Authentication action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthAction {
    Login = 0,
    Logout = 1,
    Challenge = 2,
    TokenRefresh = 3,
    KeyRotation = 4,
    Revocation = 5,
}

/// Authentication audit log entry
#[derive(Debug, Clone)]
pub struct AuthAuditLog {
    pub identity_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub action: AuthAction,
    pub success: bool,
    pub zkp_verified: bool,
}

impl AuthAuditLog {
    /// Serialize to 43-byte binary
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut buf = [0u8; 43];
        buf[0..32].copy_from_slice(&self.identity_hash);
        buf[32..40].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        buf[40] = self.action as u8;
        buf[41] = self.success as u8;
        buf[42] = self.zkp_verified as u8;
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 43 {
            return None;
        }
        let mut identity_hash = [0u8; 32];
        identity_hash.copy_from_slice(&buf[0..32]);
        Some(Self {
            identity_hash,
            timestamp_ms: u64::from_le_bytes(buf[32..40].try_into().ok()?),
            action: match buf[40] {
                0 => AuthAction::Login,
                1 => AuthAction::Logout,
                2 => AuthAction::Challenge,
                3 => AuthAction::TokenRefresh,
                4 => AuthAction::KeyRotation,
                5 => AuthAction::Revocation,
                _ => return None,
            },
            success: buf[41] != 0,
            zkp_verified: buf[42] != 0,
        })
    }
}

/// Auth audit store backed by BTreeMap (sorted by key for range queries)
///
/// Key = identity_hash(32) || timestamp_ms_be(8) = 40 bytes
/// Value = AuthAuditLog::to_bytes() = 43 bytes
pub struct AuthDbStore {
    store: BTreeMap<[u8; 40], [u8; 43]>,
    pub total_entries: u64,
}

impl Default for AuthDbStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthDbStore {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            total_entries: 0,
        }
    }

    /// Compose a 40-byte key: identity_hash(32) || timestamp_ms(8, big-endian)
    #[inline]
    fn make_key(id_hash: &[u8; 32], timestamp_ms: u64) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[0..32].copy_from_slice(id_hash);
        key[32..40].copy_from_slice(&timestamp_ms.to_be_bytes());
        key
    }

    /// Store an audit log entry.
    ///
    /// `total_entries` is synchronized with the actual store size after
    /// insertion, correctly handling duplicate key collisions.
    pub fn store_audit(&mut self, log: &AuthAuditLog) {
        let key = Self::make_key(&log.identity_hash, log.timestamp_ms);
        self.store.insert(key, log.to_bytes());
        self.total_entries = self.store.len() as u64;
    }

    /// Query audit logs by identity hash from a given timestamp onward
    pub fn query_by_identity(&self, id_hash: &[u8; 32], from_ms: u64) -> Vec<AuthAuditLog> {
        let start = Self::make_key(id_hash, from_ms);
        let end = Self::make_key(id_hash, u64::MAX);
        self.store
            .range(start..=end)
            .filter_map(|(_k, v)| AuthAuditLog::from_bytes(v))
            .collect()
    }

    /// Count failed auth attempts in a time window (for rate limiting)
    pub fn count_failed_attempts(&self, id_hash: &[u8; 32], from_ms: u64) -> u64 {
        self.query_by_identity(id_hash, from_ms)
            .iter()
            .filter(|log| !log.success)
            .count() as u64
    }

    /// Total number of entries stored
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the store is empty
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_serialization() {
        let log = AuthAuditLog {
            identity_hash: [0xAB; 32],
            timestamp_ms: 1234567890,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        };
        let bytes = log.to_bytes();
        let restored = AuthAuditLog::from_bytes(&bytes).unwrap();
        assert_eq!(restored.identity_hash, [0xAB; 32]);
        assert_eq!(restored.action, AuthAction::Login);
        assert!(restored.success);
        assert!(restored.zkp_verified);
    }

    #[test]
    fn test_action_values() {
        assert_eq!(AuthAction::Login as u8, 0);
        assert_eq!(AuthAction::KeyRotation as u8, 4);
        assert_eq!(AuthAction::Revocation as u8, 5);
    }

    #[test]
    fn test_all_action_roundtrip() {
        for (byte, expected) in [
            (0, AuthAction::Login),
            (1, AuthAction::Logout),
            (2, AuthAction::Challenge),
            (3, AuthAction::TokenRefresh),
            (4, AuthAction::KeyRotation),
            (5, AuthAction::Revocation),
        ] {
            let log = AuthAuditLog {
                identity_hash: [0; 32],
                timestamp_ms: 100,
                action: expected,
                success: false,
                zkp_verified: false,
            };
            let bytes = log.to_bytes();
            assert_eq!(bytes[40], byte);
            let restored = AuthAuditLog::from_bytes(&bytes).unwrap();
            assert_eq!(restored.action, expected);
        }
    }

    #[test]
    fn test_from_bytes_too_short() {
        assert!(AuthAuditLog::from_bytes(&[0u8; 42]).is_none());
        assert!(AuthAuditLog::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_from_bytes_invalid_action() {
        let mut buf = [0u8; 43];
        buf[40] = 99;
        assert!(AuthAuditLog::from_bytes(&buf).is_none());
    }

    #[test]
    fn test_success_and_zkp_flags() {
        let log = AuthAuditLog {
            identity_hash: [0; 32],
            timestamp_ms: 0,
            action: AuthAction::Login,
            success: false,
            zkp_verified: false,
        };
        let bytes = log.to_bytes();
        assert_eq!(bytes[41], 0);
        assert_eq!(bytes[42], 0);

        let log2 = AuthAuditLog {
            success: true,
            zkp_verified: true,
            ..log
        };
        let bytes2 = log2.to_bytes();
        assert_eq!(bytes2[41], 1);
        assert_eq!(bytes2[42], 1);
    }

    #[test]
    fn test_to_bytes_length() {
        let log = AuthAuditLog {
            identity_hash: [0xFF; 32],
            timestamp_ms: u64::MAX,
            action: AuthAction::Challenge,
            success: true,
            zkp_verified: false,
        };
        assert_eq!(log.to_bytes().len(), 43);
    }

    #[test]
    fn test_timestamp_roundtrip() {
        let ts = 0xDEAD_BEEF_CAFE_1234u64;
        let log = AuthAuditLog {
            identity_hash: [0; 32],
            timestamp_ms: ts,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        };
        let restored = AuthAuditLog::from_bytes(&log.to_bytes()).unwrap();
        assert_eq!(restored.timestamp_ms, ts);
    }

    #[test]
    fn test_store_and_query() {
        let mut store = AuthDbStore::new();
        let id = [0xAA; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 1000,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 2000,
            action: AuthAction::Logout,
            success: true,
            zkp_verified: false,
        });
        let logs = store.query_by_identity(&id, 0);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].action, AuthAction::Login);
        assert_eq!(logs[1].action, AuthAction::Logout);
    }

    #[test]
    fn test_store_query_time_range() {
        let mut store = AuthDbStore::new();
        let id = [0xBB; 32];
        for ts in [100, 200, 300, 400, 500] {
            store.store_audit(&AuthAuditLog {
                identity_hash: id,
                timestamp_ms: ts,
                action: AuthAction::Challenge,
                success: true,
                zkp_verified: false,
            });
        }
        let logs = store.query_by_identity(&id, 300);
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].timestamp_ms, 300);
    }

    #[test]
    fn test_count_failed_attempts() {
        let mut store = AuthDbStore::new();
        let id = [0xCC; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 100,
            action: AuthAction::Login,
            success: false,
            zkp_verified: false,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 200,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 300,
            action: AuthAction::Login,
            success: false,
            zkp_verified: false,
        });
        assert_eq!(store.count_failed_attempts(&id, 0), 2);
        assert_eq!(store.count_failed_attempts(&id, 200), 1);
    }

    #[test]
    fn test_store_separate_identities() {
        let mut store = AuthDbStore::new();
        let id_a = [0x11; 32];
        let id_b = [0x22; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id_a,
            timestamp_ms: 100,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id_b,
            timestamp_ms: 200,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        assert_eq!(store.query_by_identity(&id_a, 0).len(), 1);
        assert_eq!(store.query_by_identity(&id_b, 0).len(), 1);
        assert_eq!(store.total_entries, 2);
    }

    #[test]
    fn test_store_len_and_empty() {
        let mut store = AuthDbStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.store_audit(&AuthAuditLog {
            identity_hash: [0; 32],
            timestamp_ms: 0,
            action: AuthAction::Login,
            success: true,
            zkp_verified: false,
        });
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
}
