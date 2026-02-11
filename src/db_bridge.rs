//! ALICE-Auth × ALICE-DB bridge
//!
//! Authentication audit log persistence with ZKP metadata.
//!
//! Author: Moroya Sakamoto

use alice_db::AliceDB;

/// Authentication action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthAction {
    Login = 0,
    Logout = 1,
    Challenge = 2,
    TokenRefresh = 3,
    KeyRotation = 4,
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
        if buf.len() < 43 { return None; }
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
                _ => return None,
            },
            success: buf[41] != 0,
            zkp_verified: buf[42] != 0,
        })
    }
}

/// Auth audit DB store
pub struct AuthDbStore {
    db: AliceDB,
    pub total_entries: u64,
}

impl AuthDbStore {
    pub fn new(db: AliceDB) -> Self {
        Self { db, total_entries: 0 }
    }

    /// Store an audit log entry
    pub fn store_audit(&mut self, log: &AuthAuditLog) {
        let mut key = [0u8; 40];
        key[0..32].copy_from_slice(&log.identity_hash);
        key[32..40].copy_from_slice(&log.timestamp_ms.to_be_bytes());
        self.db.put(&key, &log.to_bytes());
        self.total_entries += 1;
    }

    /// Query audit logs by identity hash and time range
    pub fn query_by_identity(&self, id_hash: &[u8; 32], from_ms: u64) -> Vec<AuthAuditLog> {
        let mut start = [0u8; 40];
        start[0..32].copy_from_slice(id_hash);
        start[32..40].copy_from_slice(&from_ms.to_be_bytes());
        let mut end = [0u8; 40];
        end[0..32].copy_from_slice(id_hash);
        end[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
        self.db
            .range(&start, &end)
            .filter_map(|(_k, v)| AuthAuditLog::from_bytes(&v))
            .collect()
    }

    /// Count failed auth attempts in a time window (for rate limiting)
    pub fn count_failed_attempts(&self, id_hash: &[u8; 32], from_ms: u64) -> u64 {
        self.query_by_identity(id_hash, from_ms)
            .iter()
            .filter(|log| !log.success)
            .count() as u64
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
    }
}
