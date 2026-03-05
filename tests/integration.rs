// ALICE-Auth 統合テスト
// 追加テスト: 認証フロー・トークン・RBAC・監査ログ・ソーシャルリカバリ等

use alice_auth::{
    approve_recovery, check, check_timed, ct_eq, ct_eq_n, endorse, make_challenge,
    make_timed_challenge, ok, rand, respond, verify, verify_chain, verify_endorsement,
    verify_recovery_approval, AliceId, AliceSig, AuthError, AuthResult, Challenge, Identity,
    Pending, CHALLENGE_TTL_MS,
};

// ============================================================================
// AliceId
// ============================================================================

#[test]
fn alice_id_display_starts_with_did_prefix() {
    let id = Identity::gen().unwrap();
    let s = format!("{}", id.id());
    assert!(s.starts_with("alice://did:ed25519:"));
    assert_eq!(s.len(), 84);
}

#[test]
fn alice_id_to_did_bytes_matches_write_did() {
    let id = Identity::gen().unwrap();
    let mut buf = [0u8; 84];
    id.id().write_did(&mut buf);
    let from_method = id.id().to_did_bytes();
    assert_eq!(from_method, buf);
}

#[test]
fn alice_id_zero_key_did() {
    // AliceId with all-zero bytes should still produce a 84-byte DID string
    let id = AliceId::new([0u8; 32]);
    let did = id.to_did_bytes();
    assert_eq!(did.len(), 84);
    let s = core::str::from_utf8(&did).unwrap();
    assert!(s.starts_with("alice://did:ed25519:"));
    // suffix should be 64 hex zeros
    assert_eq!(
        &s[20..],
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn alice_id_n_constant() {
    assert_eq!(AliceId::N, 32);
}

#[test]
fn alice_id_did_n_constant() {
    assert_eq!(AliceId::DID_N, 84);
}

#[test]
fn alice_sig_n_constant() {
    assert_eq!(AliceSig::N, 64);
}

// ============================================================================
// verify / ok
// ============================================================================

#[test]
fn verify_returns_e3_for_bad_sig() {
    let id = Identity::gen().unwrap();
    let bad_sig = AliceSig::new([0u8; 64]);
    let err = verify(&id.id(), b"msg", &bad_sig).unwrap_err();
    assert_eq!(err, AuthError::E3);
}

#[test]
fn verify_returns_err_for_invalid_pubkey() {
    // Certain byte patterns are not valid compressed Edwards points; verify returns Err.
    // The specific error code (E1 vs E3) depends on whether point decompression fails
    // before or after signature parsing. We simply assert it is an error.
    let bad_id = AliceId::new([0xFF; 32]);
    let sig = AliceSig::new([0u8; 64]);
    assert!(verify(&bad_id, b"msg", &sig).is_err());
}

#[test]
fn ok_returns_true_for_correct_sig() {
    let id = Identity::gen().unwrap();
    let msg = b"alice auth message";
    let sig = id.sign(msg);
    assert!(ok(&id.id(), msg, &sig));
}

#[test]
fn ok_returns_false_wrong_message() {
    let id = Identity::gen().unwrap();
    let sig = id.sign(b"original");
    assert!(!ok(&id.id(), b"tampered", &sig));
}

// ============================================================================
// rand
// ============================================================================

#[test]
fn rand_32_is_random() {
    let a = rand::<32>().unwrap();
    let b = rand::<32>().unwrap();
    assert_ne!(a, b);
}

#[test]
fn rand_16_produces_16_bytes() {
    let r = rand::<16>().unwrap();
    assert_eq!(r.len(), 16);
}

// ============================================================================
// Protocol structs
// ============================================================================

#[test]
fn pending_fields_are_populated() {
    let id = Identity::gen().unwrap();
    let p = make_challenge(id.id()).unwrap();
    assert_eq!(p.id, id.id());
    assert_ne!(p.c, [0u8; 32]);
}

#[test]
fn check_returns_ok_with_token() {
    let id = Identity::gen().unwrap();
    let p = make_challenge(id.id()).unwrap();
    let r = respond(&id, &Challenge { n: p.c });
    match check(&p, &r) {
        AuthResult::Ok(tok) => assert_eq!(tok.len(), 16),
        AuthResult::Fail => panic!("expected Ok"),
    }
}

#[test]
fn two_auth_flows_produce_different_tokens() {
    let id = Identity::gen().unwrap();

    let p1 = make_challenge(id.id()).unwrap();
    let r1 = respond(&id, &Challenge { n: p1.c });
    let tok1 = match check(&p1, &r1) {
        AuthResult::Ok(t) => t,
        AuthResult::Fail => panic!("expected Ok"),
    };

    let p2 = make_challenge(id.id()).unwrap();
    let r2 = respond(&id, &Challenge { n: p2.c });
    let tok2 = match check(&p2, &r2) {
        AuthResult::Ok(t) => t,
        AuthResult::Fail => panic!("expected Ok"),
    };

    assert_ne!(tok1, tok2);
}

#[test]
fn replaying_response_to_different_pending_fails() {
    let id = Identity::gen().unwrap();
    let p1 = make_challenge(id.id()).unwrap();
    let p2 = make_challenge(id.id()).unwrap();
    // Sign p1's nonce
    let r = respond(&id, &Challenge { n: p1.c });
    // Use against p2 (different nonce) — must fail
    assert!(matches!(check(&p2, &r), AuthResult::Fail));
}

#[test]
fn auth_error_display_debug_consistent() {
    // In debug builds Display produces "E1" etc. Just check no panic.
    let _ = format!("{:?}", AuthError::E1);
    let _ = format!("{}", AuthError::E2);
}

#[test]
fn pending_size_is_64() {
    assert_eq!(core::mem::size_of::<Pending>(), 64);
}

// ============================================================================
// Identity seed determinism
// ============================================================================

#[test]
fn from_seed_is_deterministic() {
    let seed = [0x42u8; 32];
    let a = Identity::from_seed(&seed);
    let b = Identity::from_seed(&seed);
    assert_eq!(a.id(), b.id());
}

#[test]
fn different_seeds_give_different_ids() {
    let a = Identity::from_seed(&[0x01; 32]);
    let b = Identity::from_seed(&[0x02; 32]);
    assert_ne!(a.id(), b.id());
}

#[test]
fn sign32_matches_sign_on_32_bytes() {
    let id = Identity::gen().unwrap();
    let msg = [0xAA; 32];
    let sig_via_sign = id.sign(&msg);
    let sig_via_sign32 = id.sign32(&msg);
    assert_eq!(sig_via_sign.0, sig_via_sign32.0);
}

// ============================================================================
// ct_eq / ct_eq_n edge cases
// ============================================================================

#[test]
fn ct_eq_all_zeros() {
    assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
}

#[test]
fn ct_eq_all_ff() {
    assert!(ct_eq(&[0xFFu8; 32], &[0xFFu8; 32]));
}

#[test]
fn ct_eq_one_byte_diff_at_end() {
    let a = [0u8; 8];
    let mut b = [0u8; 8];
    b[7] = 1;
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_empty_slices() {
    assert!(ct_eq(&[], &[]));
}

#[test]
fn ct_eq_length_mismatch_returns_false() {
    assert!(!ct_eq(&[1u8; 4], &[1u8; 5]));
    assert!(!ct_eq(&[0u8; 1], &[]));
}

#[test]
fn ct_eq_n_all_zeros() {
    assert!(ct_eq_n(&[0u8; 32], &[0u8; 32]));
}

#[test]
fn ct_eq_n_first_byte_diff() {
    let mut b = [0u8; 32];
    b[0] = 1;
    assert!(!ct_eq_n(&[0u8; 32], &b));
}

// ============================================================================
// Timed challenge
// ============================================================================

#[test]
fn timed_challenge_created_ms_stored() {
    let id = Identity::gen().unwrap();
    let tp = make_timed_challenge(id.id(), 9999).unwrap();
    assert_eq!(tp.created_ms, 9999);
    assert_eq!(tp.id, id.id());
}

#[test]
fn challenge_ttl_default_is_30s() {
    assert_eq!(CHALLENGE_TTL_MS, 30_000);
}

#[test]
fn check_timed_wrong_signer_fails_even_within_ttl() {
    let id = Identity::gen().unwrap();
    let other = Identity::gen().unwrap();
    let tp = make_timed_challenge(id.id(), 0).unwrap();
    let r = respond(&other, &Challenge { n: tp.c });
    assert!(matches!(
        check_timed(&tp, &r, 1000, CHALLENGE_TTL_MS),
        AuthResult::Fail
    ));
}

#[test]
fn check_timed_zero_ttl_expires_immediately() {
    let id = Identity::gen().unwrap();
    let tp = make_timed_challenge(id.id(), 1000).unwrap();
    let r = respond(&id, &Challenge { n: tp.c });
    // zero TTL: any now_ms > 1000 fails
    assert!(matches!(check_timed(&tp, &r, 1001, 0), AuthResult::Fail));
}

// ============================================================================
// Trust chain — extra cases
// ============================================================================

#[test]
fn endorse_fields_correct() {
    let signer = Identity::gen().unwrap();
    let target = Identity::gen().unwrap();
    let e = endorse(&signer, &target.id(), 5000, 10_000);
    assert_eq!(e.endorser, signer.id());
    assert_eq!(e.endorsed, target.id());
    assert_eq!(e.issued_ms, 5000);
    assert_eq!(e.expires_ms, 15_000);
}

#[test]
fn endorsement_exactly_at_expiry_is_valid() {
    let signer = Identity::gen().unwrap();
    let target = Identity::gen().unwrap();
    let e = endorse(&signer, &target.id(), 0, 1000);
    // expires_ms == 1000, now_ms == 1000 → not > → valid
    assert!(verify_endorsement(&e, 1000));
}

#[test]
fn endorsement_one_ms_after_expiry_is_invalid() {
    let signer = Identity::gen().unwrap();
    let target = Identity::gen().unwrap();
    let e = endorse(&signer, &target.id(), 0, 1000);
    assert!(!verify_endorsement(&e, 1001));
}

#[test]
fn verify_chain_3_hop() {
    let root = Identity::gen().unwrap();
    let mid1 = Identity::gen().unwrap();
    let mid2 = Identity::gen().unwrap();
    let leaf = Identity::gen().unwrap();
    let e1 = endorse(&root, &mid1.id(), 0, 100_000);
    let e2 = endorse(&mid1, &mid2.id(), 0, 100_000);
    let e3 = endorse(&mid2, &leaf.id(), 0, 100_000);
    assert!(verify_chain(&[e1, e2, e3], &root.id(), 1000));
}

#[test]
fn verify_chain_wrong_first_endorser() {
    let root = Identity::gen().unwrap();
    let impersonator = Identity::gen().unwrap();
    let user = Identity::gen().unwrap();
    // Chain where first link is signed by impersonator, not root
    let e = endorse(&impersonator, &user.id(), 0, 100_000);
    assert!(!verify_chain(&[e], &root.id(), 1000));
}

#[test]
fn verify_chain_broken_at_second_link() {
    let root = Identity::gen().unwrap();
    let mid = Identity::gen().unwrap();
    let unrelated = Identity::gen().unwrap();
    let leaf = Identity::gen().unwrap();
    let e1 = endorse(&root, &mid.id(), 0, 100_000);
    // Second link endorser is unrelated, not mid
    let e2 = endorse(&unrelated, &leaf.id(), 0, 100_000);
    assert!(!verify_chain(&[e1, e2], &root.id(), 1000));
}

// ============================================================================
// Social recovery — extra cases
// ============================================================================

#[test]
fn recovery_approval_timestamp_preserved() {
    let guardian = Identity::gen().unwrap();
    let old = Identity::gen().unwrap();
    let new = Identity::gen().unwrap();
    let approval = approve_recovery(&guardian, &old.id(), &new.id(), 42_000);
    assert_eq!(approval.approved_ms, 42_000);
}

#[test]
fn recovery_approval_tampered_old_id_fails() {
    let guardian = Identity::gen().unwrap();
    let old = Identity::gen().unwrap();
    let new = Identity::gen().unwrap();
    let mut approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
    approval.old_id = AliceId::new([0x77; 32]);
    assert!(!verify_recovery_approval(&approval));
}

#[test]
fn recovery_approval_tampered_guardian_fails() {
    let guardian = Identity::gen().unwrap();
    let impersonator = Identity::gen().unwrap();
    let old = Identity::gen().unwrap();
    let new = Identity::gen().unwrap();
    let mut approval = approve_recovery(&guardian, &old.id(), &new.id(), 1000);
    approval.guardian = impersonator.id();
    assert!(!verify_recovery_approval(&approval));
}

// ============================================================================
// RotatingIdentity
// ============================================================================

#[test]
fn rotating_identity_from_identity_no_previous() {
    let base = Identity::gen().unwrap();
    let ri = alice_auth::RotatingIdentity::from_identity(base);
    assert!(!ri.has_previous());
    assert_eq!(ri.generation_count(), 0);
}

#[test]
fn rotating_identity_previous_id_none_before_rotation() {
    let ri = alice_auth::RotatingIdentity::gen().unwrap();
    assert!(ri.previous_id().is_none());
}

#[test]
fn rotating_identity_previous_ids_empty_before_rotation() {
    let ri = alice_auth::RotatingIdentity::gen().unwrap();
    assert!(ri.previous_ids().is_empty());
}

#[test]
fn rotating_identity_max_generations_1_evicts_immediately() {
    let base = Identity::gen().unwrap();
    let mut ri = alice_auth::RotatingIdentity::with_max_generations(base, 1);
    let id0 = ri.id();
    ri.rotate(1000).unwrap();
    assert_eq!(ri.generation_count(), 1);
    ri.rotate(2000).unwrap();
    // max_generations=1: only most recent previous kept
    assert_eq!(ri.generation_count(), 1);
    // id0 was evicted
    let prev = ri.previous_ids();
    assert!(prev.iter().all(|(id, _)| *id != id0));
}

#[test]
fn rotating_identity_clear_previous_removes_archived_keys() {
    let mut ri = alice_auth::RotatingIdentity::gen().unwrap();
    ri.rotate(1000).unwrap();
    assert!(ri.has_previous());
    ri.clear_previous();
    assert!(!ri.has_previous());
    assert_eq!(ri.generation_count(), 0);
    assert!(ri.previous_id().is_none());
    assert!(ri.previous_ids().is_empty());
}

#[test]
fn rotating_identity_current_key_always_verifiable() {
    let mut ri = alice_auth::RotatingIdentity::gen().unwrap();
    for i in 0..4u64 {
        ri.rotate(i * 1000).unwrap();
        let sig = ri.sign(b"current");
        assert!(ri.verify_any(&ri.id(), b"current", &sig));
    }
}

// ============================================================================
// api_bridge tests
// ============================================================================

#[cfg(feature = "api")]
mod api_tests {
    use alice_auth::api_bridge::{
        AuthMiddleware, AuthRequest, AuthResponse, AuthToken, Permission, PolicyEngine,
        RevocationList, Role,
    };
    use alice_auth::Identity;

    // --- AuthToken ---

    #[test]
    fn auth_token_not_expired_at_creation() {
        let token = AuthToken::new(1000, 60_000);
        assert!(!token.is_expired(1000));
    }

    #[test]
    fn auth_token_not_expired_one_before_boundary() {
        let token = AuthToken::new(0, 5000);
        assert!(!token.is_expired(5000)); // expires_ms == 5000, now==5000 → not > → not expired
    }

    #[test]
    fn auth_token_expired_one_past_boundary() {
        let token = AuthToken::new(0, 5000);
        assert!(token.is_expired(5001));
    }

    #[test]
    fn auth_token_from_bytes_wrong_version_is_none() {
        let mut bytes = AuthToken::new(0, 1000).to_bytes();
        bytes[0] = 0; // version 0 is invalid
        assert!(AuthToken::from_bytes(&bytes).is_none());
    }

    #[test]
    fn auth_token_from_bytes_exact_size_parses() {
        let token = AuthToken::new(12345, 99999);
        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), AuthToken::SIZE);
        let restored = AuthToken::from_bytes(&bytes).unwrap();
        assert_eq!(restored.nonce_ms, 12345);
        assert_eq!(restored.expires_ms, 12345 + 99999);
    }

    // --- RevocationList ---

    #[test]
    fn revocation_list_is_empty_on_new() {
        let rl = RevocationList::new();
        assert!(rl.is_empty());
        assert_eq!(rl.len(), 0);
    }

    #[test]
    fn revocation_with_capacity_1_evicts_on_second() {
        let mut rl = RevocationList::with_capacity(1);
        let tok_a = [0x01u8; 16];
        let tok_b = [0x02u8; 16];
        rl.revoke(&tok_a, 1000);
        assert!(rl.is_revoked(&tok_a));
        rl.revoke(&tok_b, 2000);
        // tok_a evicted
        assert!(!rl.is_revoked(&tok_a));
        assert!(rl.is_revoked(&tok_b));
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn revocation_purge_empty_list_is_noop() {
        let mut rl = RevocationList::new();
        rl.purge(&[[0u8; 16]]);
        assert_eq!(rl.len(), 0);
    }

    #[test]
    fn revocation_auto_purge_no_expired() {
        let mut rl = RevocationList::new();
        rl.revoke(&[0xAA; 16], 5000);
        let purged = rl.auto_purge(6000, 5000); // 6000-5000=1000 <= 5000 → keep
        assert_eq!(purged, 0);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn revocation_auto_purge_all_expired() {
        let mut rl = RevocationList::new();
        rl.revoke(&[0x11; 16], 1000);
        rl.revoke(&[0x22; 16], 2000);
        let purged = rl.auto_purge(100_000, 100); // all way older than 100ms
        assert_eq!(purged, 2);
        assert!(rl.is_empty());
    }

    // --- PolicyEngine ---

    #[test]
    fn policy_engine_role_of_returns_default_for_unknown() {
        let engine = PolicyEngine::new(Role::READER);
        let unknown = Identity::gen().unwrap();
        let role = engine.role_of(&unknown.id());
        assert_eq!(role, Role::READER);
    }

    #[test]
    fn policy_engine_none_role_has_no_permissions() {
        assert!(!Role::NONE.has(Permission::Read));
        assert!(!Role::NONE.has(Permission::Write));
        assert!(!Role::NONE.has(Permission::Admin));
        assert!(!Role::NONE.has(Permission::Execute));
    }

    #[test]
    fn policy_engine_admin_role_has_all_permissions() {
        assert!(Role::ADMIN.has(Permission::Read));
        assert!(Role::ADMIN.has(Permission::Write));
        assert!(Role::ADMIN.has(Permission::Admin));
        assert!(Role::ADMIN.has(Permission::Execute));
    }

    #[test]
    fn policy_engine_multiple_identities_isolated() {
        let mut engine = PolicyEngine::new(Role::NONE);
        let alice = Identity::gen().unwrap();
        let bob = Identity::gen().unwrap();
        engine.assign(&alice.id(), Role::ADMIN);
        engine.assign(&bob.id(), Role::READER);
        assert!(engine.authorize(&alice.id(), Permission::Admin));
        assert!(!engine.authorize(&bob.id(), Permission::Admin));
        assert!(engine.authorize(&bob.id(), Permission::Read));
    }

    // --- AuthMiddleware ---

    #[test]
    fn middleware_denied_count_accumulates() {
        let i = Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
        let bad_sig = alice_auth::AliceSig::new([0u8; 64]);
        let req = AuthRequest {
            token,
            signature: bad_sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        mw.verify_request(&req, 2000);
        mw.verify_request(&req, 2000);
        assert_eq!(mw.denied_count, 2);
        assert_eq!(mw.verified_count, 0);
    }

    #[test]
    fn middleware_verified_count_accumulates() {
        let i = Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(1000, 60_000);
        let sig = i.sign(&token);
        let req = AuthRequest {
            token,
            signature: sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        mw.verify_request(&req, 2000);
        mw.verify_request(&req, 2000);
        assert_eq!(mw.verified_count, 2);
        assert_eq!(mw.denied_count, 0);
    }

    #[test]
    fn middleware_authorized_response_contains_correct_identity() {
        let i = Identity::gen().unwrap();
        let token = AuthMiddleware::create_auth_token(5000, 60_000);
        let sig = i.sign(&token);
        let req = AuthRequest {
            token,
            signature: sig,
            identity: i.id(),
        };
        let mut mw = AuthMiddleware::new();
        match mw.verify_request(&req, 6000) {
            AuthResponse::Authorized { identity, .. } => assert_eq!(identity, i.id()),
            AuthResponse::Denied { reason } => panic!("denied: {reason}"),
        }
    }

    #[test]
    fn rate_limit_window_slides_correctly() {
        let mut mw = AuthMiddleware::new();
        let id = [0xCC; 32];
        // Fill window at t=0
        assert!(mw.validate_rate_limit(&id, 1000, 2000, 2));
        assert!(mw.validate_rate_limit(&id, 1500, 2000, 2));
        assert!(!mw.validate_rate_limit(&id, 1800, 2000, 2));
        // At t=3100: t=1000 is outside window [3100-2000=1100..3100], t=1500 also outside
        assert!(mw.validate_rate_limit(&id, 3100, 2000, 2));
    }
}

// ============================================================================
// db_bridge tests
// ============================================================================

#[cfg(feature = "db")]
mod db_tests {
    use alice_auth::db_bridge::{AuthAction, AuthAuditLog, AuthDbStore};

    #[test]
    fn store_duplicate_timestamp_same_identity_overwrites() {
        let mut store = AuthDbStore::new();
        let id = [0x55; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 1000,
            action: AuthAction::Login,
            success: true,
            zkp_verified: false,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 1000, // same key
            action: AuthAction::Logout,
            success: false,
            zkp_verified: false,
        });
        // BTreeMap insert overwrites duplicate key → still 1 entry
        assert_eq!(store.total_entries, 1);
        let logs = store.query_by_identity(&id, 0);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].action, AuthAction::Logout);
    }

    #[test]
    fn query_by_identity_empty_returns_empty() {
        let store = AuthDbStore::new();
        let id = [0xAA; 32];
        let logs = store.query_by_identity(&id, 0);
        assert!(logs.is_empty());
    }

    #[test]
    fn total_entries_tracks_unique_keys() {
        let mut store = AuthDbStore::new();
        let id_a = [0x01; 32];
        let id_b = [0x02; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id_a,
            timestamp_ms: 100,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id_a,
            timestamp_ms: 200,
            action: AuthAction::Challenge,
            success: true,
            zkp_verified: true,
        });
        store.store_audit(&AuthAuditLog {
            identity_hash: id_b,
            timestamp_ms: 100,
            action: AuthAction::Login,
            success: true,
            zkp_verified: true,
        });
        assert_eq!(store.total_entries, 3);
    }

    #[test]
    fn count_failed_attempts_returns_zero_for_empty_store() {
        let store = AuthDbStore::new();
        assert_eq!(store.count_failed_attempts(&[0u8; 32], 0), 0);
    }

    #[test]
    fn count_failed_attempts_from_future_ts_returns_zero() {
        let mut store = AuthDbStore::new();
        let id = [0x33; 32];
        store.store_audit(&AuthAuditLog {
            identity_hash: id,
            timestamp_ms: 100,
            action: AuthAction::Login,
            success: false,
            zkp_verified: false,
        });
        // from_ms beyond any stored entry
        assert_eq!(store.count_failed_attempts(&id, 999_999), 0);
    }

    #[test]
    fn audit_log_all_actions_serialize_and_deserialize() {
        for action in [
            AuthAction::Login,
            AuthAction::Logout,
            AuthAction::Challenge,
            AuthAction::TokenRefresh,
            AuthAction::KeyRotation,
            AuthAction::Revocation,
        ] {
            let log = AuthAuditLog {
                identity_hash: [0u8; 32],
                timestamp_ms: 42,
                action,
                success: true,
                zkp_verified: false,
            };
            let restored = AuthAuditLog::from_bytes(&log.to_bytes()).unwrap();
            assert_eq!(restored.action, action);
        }
    }
}
