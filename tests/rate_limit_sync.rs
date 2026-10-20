//! Rate-limit state from other nodes is counted, bounded and fail-closed.
//!
//! A node's report is a count with the moment its counted requests stop mattering
//! (`expires_ms`). Importing replaces that node's entry (a replay is not additive), a
//! count above the configured cap or a node beyond the configured number is refused
//! before anything is stored and marks the identity as over its limit until the report
//! expires, merged counts never wrap, and an entry stops counting only at its own expiry.

#![cfg(feature = "api")]

use alice_auth::api_bridge::{AuthMiddleware, RateLimitState, RateSyncConfig, RateSyncError};

const A: [u8; 32] = [0xa1; 32];
const B: [u8; 32] = [0xb2; 32];

fn node(n: u8) -> [u8; 32] {
    [n; 32]
}

fn state(identity: [u8; 32], count: u32, window_start_ms: u64, expires_ms: u64) -> RateLimitState {
    RateLimitState {
        identity,
        count,
        window_start_ms,
        expires_ms,
    }
}

/// How many more requests the limiter admits for `id` at `now` (window 10 s, max `max`)
fn admitted(mw: &mut AuthMiddleware, id: &[u8; 32], now: u64, max: u32) -> u32 {
    let n = (0..max + 2)
        .filter(|_| mw.validate_rate_limit(id, now, 10_000, max))
        .count();
    u32::try_from(n).expect("small")
}

// ── merge ───────────────────────────────────────────────────────────────────

#[test]
fn a_merge_that_would_overflow_is_refused() {
    let r = std::panic::catch_unwind(|| {
        AuthMiddleware::merge_rate_states(&[state(A, u32::MAX, 0, 10), state(A, 1, 0, 10)])
    });
    assert_eq!(r.expect("no panic"), Err(RateSyncError::Overflow));
}

#[test]
fn a_merge_of_different_identities_is_refused() {
    assert_eq!(
        AuthMiddleware::merge_rate_states(&[state(A, 1, 0, 10), state(B, 1, 0, 10)]),
        Err(RateSyncError::MixedIdentity)
    );
    assert_eq!(
        AuthMiddleware::merge_rate_states(&[]),
        Err(RateSyncError::Empty)
    );
}

#[test]
fn a_merge_sums_counts_and_spans_the_windows() {
    let m = AuthMiddleware::merge_rate_states(&[
        state(A, 3, 1_000, 9_000),
        state(A, 2, 500, 12_000),
        state(A, 1, 2_000, 8_000),
    ])
    .expect("merge");
    assert_eq!(
        (m.identity, m.count, m.window_start_ms, m.expires_ms),
        (A, 6, 500, 12_000)
    );
}

// ── import ──────────────────────────────────────────────────────────────────

#[test]
fn a_count_above_the_cap_is_refused_and_the_identity_is_held_over_its_limit() {
    let mut mw =
        AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 8, 60_000).expect("config"));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mw.import_rate_state(&node(1), &state(A, u32::MAX, 0, 20_000), 1_000)
    }));
    assert_eq!(
        r.expect("no panic"),
        Err(RateSyncError::OverCap {
            count: u32::MAX,
            cap: 100
        })
    );
    assert_eq!(
        admitted(&mut mw, &A, 5_000, 1_000),
        0,
        "fail-closed until the report expires"
    );
    assert_eq!(
        admitted(&mut mw, &A, 20_000, 3),
        3,
        "released at the report's expiry"
    );
    assert_eq!(
        admitted(&mut mw, &B, 5_000, 3),
        3,
        "another identity is unaffected"
    );
}

#[test]
fn importing_the_same_report_twice_counts_it_once() {
    let mut mw = AuthMiddleware::new();
    let s = state(A, 3, 0, 20_000);
    mw.import_rate_state(&node(1), &s, 1_000).expect("import");
    mw.import_rate_state(&node(1), &s, 1_000).expect("import");
    assert_eq!(admitted(&mut mw, &A, 2_000, 5), 2);
}

#[test]
fn a_newer_report_from_a_node_replaces_its_older_one() {
    let mut mw = AuthMiddleware::new();
    mw.import_rate_state(&node(1), &state(A, 4, 0, 20_000), 1_000)
        .expect("import");
    mw.import_rate_state(&node(1), &state(A, 1, 0, 20_000), 1_000)
        .expect("import");
    assert_eq!(admitted(&mut mw, &A, 2_000, 5), 4);
}

#[test]
fn reports_from_different_nodes_add_up() {
    let mut mw = AuthMiddleware::new();
    mw.import_rate_state(&node(1), &state(A, 2, 0, 20_000), 1_000)
        .expect("import");
    mw.import_rate_state(&node(2), &state(A, 2, 0, 20_000), 1_000)
        .expect("import");
    assert_eq!(admitted(&mut mw, &A, 2_000, 5), 1);
}

#[test]
fn a_report_counts_until_its_own_expiry_and_not_after() {
    let mut mw = AuthMiddleware::new();
    mw.import_rate_state(&node(1), &state(A, 5, 0, 10_000), 1_000)
        .expect("import");
    assert!(
        !mw.validate_rate_limit(&A, 9_999, 10_000, 5),
        "still counted just before expiry"
    );
    assert!(
        mw.validate_rate_limit(&A, 10_000, 10_000, 5),
        "no longer counted at expiry"
    );
}

#[test]
fn nodes_beyond_the_cap_are_refused_without_evicting_the_counted_ones() {
    let mut mw =
        AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 2, 60_000).expect("config"));
    mw.import_rate_state(&node(1), &state(A, 1, 0, 30_000), 1_000)
        .expect("first");
    mw.import_rate_state(&node(2), &state(A, 1, 0, 30_000), 1_000)
        .expect("second");
    assert_eq!(
        mw.import_rate_state(&node(3), &state(A, 1, 0, 25_000), 1_000),
        Err(RateSyncError::TooManyNodes { cap: 2 })
    );
    assert_eq!(
        admitted(&mut mw, &A, 2_000, 10),
        0,
        "fail-closed until the refused report expires"
    );
    // after the refused report's expiry the two counted entries still count (not evicted)
    assert_eq!(admitted(&mut mw, &A, 25_000, 4), 2);
    // a known node can still update its own entry while the map is full
    mw.import_rate_state(&node(1), &state(A, 0, 0, 30_000), 26_000)
        .expect("replace");
}

#[test]
fn an_expired_entry_frees_its_node_slot() {
    let mut mw =
        AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 1, 60_000).expect("config"));
    mw.import_rate_state(&node(1), &state(A, 1, 0, 5_000), 1_000)
        .expect("first");
    assert!(mw
        .import_rate_state(&node(2), &state(A, 1, 0, 9_000), 2_000)
        .is_err());
    mw.import_rate_state(&node(2), &state(A, 1, 0, 30_000), 5_000)
        .expect("slot freed at expiry");
}

#[test]
fn an_already_expired_report_is_ignored_even_when_the_node_map_is_full() {
    let mut mw =
        AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 1, 60_000).expect("config"));
    mw.import_rate_state(&node(1), &state(A, 1, 0, 30_000), 1_000)
        .expect("first");
    assert_eq!(
        mw.import_rate_state(&node(2), &state(A, 1, 0, 1_000), 1_000),
        Ok(())
    );
    assert_eq!(
        admitted(&mut mw, &A, 2_000, 3),
        2,
        "not held over the limit"
    );
}

#[test]
fn an_already_expired_report_is_not_stored() {
    let mut mw =
        AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 1, 60_000).expect("config"));
    mw.import_rate_state(&node(1), &state(A, 50, 0, 1_000), 1_000)
        .expect("ignored");
    mw.import_rate_state(&node(2), &state(A, 1, 0, 30_000), 1_000)
        .expect("slot not taken");
    assert_eq!(admitted(&mut mw, &A, 2_000, 3), 2);
}

#[test]
fn reports_for_one_identity_do_not_affect_another() {
    let mut mw = AuthMiddleware::new();
    mw.import_rate_state(&node(1), &state(A, 5, 0, 20_000), 1_000)
        .expect("import");
    assert_eq!(admitted(&mut mw, &B, 2_000, 5), 5);
    assert_eq!(admitted(&mut mw, &A, 2_000, 5), 0);
}

// ── limiter and config ──────────────────────────────────────────────────────

#[test]
fn local_and_remote_load_together_reach_the_limit() {
    let mut mw = AuthMiddleware::new();
    assert!(mw.validate_rate_limit(&A, 1_000, 10_000, 4));
    mw.import_rate_state(&node(1), &state(A, 2, 0, 20_000), 1_000)
        .expect("import");
    assert!(
        mw.validate_rate_limit(&A, 1_100, 10_000, 4),
        "local 1 + remote 2 = 3 < 4"
    );
    assert!(
        !mw.validate_rate_limit(&A, 1_200, 10_000, 4),
        "local 2 + remote 2 = 4"
    );
}

#[test]
fn the_config_refuses_zero_and_absurd_bounds() {
    assert_eq!(
        RateSyncConfig::new(0, 1, 1).err(),
        Some(RateSyncError::InvalidConfig)
    );
    assert_eq!(
        RateSyncConfig::new(1, 0, 1).err(),
        Some(RateSyncError::InvalidConfig)
    );
    assert_eq!(
        RateSyncConfig::new(RateSyncConfig::MAX_REMOTE_COUNT + 1, 1, 1).err(),
        Some(RateSyncError::InvalidConfig)
    );
    assert_eq!(
        RateSyncConfig::new(1, RateSyncConfig::MAX_REMOTE_NODES + 1, 1).err(),
        Some(RateSyncError::InvalidConfig)
    );
    assert_eq!(
        RateSyncConfig::new(1, 1, 0).err(),
        Some(RateSyncError::InvalidConfig)
    );
    assert_eq!(
        RateSyncConfig::new(1, 1, RateSyncConfig::MAX_REPORT_TTL_MS + 1).err(),
        Some(RateSyncError::InvalidConfig)
    );
    let d = RateSyncConfig::default();
    assert!(RateSyncConfig::new(
        d.max_remote_count(),
        d.max_remote_nodes(),
        d.max_report_ttl_ms()
    )
    .is_ok());
}

#[test]
fn an_export_counts_local_requests_and_saturates_its_expiry() {
    let mut mw = AuthMiddleware::new();
    for t in [1_000, 2_000, 3_000] {
        assert!(mw.validate_rate_limit(&A, t, 5_000, 10));
    }
    mw.import_rate_state(&node(1), &state(A, 7, 0, 20_000), 3_000)
        .expect("import");
    let s = mw.export_rate_state(&A, 5_000, 5_000).expect("state");
    assert_eq!(
        (s.count, s.window_start_ms, s.expires_ms),
        (3, 0, 10_000),
        "local requests only"
    );
    let s = mw
        .export_rate_state(&A, 5_000, u64::MAX - 1)
        .expect("state");
    assert_eq!(s.expires_ms, u64::MAX);
}

// ── a report's lifetime is bounded by the receiver ──────────────────────────

fn bounded() -> AuthMiddleware {
    AuthMiddleware::with_rate_sync(RateSyncConfig::new(100, 8, 60_000).expect("config"))
}

#[test]
fn a_report_with_an_unbounded_expiry_is_released_at_now_plus_the_ttl_bound() {
    let mut mw = bounded();
    mw.import_rate_state(&node(1), &state(A, 5, 0, u64::MAX), 1_000)
        .expect("import");
    assert!(
        !mw.validate_rate_limit(&A, 60_999, 10_000, 5),
        "counted until now + ttl"
    );
    assert!(
        mw.validate_rate_limit(&A, 61_000, 10_000, 5),
        "released at now + ttl"
    );
}

#[test]
fn an_over_cap_report_with_an_unbounded_expiry_is_held_only_until_now_plus_the_ttl_bound() {
    let mut mw = bounded();
    assert!(mw
        .import_rate_state(&node(1), &state(A, 101, 0, u64::MAX), 1_000)
        .is_err());
    assert!(
        !mw.validate_rate_limit(&A, 60_999, 10_000, 5),
        "held until now + ttl"
    );
    assert!(
        mw.validate_rate_limit(&A, 61_000, 10_000, 5),
        "released at now + ttl"
    );
}

#[test]
fn the_ttl_bound_does_not_overflow_near_u64_max() {
    let mut mw = bounded();
    let now = u64::MAX - 10;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mw.import_rate_state(&node(1), &state(A, 5, 0, u64::MAX), now)
    }));
    assert_eq!(r.expect("no panic"), Ok(()));
    assert!(!mw.validate_rate_limit(&A, u64::MAX - 1, 10_000, 5));
}

#[test]
fn the_count_cap_is_inclusive() {
    let mut mw = bounded();
    assert_eq!(
        mw.import_rate_state(&node(1), &state(A, 100, 0, 20_000), 1_000),
        Ok(())
    );
    assert_eq!(
        mw.import_rate_state(&node(2), &state(B, 101, 0, 20_000), 1_000),
        Err(RateSyncError::OverCap {
            count: 101,
            cap: 100
        })
    );
}

#[test]
fn the_hold_ends_exactly_at_the_refused_reports_expiry() {
    let mut mw = bounded();
    assert!(mw
        .import_rate_state(&node(1), &state(A, 101, 0, 20_000), 1_000)
        .is_err());
    assert!(
        !mw.validate_rate_limit(&A, 19_999, 10_000, 5),
        "held at its last millisecond"
    );
    assert!(
        mw.validate_rate_limit(&A, 20_000, 10_000, 5),
        "released at expiry"
    );
}
