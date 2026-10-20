//! A revoked token stays revoked: the revocation list never forgets an entry
//! to make room for a new one.
//!
//! The only ways an entry leaves the list are the explicit `purge` (by value)
//! and `auto_purge` (by age). When the list is full, `revoke` refuses the new
//! token instead of dropping an old one, and the caller sees the refusal.

#![cfg(feature = "api")]

use alice_auth::api_bridge::{RevocationList, RevokeError, DEFAULT_REVOCATION_CAPACITY};

/// The `i`-th distinct token.
fn token(i: usize) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&(i as u64).to_le_bytes());
    t[15] = 0xa5;
    t
}

/// Revoking one more token than the default capacity holds leaves every
/// earlier token revoked, the first one included
#[test]
fn the_first_token_stays_revoked_past_the_default_capacity() {
    let mut rl = RevocationList::new();
    for i in 0..=DEFAULT_REVOCATION_CAPACITY {
        let _ = rl.revoke(&token(i), 1_000 + i as u64);
    }
    assert_eq!(
        rl.revoke(&token(DEFAULT_REVOCATION_CAPACITY), 1),
        Err(RevokeError::Full {
            capacity: DEFAULT_REVOCATION_CAPACITY
        }),
        "the token past the capacity must be refused, not silently dropped"
    );
    assert!(
        rl.is_revoked(&token(0)),
        "the first revoked token became valid again"
    );
    for i in 0..DEFAULT_REVOCATION_CAPACITY {
        assert!(rl.is_revoked(&token(i)), "token {i} became valid again");
    }
    assert_eq!(rl.len(), DEFAULT_REVOCATION_CAPACITY);
}

/// A refused token leaves the list exactly as it was, and an already revoked
/// token is still accepted on a full list
#[test]
fn a_full_list_refuses_without_changing() {
    let mut rl = RevocationList::with_capacity(2);
    assert_eq!(rl.revoke(&token(0), 10), Ok(()));
    assert_eq!(rl.revoke(&token(1), 20), Ok(()));
    let err = rl.revoke(&token(2), 30).unwrap_err();
    assert_eq!(err, RevokeError::Full { capacity: 2 });
    assert!(err.to_string().contains("not revoked"), "{err}");
    assert!(rl.is_revoked(&token(0)) && rl.is_revoked(&token(1)));
    assert!(!rl.is_revoked(&token(2)));
    assert_eq!(rl.len(), 2);
    assert_eq!(rl.revoke(&token(0), 40), Ok(()));
    assert_eq!(rl.len(), 2);
}

/// `with_capacity(0)` holds one entry, as documented: the first token is
/// revoked and the second is refused
#[test]
fn a_capacity_of_zero_holds_one_entry() {
    let mut rl = RevocationList::with_capacity(0);
    assert_eq!(rl.revoke(&token(0), 1), Ok(()));
    assert_eq!(
        rl.revoke(&token(1), 2),
        Err(RevokeError::Full { capacity: 1 })
    );
    assert!(rl.is_revoked(&token(0)));
}

/// `auto_purge` removes exactly the entries older than `ttl_ms` (an entry
/// exactly `ttl_ms` old and one stamped after `now_ms` stay), and only then is
/// there room for a new token
#[test]
fn auto_purge_removes_by_age_only() {
    let mut rl = RevocationList::with_capacity(4);
    rl.revoke(&token(0), 1_000).unwrap(); // age 9_000 > 5_000: removed
    rl.revoke(&token(1), 5_000).unwrap(); // age 5_000 == ttl: kept
    rl.revoke(&token(2), 9_999).unwrap(); // age 1: kept
    rl.revoke(&token(3), 20_000).unwrap(); // after now: kept
    assert!(rl.revoke(&token(4), 10_000).is_err());
    assert_eq!(rl.auto_purge(10_000, 5_000), 1);
    assert!(!rl.is_revoked(&token(0)));
    for i in 1..4 {
        assert!(
            rl.is_revoked(&token(i)),
            "token {i} was removed by auto_purge"
        );
    }
    assert_eq!(rl.revoke(&token(4), 10_000), Ok(()));
    assert_eq!(rl.auto_purge(10_000, 5_000), 0);
}

/// The same rule through the C ABI: a full list refuses with
/// `AA_REVLIST_ERR_FULL` and keeps every earlier token revoked; a null
/// argument is refused with `AA_REVLIST_ERR_NULL`; both leave a message for
/// `aa_last_error`.
#[cfg(feature = "ffi")]
mod c_abi {
    use super::token;
    use alice_auth::{
        aa_clear_last_error, aa_free_error_string, aa_last_error, aa_revlist_free,
        aa_revlist_is_revoked, aa_revlist_new, aa_revlist_new_with_capacity, aa_revlist_revoke,
        AA_REVLIST_ERR_FULL, AA_REVLIST_ERR_NULL, AA_REVLIST_OK,
    };
    use std::ffi::CStr;
    use std::ptr;

    /// Take the message `aa_last_error` holds, or an empty string.
    fn last_error() -> String {
        let p = aa_last_error();
        if p.is_null() {
            return String::new();
        }
        // SAFETY: a non-null pointer from aa_last_error, freed once below
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { aa_free_error_string(p) };
        s
    }

    #[test]
    fn a_full_list_refuses_and_keeps_the_first_token() {
        let h = aa_revlist_new_with_capacity(3);
        assert!(!h.is_null());
        for i in 0..3 {
            let t = token(i);
            assert_eq!(
                unsafe { aa_revlist_revoke(h, t.as_ptr(), 1_000) },
                AA_REVLIST_OK
            );
        }
        aa_clear_last_error();
        let fourth = token(3);
        assert_eq!(
            unsafe { aa_revlist_revoke(h, fourth.as_ptr(), 2_000) },
            AA_REVLIST_ERR_FULL
        );
        assert!(last_error().contains("full"));
        for i in 0..3 {
            let t = token(i);
            assert_eq!(
                unsafe { aa_revlist_is_revoked(h, t.as_ptr()) },
                1,
                "token {i}"
            );
        }
        assert_eq!(unsafe { aa_revlist_is_revoked(h, fourth.as_ptr()) }, 0);
        // an already revoked token still reports OK on a full list
        let first = token(0);
        assert_eq!(
            unsafe { aa_revlist_revoke(h, first.as_ptr(), 3_000) },
            AA_REVLIST_OK
        );
        unsafe { aa_revlist_free(h) };
    }

    #[test]
    fn the_default_list_refuses_past_its_capacity_through_the_c_abi() {
        let h = aa_revlist_new();
        for i in 0..super::DEFAULT_REVOCATION_CAPACITY {
            let t = token(i);
            assert_eq!(
                unsafe { aa_revlist_revoke(h, t.as_ptr(), 1_000) },
                AA_REVLIST_OK
            );
        }
        let over = token(super::DEFAULT_REVOCATION_CAPACITY);
        assert_eq!(
            unsafe { aa_revlist_revoke(h, over.as_ptr(), 2_000) },
            AA_REVLIST_ERR_FULL
        );
        let first = token(0);
        assert_eq!(unsafe { aa_revlist_is_revoked(h, first.as_ptr()) }, 1);
        unsafe { aa_revlist_free(h) };
    }

    #[test]
    fn a_null_handle_or_token_is_refused_with_a_message() {
        let t = token(0);
        aa_clear_last_error();
        assert_eq!(
            unsafe { aa_revlist_revoke(ptr::null_mut(), t.as_ptr(), 1_000) },
            AA_REVLIST_ERR_NULL
        );
        assert!(last_error().contains("null"));
        let h = aa_revlist_new_with_capacity(1);
        assert_eq!(
            unsafe { aa_revlist_revoke(h, ptr::null(), 1_000) },
            AA_REVLIST_ERR_NULL
        );
        assert!(last_error().contains("null"));
        // the refused calls recorded nothing: the list still has room
        assert_eq!(
            unsafe { aa_revlist_revoke(h, t.as_ptr(), 1_000) },
            AA_REVLIST_OK
        );
        unsafe { aa_revlist_free(h) };
    }
}
