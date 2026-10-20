//! The C ABI of the player module gives the same bytes and the same decisions as the Rust
//! API, with the codes of `GrantError::code`.
//!
//! References: the reference bytes are those of `tests/player_chain.rs` and
//! `tests/player_grant.rs` (computed by a separate program, not by this crate). Every
//! refusal is checked three ways: the code equals the Rust error's code for the same
//! input, `aa_last_error` names the function, and the output buffer is left as it was.

#![cfg(feature = "ffi")]

use alice_auth::{
    aa_clear_last_error, aa_free, aa_free_error_string, aa_from_seed, aa_grant_issue,
    aa_grant_verify, aa_id, aa_last_error, aa_player_chain_resolve, aa_player_id_from_genesis,
    aa_revocation_issue, aa_revset_add, aa_revset_contains, aa_revset_free, aa_revset_len,
    aa_revset_new, aa_revset_purge, aa_rotation_link_issue, ChainHead, Grant, GrantError, Handle,
    Identity, PlayerId, RevocationSet, AA_GRANT_LEN, AA_PLAYER_OK, AA_REVOCATION_LEN,
    AA_ROTATION_LINK_LEN, GRANT_LEN, REVOCATION_LEN, ROTATION_LINK_LEN,
};
use core::ptr::{null, null_mut};

const K1: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const K2: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const PLAYER: &str = "2b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f";
const LINK0: &str = "012b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394e8030000000000001bafc28ddbb05a7fe3788452af7c95562ffe3dec38d769f8b9c0c9a7a8cd6cee635663f8153bdf391ff1009cf0e4f0233f971e6ba00ebedb1b9b3400db812707";
const GAME: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const GRANT0: &str = "012b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618efcdab8967452301dc050000000000008813000000000000000102030405060708090a0b0c0d0e0f39e83927a5408ab80f3ba57dacf6a4c75790413481309616f3d9a33dc96e7bdfdccf211b934e80da2fbc37b5879ec560e9759d0d9342c3d62731c889eada010a";
const REVOCATION0: &str = "01fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618000102030405060708090a0b0c0d0e0f8813000000000000b80b000000000000a61440e192f02a1f7cd56f24a200eee887f50da939ebace082532ea3f95c2b8e283ab093886ab42c28401a504d1c88310951383fc8ab1d17b160e9361c0a5f0b";
const SCOPE: u64 = 0x0123_4567_89ab_cdef;
const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const FILL: u8 = 0xa5;

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "{hex}");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn handle(seed: u8) -> *mut Handle {
    let h = unsafe { aa_from_seed([seed; 32].as_ptr()) };
    assert!(!h.is_null());
    h
}

/// The text of `aa_last_error`, consumed.
fn last_error() -> Option<String> {
    let p = aa_last_error();
    if p.is_null() {
        return None;
    }
    // SAFETY: a pointer returned by aa_last_error, freed once below
    let s = unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned();
    unsafe { aa_free_error_string(p) };
    Some(s)
}

/// A refusal: the code, an error message naming `func`, and nothing written.
fn assert_refused(code: i32, want: GrantError, func: &str, out: &[u8]) {
    assert_eq!(code, want.code(), "{func}: {want:?}");
    let msg = last_error().unwrap_or_else(|| panic!("{func}: no aa_last_error for {want:?}"));
    assert!(msg.contains(func), "{func}: message {msg:?}");
    assert!(
        out.iter().all(|&b| b == FILL),
        "{func}: output written on {want:?}"
    );
}

struct Head {
    player: [u8; 32],
    key: [u8; 32],
    since_ms: u64,
}

fn head() -> Head {
    Head {
        player: bytes(PLAYER),
        key: bytes(K2),
        since_ms: 1000,
    }
}

/// `aa_grant_verify` with the outputs filled; returns the code and the outputs.
fn verify(
    grant: &[u8],
    game: &[u8; 32],
    h: &Head,
    now_ms: u64,
    set: *const alice_auth::RevSetHandle,
) -> (i32, [u8; 32], u64, u64) {
    let mut player = [FILL; 32];
    let mut scope = u64::from_le_bytes([FILL; 8]);
    let mut expires = scope;
    let code = unsafe {
        aa_grant_verify(
            grant.as_ptr(),
            grant.len(),
            game.as_ptr(),
            h.player.as_ptr(),
            h.key.as_ptr(),
            h.since_ms,
            now_ms,
            set,
            player.as_mut_ptr(),
            &mut scope,
            &mut expires,
        )
    };
    (code, player, scope, expires)
}

/// A key restored from its seed is the same key (the game's issuing key must survive a
/// restart of the host); a null seed is refused.
#[test]
fn a_handle_from_a_seed_is_that_key() {
    let h = handle(9);
    let mut id = [FILL; 32];
    unsafe { aa_id(h, id.as_mut_ptr()) };
    assert_eq!(id, bytes::<32>(GAME));
    assert_eq!(id, Identity::from_seed(&[9; 32]).id().0);
    unsafe { aa_free(h) };
    aa_clear_last_error();
    assert!(unsafe { aa_from_seed(null()) }.is_null());
    assert!(last_error().is_some_and(|m| m.contains("aa_from_seed")));
}

#[test]
fn lengths_are_the_rust_lengths() {
    assert_eq!(AA_PLAYER_OK, 0);
    assert_eq!(AA_ROTATION_LINK_LEN, ROTATION_LINK_LEN);
    assert_eq!(AA_GRANT_LEN, GRANT_LEN);
    assert_eq!(AA_REVOCATION_LEN, REVOCATION_LEN);
}

#[test]
fn player_id_and_link_are_the_reference_bytes() {
    let mut id = [FILL; 32];
    assert_eq!(
        unsafe { aa_player_id_from_genesis(bytes::<32>(K1).as_ptr(), id.as_mut_ptr()) },
        AA_PLAYER_OK
    );
    assert_eq!(id, bytes::<32>(PLAYER));
    let h = handle(1);
    let mut link = [FILL; ROTATION_LINK_LEN];
    let code = unsafe {
        aa_rotation_link_issue(
            h,
            id.as_ptr(),
            0,
            bytes::<32>(K2).as_ptr(),
            1000,
            link.as_mut_ptr(),
        )
    };
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!(link, bytes::<ROTATION_LINK_LEN>(LINK0));
    unsafe { aa_free(h) };
}

#[test]
fn the_chain_resolves_as_in_rust() {
    let link = bytes::<ROTATION_LINK_LEN>(LINK0);
    let (mut player, mut key, mut since) = ([FILL; 32], [FILL; 32], 7u64);
    let code = unsafe {
        aa_player_chain_resolve(
            bytes::<32>(K1).as_ptr(),
            link.as_ptr(),
            1,
            player.as_mut_ptr(),
            key.as_mut_ptr(),
            &mut since,
        )
    };
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!((player, key, since), (bytes(PLAYER), bytes(K2), 1000));
    // no link: the first key, from 0 (links may be null when there is none)
    let code = unsafe {
        aa_player_chain_resolve(
            bytes::<32>(K1).as_ptr(),
            null(),
            0,
            player.as_mut_ptr(),
            key.as_mut_ptr(),
            &mut since,
        )
    };
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!((player, key, since), (bytes(PLAYER), bytes(K1), 0));
}

#[test]
fn a_broken_chain_is_refused_with_the_rust_code() {
    let mut link = bytes::<ROTATION_LINK_LEN>(LINK0);
    link[150] ^= 1;
    let (mut player, mut key, mut since) = ([FILL; 32], [FILL; 32], u64::from_le_bytes([FILL; 8]));
    aa_clear_last_error();
    let code = unsafe {
        aa_player_chain_resolve(
            bytes::<32>(K1).as_ptr(),
            link.as_ptr(),
            1,
            player.as_mut_ptr(),
            key.as_mut_ptr(),
            &mut since,
        )
    };
    assert_refused(
        code,
        GrantError::Signature,
        "aa_player_chain_resolve",
        &player,
    );
    assert!(key.iter().all(|&b| b == FILL) && since == u64::from_le_bytes([FILL; 8]));
    // the first key is a small-order point
    let mut weak = [0u8; 32];
    weak[0] = 1;
    let code = unsafe {
        aa_player_chain_resolve(
            weak.as_ptr(),
            null(),
            0,
            player.as_mut_ptr(),
            key.as_mut_ptr(),
            &mut since,
        )
    };
    assert_refused(code, GrantError::Chain, "aa_player_chain_resolve", &player);
    // a link with another version byte
    let mut v2 = bytes::<ROTATION_LINK_LEN>(LINK0);
    v2[0] = 2;
    let code = unsafe {
        aa_player_chain_resolve(
            bytes::<32>(K1).as_ptr(),
            v2.as_ptr(),
            1,
            player.as_mut_ptr(),
            key.as_mut_ptr(),
            &mut since,
        )
    };
    assert_refused(
        code,
        GrantError::Version,
        "aa_player_chain_resolve",
        &player,
    );
}

#[test]
fn issue_and_verify_match_the_rust_api() {
    let g = handle(9);
    let mut grant = [FILL; GRANT_LEN];
    let code = unsafe {
        aa_grant_issue(
            g,
            bytes::<32>(PLAYER).as_ptr(),
            bytes::<32>(K2).as_ptr(),
            SCOPE,
            1500,
            3500,
            NONCE.as_ptr(),
            grant.as_mut_ptr(),
        )
    };
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!(grant, bytes::<GRANT_LEN>(GRANT0));
    let set = aa_revset_new(4);
    assert!(!set.is_null());
    let (code, player, scope, expires) = verify(&grant, &bytes(GAME), &head(), 2000, set);
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!((player, scope, expires), (bytes(PLAYER), SCOPE, 5000));
    let mut rev = [FILL; REVOCATION_LEN];
    let code =
        unsafe { aa_revocation_issue(g, grant.as_ptr(), grant.len(), 3000, rev.as_mut_ptr()) };
    assert_eq!(code, AA_PLAYER_OK);
    assert_eq!(rev, bytes::<REVOCATION_LEN>(REVOCATION0));
    unsafe {
        aa_revset_free(set);
        aa_free(g);
    }
}

/// Every refusal of `Grant::verify` comes out of `aa_grant_verify` with the same code,
/// with the outputs untouched.
#[test]
fn every_verify_refusal_has_the_rust_code() {
    let good = bytes::<GRANT_LEN>(GRANT0);
    let game = bytes::<32>(GAME);
    let set = aa_revset_new(4);
    let rust_set = RevocationSet::new(4).expect("set");
    let rust = |b: &[u8], h: &Head, now: u64, s: &RevocationSet| {
        Grant::from_bytes(b).and_then(|g| {
            g.verify(
                &alice_auth::AliceId(game),
                &ChainHead {
                    player: PlayerId(h.player),
                    key: alice_auth::AliceId(h.key),
                    since_ms: h.since_ms,
                },
                now,
                s,
            )
        })
    };
    let mut flipped = good;
    flipped[140] ^= 1;
    let mut v2 = good;
    v2[0] = 2;
    let other_key = Head {
        key: bytes(K1),
        ..head()
    };
    let cases: [(&str, Vec<u8>, Head, u64, GrantError); 7] = [
        (
            "length",
            good[..200].to_vec(),
            head(),
            2000,
            GrantError::Length,
        ),
        ("version", v2.to_vec(), head(), 2000, GrantError::Version),
        (
            "signature",
            flipped.to_vec(),
            head(),
            2000,
            GrantError::Signature,
        ),
        (
            "not yet",
            good.to_vec(),
            head(),
            1499,
            GrantError::NotYetValid,
        ),
        (
            "expired at the end",
            good.to_vec(),
            head(),
            5000,
            GrantError::Expired,
        ),
        (
            "another key",
            good.to_vec(),
            other_key,
            2000,
            GrantError::WrongKey,
        ),
        (
            "another game",
            good.to_vec(),
            head(),
            2000,
            GrantError::WrongGame,
        ),
    ];
    for (name, b, h, now, want) in cases {
        let expected_game = if name == "another game" {
            bytes::<32>(K1)
        } else {
            game
        };
        let rust_res = if name == "another game" {
            Err(GrantError::WrongGame)
        } else {
            rust(&b, &h, now, &rust_set).map(|_| ())
        };
        assert_eq!(rust_res, Err(want), "rust {name}");
        aa_clear_last_error();
        let (code, player, scope, expires) = verify(&b, &expected_game, &h, now, set);
        assert_refused(code, want, "aa_grant_verify", &player);
        assert_eq!(
            scope,
            u64::from_le_bytes([FILL; 8]),
            "{name}: scope written"
        );
        assert_eq!(
            expires,
            u64::from_le_bytes([FILL; 8]),
            "{name}: expiry written"
        );
    }
    // revoked
    let rev = bytes::<REVOCATION_LEN>(REVOCATION0);
    assert_eq!(
        unsafe { aa_revset_add(set, rev.as_ptr(), rev.len()) },
        AA_PLAYER_OK
    );
    assert_eq!(unsafe { aa_revset_len(set) }, 1);
    aa_clear_last_error();
    let (code, player, _, _) = verify(&good, &game, &head(), 2000, set);
    assert_refused(code, GrantError::Revoked, "aa_grant_verify", &player);
    unsafe { aa_revset_free(set) };
}

#[test]
fn issuing_refuses_with_the_rust_codes() {
    let g = handle(9);
    let mut out = [FILL; GRANT_LEN];
    for (ttl, now, want) in [
        (0, 1500, GrantError::Times),
        (2, u64::MAX - 1, GrantError::Overflow),
    ] {
        aa_clear_last_error();
        let code = unsafe {
            aa_grant_issue(
                g,
                bytes::<32>(PLAYER).as_ptr(),
                bytes::<32>(K2).as_ptr(),
                SCOPE,
                now,
                ttl,
                NONCE.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        assert_refused(code, want, "aa_grant_issue", &out);
    }
    // a link to the same key
    let h1 = handle(1);
    let mut link = [FILL; ROTATION_LINK_LEN];
    aa_clear_last_error();
    let code = unsafe {
        aa_rotation_link_issue(
            h1,
            bytes::<32>(PLAYER).as_ptr(),
            0,
            bytes::<32>(K1).as_ptr(),
            1000,
            link.as_mut_ptr(),
        )
    };
    assert_refused(code, GrantError::Chain, "aa_rotation_link_issue", &link);
    // a revocation by another game
    let mut rev = [FILL; REVOCATION_LEN];
    let grant = bytes::<GRANT_LEN>(GRANT0);
    aa_clear_last_error();
    let code =
        unsafe { aa_revocation_issue(h1, grant.as_ptr(), grant.len(), 3000, rev.as_mut_ptr()) };
    assert_refused(code, GrantError::WrongGame, "aa_revocation_issue", &rev);
    aa_clear_last_error();
    let code = unsafe { aa_revocation_issue(g, grant.as_ptr(), 200, 3000, rev.as_mut_ptr()) };
    assert_refused(code, GrantError::Length, "aa_revocation_issue", &rev);
    unsafe {
        aa_free(g);
        aa_free(h1);
    }
}

#[test]
fn the_revocation_set_through_the_c_abi() {
    assert!(aa_revset_new(0).is_null());
    assert!(last_error().is_some_and(|m| m.contains("aa_revset_new")));
    let set = aa_revset_new(1);
    let rev = bytes::<REVOCATION_LEN>(REVOCATION0);
    let mut forged = rev;
    forged[100] ^= 1;
    aa_clear_last_error();
    let code = unsafe { aa_revset_add(set, forged.as_ptr(), forged.len()) };
    assert_refused(code, GrantError::Signature, "aa_revset_add", &[]);
    aa_clear_last_error();
    let code = unsafe { aa_revset_add(set, rev.as_ptr(), 128) };
    assert_refused(code, GrantError::Length, "aa_revset_add", &[]);
    assert_eq!(unsafe { aa_revset_len(set) }, 0);
    assert_eq!(
        unsafe { aa_revset_add(set, rev.as_ptr(), rev.len()) },
        AA_PLAYER_OK
    );
    let game = bytes::<32>(GAME);
    assert_eq!(
        unsafe { aa_revset_contains(set, game.as_ptr(), NONCE.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { aa_revset_contains(set, game.as_ptr(), [9u8; 16].as_ptr()) },
        0
    );
    // full: another game's revocation is refused and the first stays
    let other = handle(8);
    let theirs = Grant::issue(
        &Identity::from_seed(&[8; 32]),
        PlayerId(bytes(PLAYER)),
        alice_auth::AliceId(bytes(K2)),
        SCOPE,
        1500,
        3500,
        NONCE,
    )
    .expect("grant");
    let mut r2 = [FILL; REVOCATION_LEN];
    assert_eq!(
        unsafe {
            aa_revocation_issue(
                other,
                theirs.to_bytes().as_ptr(),
                GRANT_LEN,
                3000,
                r2.as_mut_ptr(),
            )
        },
        AA_PLAYER_OK
    );
    aa_clear_last_error();
    let code = unsafe { aa_revset_add(set, r2.as_ptr(), r2.len()) };
    assert_refused(code, GrantError::Full, "aa_revset_add", &[]);
    assert_eq!(
        unsafe { aa_revset_contains(set, game.as_ptr(), NONCE.as_ptr()) },
        1
    );
    // purge only after the grant expired
    assert_eq!(unsafe { aa_revset_purge(set, 4999) }, 0);
    assert_eq!(unsafe { aa_revset_purge(set, 5000) }, 1);
    assert_eq!(unsafe { aa_revset_len(set) }, 0);
    unsafe {
        aa_revset_free(set);
        aa_free(other);
    }
}

/// A null argument is `GrantError::Null` with a message, never a crash, and writes nothing;
/// a null set or null query in `aa_revset_contains` reads as revoked (fail-closed).
#[test]
fn null_arguments_are_refused() {
    let g = handle(9);
    let k = bytes::<32>(K2);
    let p = bytes::<32>(PLAYER);
    let grant = bytes::<GRANT_LEN>(GRANT0);
    let mut out = [FILL; GRANT_LEN];
    let mut o32 = [FILL; 32];
    let mut since = 0u64;
    let set = aa_revset_new(1);
    let null_cases: Vec<(&str, i32)> = vec![
        ("aa_player_id_from_genesis", unsafe {
            aa_player_id_from_genesis(null(), o32.as_mut_ptr())
        }),
        ("aa_player_id_from_genesis", unsafe {
            aa_player_id_from_genesis(k.as_ptr(), null_mut())
        }),
        ("aa_rotation_link_issue", unsafe {
            aa_rotation_link_issue(null(), p.as_ptr(), 0, k.as_ptr(), 1000, out.as_mut_ptr())
        }),
        ("aa_rotation_link_issue", unsafe {
            aa_rotation_link_issue(g, p.as_ptr(), 0, k.as_ptr(), 1000, null_mut())
        }),
        ("aa_player_chain_resolve", unsafe {
            aa_player_chain_resolve(
                k.as_ptr(),
                null(),
                1,
                o32.as_mut_ptr(),
                o32.as_mut_ptr(),
                &mut since,
            )
        }),
        ("aa_player_chain_resolve", unsafe {
            aa_player_chain_resolve(
                k.as_ptr(),
                null(),
                0,
                o32.as_mut_ptr(),
                o32.as_mut_ptr(),
                null_mut(),
            )
        }),
        ("aa_grant_issue", unsafe {
            aa_grant_issue(
                g,
                p.as_ptr(),
                k.as_ptr(),
                SCOPE,
                1500,
                3500,
                null(),
                out.as_mut_ptr(),
            )
        }),
        ("aa_grant_verify", unsafe {
            aa_grant_verify(
                grant.as_ptr(),
                GRANT_LEN,
                k.as_ptr(),
                p.as_ptr(),
                k.as_ptr(),
                1000,
                2000,
                null(),
                o32.as_mut_ptr(),
                &mut since,
                &mut since,
            )
        }),
        ("aa_grant_verify", unsafe {
            aa_grant_verify(
                null(),
                GRANT_LEN,
                k.as_ptr(),
                p.as_ptr(),
                k.as_ptr(),
                1000,
                2000,
                set,
                o32.as_mut_ptr(),
                &mut since,
                &mut since,
            )
        }),
        ("aa_revocation_issue", unsafe {
            aa_revocation_issue(g, null(), GRANT_LEN, 3000, out.as_mut_ptr())
        }),
        ("aa_revset_add", unsafe {
            aa_revset_add(null_mut(), grant.as_ptr(), REVOCATION_LEN)
        }),
        ("aa_revset_add", unsafe {
            aa_revset_add(set, null(), REVOCATION_LEN)
        }),
    ];
    for (func, code) in null_cases {
        assert_eq!(code, GrantError::Null.code(), "{func}");
        assert!(last_error().is_some_and(|m| m.contains(func)), "{func}");
    }
    assert!(out.iter().all(|&b| b == FILL));
    assert_eq!(
        unsafe { aa_revset_contains(null(), k.as_ptr(), NONCE.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { aa_revset_contains(set, null(), NONCE.as_ptr()) },
        1
    );
    assert_eq!(unsafe { aa_revset_purge(null_mut(), 0) }, -1);
    assert_eq!(unsafe { aa_revset_len(null()) }, -1);
    unsafe {
        aa_revset_free(null_mut());
        aa_revset_free(set);
        aa_free(g);
    }
}
