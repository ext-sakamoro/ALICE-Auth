//! A game's grant to a player, its revocation, and the revocation set.
//!
//! References: the expected bytes below were computed by a separate program (Python,
//! `hashlib.sha256` and the RFC 8032 section 6 reference Ed25519, checked against RFC 8032
//! TEST 1 and 3), not by this crate. The game key is that of the seed `[9; 32]`, the player
//! is the one of `tests/player_chain.rs` (first key of the seed `[1; 32]`, moved to the key
//! of `[2; 32]` at 1000 ms). `GRANT0` gives that player, under the second key, the scope
//! `0x0123456789abcdef` from 1500 ms to 5000 ms with the nonce `00 01 .. 0f`, signed by the
//! game over `alice-auth/grant/v1/////` and its first 137 bytes. `REVOCATION0` revokes it at
//! 3000 ms (it carries the grant's expiry 5000), signed over `alice-auth/revoke/v1////` and
//! its first 65 bytes.

#![cfg(feature = "alloc")]

use alice_auth::{
    endorse, AliceId, AliceSig, ChainHead, Grant, GrantError, Identity, PlayerId, Revocation,
    RevocationSet, RotationLink, VerifiedGrant, GRANT_LEN, REVOCATION_LEN, TAG_GRANT_V1,
    TAG_PLAYER_ID_V1, TAG_REVOCATION_V1, TAG_ROTATION_V1,
};

const K1: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const K2: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const PLAYER: &str = "2b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f";
const GAME: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const GRANT0: &str = "012b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618efcdab8967452301dc050000000000008813000000000000000102030405060708090a0b0c0d0e0f39e83927a5408ab80f3ba57dacf6a4c75790413481309616f3d9a33dc96e7bdfdccf211b934e80da2fbc37b5879ec560e9759d0d9342c3d62731c889eada010a";
const REVOCATION0: &str = "01fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618000102030405060708090a0b0c0d0e0f8813000000000000b80b000000000000a61440e192f02a1f7cd56f24a200eee887f50da939ebace082532ea3f95c2b8e283ab093886ab42c28401a504d1c88310951383fc8ab1d17b160e9361c0a5f0b";

const SCOPE: u64 = 0x0123_4567_89ab_cdef;
const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "{hex}");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn key(hex: &str) -> AliceId {
    AliceId(bytes(hex))
}

fn game() -> Identity {
    Identity::from_seed(&[9; 32])
}

fn player() -> PlayerId {
    PlayerId(bytes(PLAYER))
}

/// The player's chain end after the reference link: the second key, current from 1000 ms.
fn head() -> ChainHead {
    ChainHead {
        player: player(),
        key: key(K2),
        since_ms: 1000,
    }
}

fn grant0() -> Grant {
    Grant::from_bytes(&bytes::<GRANT_LEN>(GRANT0)).expect("GRANT0 parses")
}

fn revocation0() -> Revocation {
    Revocation::from_bytes(&bytes::<REVOCATION_LEN>(REVOCATION0)).expect("REVOCATION0 parses")
}

fn empty() -> RevocationSet {
    RevocationSet::new(8).expect("capacity 8")
}

fn ok_at(now_ms: u64) -> Result<VerifiedGrant, GrantError> {
    grant0().verify(&key(GAME), &head(), now_ms, &empty())
}

fn verified() -> VerifiedGrant {
    VerifiedGrant {
        player: player(),
        scope: SCOPE,
        expires_ms: 5000,
    }
}

fn tagged(tag: &[u8; 24], body: &[u8]) -> Vec<u8> {
    let mut m = tag.to_vec();
    m.extend_from_slice(body);
    m
}

#[test]
fn wire_lengths_are_fixed() {
    assert_eq!(GRANT_LEN, 201);
    assert_eq!(REVOCATION_LEN, 129);
    assert_eq!(game().id(), key(GAME));
}

#[test]
fn issued_grant_and_revocation_are_the_reference_bytes() {
    let g = Grant::issue(&game(), player(), key(K2), SCOPE, 1500, 3500, NONCE).expect("issue");
    assert_eq!(g.to_bytes(), bytes::<GRANT_LEN>(GRANT0));
    let r = Revocation::issue(&game(), &g, 3000).expect("revoke");
    assert_eq!(r.to_bytes(), bytes::<REVOCATION_LEN>(REVOCATION0));
    // same inputs, same bytes
    let again = Grant::issue(&game(), player(), key(K2), SCOPE, 1500, 3500, NONCE).expect("issue");
    assert_eq!(again, g);
}

#[test]
fn the_wire_forms_round_trip_field_by_field() {
    let g = grant0();
    assert_eq!(
        (
            g.player,
            g.player_key,
            g.game,
            g.scope,
            g.issued_ms,
            g.expires_ms,
            g.nonce
        ),
        (player(), key(K2), key(GAME), SCOPE, 1500, 5000, NONCE)
    );
    assert_eq!(Grant::from_bytes(&g.to_bytes()), Ok(g));
    let r = revocation0();
    assert_eq!(
        (r.game, r.nonce, r.grant_expires_ms, r.revoked_ms),
        (key(GAME), NONCE, 5000, 3000)
    );
    assert_eq!(Revocation::from_bytes(&r.to_bytes()), Ok(r));
}

#[test]
fn other_lengths_and_versions_are_refused() {
    let g = bytes::<GRANT_LEN>(GRANT0);
    let r = bytes::<REVOCATION_LEN>(REVOCATION0);
    for n in [0, 1, 136, 137, 200, 202] {
        let v: Vec<u8> = g
            .iter()
            .copied()
            .chain(core::iter::repeat(0))
            .take(n)
            .collect();
        assert_eq!(
            Grant::from_bytes(&v),
            Err(GrantError::Length),
            "grant length {n}"
        );
    }
    for n in [0, 1, 64, 65, 128, 130, 173, 201] {
        let v: Vec<u8> = r
            .iter()
            .copied()
            .chain(core::iter::repeat(0))
            .take(n)
            .collect();
        assert_eq!(
            Revocation::from_bytes(&v),
            Err(GrantError::Length),
            "revocation length {n}"
        );
    }
    for version in [0u8, 2, 0xff] {
        let mut b = g;
        b[0] = version;
        assert_eq!(Grant::from_bytes(&b), Err(GrantError::Version));
        let mut b = r;
        b[0] = version;
        assert_eq!(Revocation::from_bytes(&b), Err(GrantError::Version));
    }
}

#[test]
fn a_valid_grant_is_accepted_inside_its_window() {
    for now in [1500, 1501, 3000, 4999] {
        assert_eq!(ok_at(now), Ok(verified()), "at {now}");
    }
}

/// The window is `issued <= now < expires`: the end is excluded.
#[test]
fn the_window_ends_before_expires() {
    assert_eq!(ok_at(1499), Err(GrantError::NotYetValid));
    assert_eq!(ok_at(0), Err(GrantError::NotYetValid));
    assert_eq!(ok_at(5000), Err(GrantError::Expired));
    assert_eq!(ok_at(5001), Err(GrantError::Expired));
    assert_eq!(ok_at(u64::MAX), Err(GrantError::Expired));
}

#[test]
fn issuing_refuses_an_empty_or_overflowing_window() {
    let g = game();
    assert_eq!(
        Grant::issue(&g, player(), key(K2), SCOPE, 1500, 0, NONCE),
        Err(GrantError::Times)
    );
    assert_eq!(
        Grant::issue(&g, player(), key(K2), SCOPE, u64::MAX - 1, 2, NONCE),
        Err(GrantError::Overflow)
    );
    // the largest window that fits ends at u64::MAX
    let last = Grant::issue(&g, player(), key(K2), SCOPE, u64::MAX - 2, 2, NONCE).expect("fits");
    assert_eq!(last.expires_ms, u64::MAX);
}

/// A grant signed with an empty window (built by hand, not by `issue`) is refused.
#[test]
fn a_signed_grant_with_an_empty_window_is_refused() {
    for (issued, expires) in [(5000, 5000), (5000, 1500)] {
        let g = hand_signed_grant(&game(), issued, expires, NONCE);
        assert_eq!(
            g.verify(&key(GAME), &head(), 5000, &empty()),
            Err(GrantError::Times),
            "{issued}..{expires}"
        );
    }
}

#[test]
fn another_games_grant_is_refused() {
    let other = Identity::from_seed(&[8; 32]);
    assert_eq!(
        grant0().verify(&other.id(), &head(), 2000, &empty()),
        Err(GrantError::WrongGame)
    );
    // the other game's own grant, checked by this game
    let g = Grant::issue(&other, player(), key(K2), SCOPE, 1500, 3500, NONCE).expect("issue");
    assert_eq!(
        g.verify(&key(GAME), &head(), 2000, &empty()),
        Err(GrantError::WrongGame)
    );
    assert_eq!(
        g.verify(&other.id(), &head(), 2000, &empty()),
        Ok(verified())
    );
}

#[test]
fn a_grant_for_a_key_that_is_not_current_is_refused() {
    // the player moved on to a third key
    let moved = ChainHead {
        key: Identity::from_seed(&[3; 32]).id(),
        since_ms: 2000,
        ..head()
    };
    assert_eq!(
        grant0().verify(&key(GAME), &moved, 2500, &empty()),
        Err(GrantError::WrongKey)
    );
    // a grant that names a key the player had not used (the current key is older than it)
    let other_key = ChainHead {
        key: Identity::from_seed(&[3; 32]).id(),
        ..head()
    };
    assert_eq!(
        grant0().verify(&key(GAME), &other_key, 2500, &empty()),
        Err(GrantError::WrongKey)
    );
    // the same key, but it became current again after the grant was issued
    let again = ChainHead {
        since_ms: 1501,
        ..head()
    };
    assert_eq!(
        grant0().verify(&key(GAME), &again, 2500, &empty()),
        Err(GrantError::WrongKey)
    );
    // another player with the same key
    let other = ChainHead {
        player: PlayerId::from_genesis(&key(K2)),
        ..head()
    };
    assert_eq!(
        grant0().verify(&key(GAME), &other, 2500, &empty()),
        Err(GrantError::WrongKey)
    );
    // the key current since exactly the grant's issue time is fine
    let exact = ChainHead {
        since_ms: 1500,
        ..head()
    };
    assert_eq!(
        grant0().verify(&key(GAME), &exact, 2500, &empty()),
        Ok(verified())
    );
}

#[test]
fn a_grant_works_with_the_head_resolve_chain_returns() {
    let link = RotationLink::issue(&Identity::from_seed(&[1; 32]), player(), 0, key(K2), 1000)
        .expect("link");
    let h = alice_auth::resolve_chain(&key(K1), &[link]).expect("chain");
    assert_eq!(h, head());
    assert_eq!(
        grant0().verify(&key(GAME), &h, 2000, &empty()),
        Ok(verified())
    );
}

#[test]
fn every_flipped_bit_of_a_grant_is_refused() {
    let good = bytes::<GRANT_LEN>(GRANT0);
    for bit in 0..GRANT_LEN * 8 {
        let mut b = good;
        b[bit / 8] ^= 1 << (bit % 8);
        let refused = Grant::from_bytes(&b)
            .and_then(|g| g.verify(&key(GAME), &head(), 2000, &empty()))
            .is_err();
        assert!(refused, "bit {bit} was accepted");
    }
}

/// The signature is checked before any field decides the result: a grant whose
/// signature is broken is refused as such even when its times are also out of range.
#[test]
fn the_signature_is_checked_before_the_fields() {
    let mut g = grant0();
    g.sig.0[10] ^= 1;
    for now in [0, 2000, 5000] {
        assert_eq!(
            g.verify(&key(GAME), &head(), now, &empty()),
            Err(GrantError::Signature),
            "at {now}"
        );
    }
}

/// The grant's signature covers the grant tag; signatures made in the other domains of the
/// crate (no tag, another tag, an endorsement of the same key) are not a grant.
#[test]
fn a_signature_made_for_another_domain_is_refused() {
    let good = grant0();
    let body: [u8; 137] = good.to_bytes()[..137].try_into().expect("137");
    let g = game();
    let e = endorse(&g, &key(K2), 1500, 3500).expect("endorse");
    for (name, sig) in [
        ("untagged", g.sign(&body)),
        ("revocation tag", g.sign(&tagged(TAG_REVOCATION_V1, &body))),
        ("rotation tag", g.sign(&tagged(TAG_ROTATION_V1, &body))),
        ("player id tag", g.sign(&tagged(TAG_PLAYER_ID_V1, &body))),
        ("endorsement", e.sig),
        ("revocation", revocation0().sig),
    ] {
        let x = Grant { sig, ..good };
        assert_eq!(
            x.verify(&key(GAME), &head(), 2000, &empty()),
            Err(GrantError::Signature),
            "{name}"
        );
    }
}

#[test]
fn a_revoked_grant_is_refused() {
    let mut set = empty();
    assert_eq!(set.add(&revocation0()), Ok(()));
    assert!(set.contains(&key(GAME), &NONCE));
    assert_eq!(
        grant0().verify(&key(GAME), &head(), 2000, &set),
        Err(GrantError::Revoked)
    );
    // revocation is checked last: a revoked grant that also expired reports the expiry
    assert_eq!(
        grant0().verify(&key(GAME), &head(), 5000, &set),
        Err(GrantError::Expired)
    );
    // another nonce of the same game is not revoked
    let g = Grant::issue(&game(), player(), key(K2), SCOPE, 1500, 3500, [7; 16]).expect("issue");
    assert_eq!(
        g.verify(&key(GAME), &head(), 2000, &set).map(|v| v.scope),
        Ok(SCOPE)
    );
}

#[test]
fn only_the_issuing_game_can_revoke() {
    let other = Identity::from_seed(&[8; 32]);
    assert_eq!(
        Revocation::issue(&other, &grant0(), 3000),
        Err(GrantError::WrongGame)
    );
    // a revocation that names the game but is signed by another key
    let forged = Revocation {
        sig: other.sign(&tagged(TAG_REVOCATION_V1, &revocation0().to_bytes()[..65])),
        ..revocation0()
    };
    let mut set = empty();
    assert_eq!(set.add(&forged), Err(GrantError::Signature));
    assert_eq!(set.len(), 0);
    // the other game's revocation of a grant with the same nonce does not touch this game
    let theirs = Grant::issue(&other, player(), key(K2), SCOPE, 1500, 3500, NONCE).expect("issue");
    let r = Revocation::issue(&other, &theirs, 3000).expect("revoke");
    assert_eq!(set.add(&r), Ok(()));
    assert_eq!(
        grant0().verify(&key(GAME), &head(), 2000, &set),
        Ok(verified())
    );
}

#[test]
fn every_flipped_bit_of_a_revocation_is_refused() {
    let good = bytes::<REVOCATION_LEN>(REVOCATION0);
    for bit in 0..REVOCATION_LEN * 8 {
        let mut b = good;
        b[bit / 8] ^= 1 << (bit % 8);
        let mut set = empty();
        let refused = Revocation::from_bytes(&b)
            .and_then(|r| set.add(&r))
            .is_err();
        assert!(refused, "bit {bit} was accepted");
        assert_eq!(set.len(), 0, "bit {bit} stored something");
    }
}

#[test]
fn a_revocation_signature_from_another_domain_is_refused() {
    let good = revocation0();
    let body: [u8; 65] = good.to_bytes()[..65].try_into().expect("65");
    let g = game();
    for (name, sig) in [
        ("untagged", g.sign(&body)),
        ("grant tag", g.sign(&tagged(TAG_GRANT_V1, &body))),
        ("rotation tag", g.sign(&tagged(TAG_ROTATION_V1, &body))),
        ("grant", grant0().sig),
    ] {
        let mut set = empty();
        assert_eq!(
            set.add(&Revocation { sig, ..good }),
            Err(GrantError::Signature),
            "{name}"
        );
    }
}

/// A full set refuses the next revocation and keeps every one it holds.
#[test]
fn a_full_set_refuses_and_keeps_what_it_holds() {
    let g = game();
    let mut set = RevocationSet::new(2).expect("capacity 2");
    let grants: Vec<Grant> = (0u8..3)
        .map(|i| Grant::issue(&g, player(), key(K2), SCOPE, 1500, 3500, [i; 16]).expect("issue"))
        .collect();
    for gr in &grants[..2] {
        assert_eq!(
            set.add(&Revocation::issue(&g, gr, 3000).expect("r")),
            Ok(())
        );
    }
    let third = Revocation::issue(&g, &grants[2], 3000).expect("r");
    assert_eq!(set.add(&third), Err(GrantError::Full));
    assert_eq!((set.len(), set.capacity()), (2, 2));
    for gr in &grants[..2] {
        assert_eq!(
            gr.verify(&key(GAME), &head(), 2000, &set),
            Err(GrantError::Revoked)
        );
    }
    assert!(grants[2].verify(&key(GAME), &head(), 2000, &set).is_ok());
    // adding a revocation it already holds is not a new entry, even when full
    let again = Revocation::issue(&g, &grants[0], 3500).expect("r");
    assert_eq!(set.add(&again), Ok(()));
    assert_eq!(set.len(), 2);
}

#[test]
fn a_set_needs_room_for_one() {
    assert_eq!(RevocationSet::new(0).err(), Some(GrantError::Full));
    assert_eq!(RevocationSet::new(1).map(|s| s.capacity()), Ok(1));
}

/// Purging removes only revocations whose grant has expired anyway (`grant_expires <= now`),
/// so it never lets a revoked grant through.
#[test]
fn purging_removes_only_revocations_of_expired_grants() {
    let g = game();
    let early = Grant::issue(&g, player(), key(K2), SCOPE, 1500, 1000, [1; 16]).expect("issue");
    let mut set = empty();
    assert_eq!(
        set.add(&Revocation::issue(&g, &early, 2000).expect("r")),
        Ok(())
    );
    assert_eq!(set.add(&revocation0()), Ok(()));
    assert_eq!(set.purge(2499), 0);
    assert_eq!(set.purge(2500), 1);
    assert_eq!(set.len(), 1);
    assert_eq!(
        grant0().verify(&key(GAME), &head(), 4999, &set),
        Err(GrantError::Revoked)
    );
    assert_eq!(set.purge(4999), 0);
    assert_eq!(set.purge(5000), 1);
    assert_eq!(set.len(), 0);
}

/// A grant signed over the grant tag and the given window without the checks `issue` makes.
fn hand_signed_grant(signer: &Identity, issued_ms: u64, expires_ms: u64, nonce: [u8; 16]) -> Grant {
    let mut m = TAG_GRANT_V1.to_vec();
    m.push(1u8);
    m.extend_from_slice(&player().0);
    m.extend_from_slice(&key(K2).0);
    m.extend_from_slice(&signer.id().0);
    m.extend_from_slice(&SCOPE.to_le_bytes());
    m.extend_from_slice(&issued_ms.to_le_bytes());
    m.extend_from_slice(&expires_ms.to_le_bytes());
    m.extend_from_slice(&nonce);
    Grant {
        player: player(),
        player_key: key(K2),
        game: signer.id(),
        scope: SCOPE,
        issued_ms,
        expires_ms,
        nonce,
        sig: AliceSig(signer.sign(&m).0),
    }
}
