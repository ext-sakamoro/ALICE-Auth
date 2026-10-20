//! A player's id and its key rotation chain.
//!
//! References: the expected bytes below were computed by a separate program (Python,
//! `hashlib.sha256` and the RFC 8032 section 6 reference Ed25519, checked against RFC 8032
//! TEST 1 and 3), not by this crate. Keys are those of the seeds `[1; 32]`, `[2; 32]` and
//! `[3; 32]`; `PLAYER` is SHA-256 of `alice-auth/player-id/v1/` and the first key; `LINK0`
//! moves the player from the first key to the second at 1000 ms and `LINK1` from the
//! second to the third at 2000 ms, each signed by the key it leaves over
//! `alice-auth/rotate/v1////` and the link's first 109 bytes.

use alice_auth::{
    resolve_chain, AliceId, AliceSig, ChainHead, GrantError, Identity, PlayerId, RotationLink,
    ROTATION_LINK_LEN, TAG_GRANT_V1, TAG_PLAYER_ID_V1, TAG_REVOCATION_V1, TAG_ROTATION_V1,
};

const K1: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const K2: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const K3: &str = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";
const PLAYER: &str = "2b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f";
const LINK0: &str = "012b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394e8030000000000001bafc28ddbb05a7fe3788452af7c95562ffe3dec38d769f8b9c0c9a7a8cd6cee635663f8153bdf391ff1009cf0e4f0233f971e6ba00ebedb1b9b3400db812707";
const LINK1: &str = "012b512b6e41b5d7005a4dfd97677df1e9823997d03a25970d476acb331f14b03f010000008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1d00700000000000077ed2f504e97659ea3dcbf33b358a4dd01a2e6bdfa65c61061b37fba5c31e819ceb4e5e4b90d8d2399b7bc08895abf253b1d5beeee9a09d8b1ed0417d98be406";

/// The identity point (a small-order key) and R = B, S = 1, which a plain Ed25519 check
/// accepts under it for every message (the same vector as `tests/verify_strict.rs`).
const SMALL_ORDER_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const ANY_MESSAGE: &str = "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000";
/// LINK0's body signed by the first key with R the identity point (small order) and
/// S = k a mod L, computed by the same separate program: a plain Ed25519 check accepts
/// it ([S]B = R + [k]A holds), a strict one refuses the small-order R.
const LINK0_SMALL_ORDER_R_SIG: &str = "0100000000000000000000000000000000000000000000000000000000000000d4cd77ec3bc51075eee33e1362a22588ff4421c4e2c30c303307854252215a07";

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "{hex}");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn key(hex: &str) -> AliceId {
    AliceId(bytes(hex))
}

fn identity(b: u8) -> Identity {
    Identity::from_seed(&[b; 32])
}

/// `i`'s Ed25519 signature of `m` made from its seed, outside the crate: the
/// public signing paths refuse a message under the reserved prefix, and these
/// tests need signatures over the crate's tagged formats made by hand
fn raw_sign(i: &Identity, m: &[u8]) -> AliceSig {
    use ed25519_dalek::Signer;
    AliceSig(
        ed25519_dalek::SigningKey::from_bytes(&i.seed())
            .sign(m)
            .to_bytes(),
    )
}

fn link0() -> RotationLink {
    RotationLink::from_bytes(&bytes::<ROTATION_LINK_LEN>(LINK0)).expect("LINK0 parses")
}

fn link1() -> RotationLink {
    RotationLink::from_bytes(&bytes::<ROTATION_LINK_LEN>(LINK1)).expect("LINK1 parses")
}

fn head(player: &str, k: &str, since_ms: u64) -> ChainHead {
    ChainHead {
        player: PlayerId(bytes(player)),
        key: key(k),
        since_ms,
    }
}

#[test]
fn tags_are_24_bytes_and_distinct() {
    let tags: [&[u8; 24]; 4] = [
        TAG_PLAYER_ID_V1,
        TAG_GRANT_V1,
        TAG_REVOCATION_V1,
        TAG_ROTATION_V1,
    ];
    assert_eq!(TAG_PLAYER_ID_V1, b"alice-auth/player-id/v1/");
    assert_eq!(TAG_GRANT_V1, b"alice-auth/grant/v1/////");
    assert_eq!(TAG_REVOCATION_V1, b"alice-auth/revoke/v1////");
    assert_eq!(TAG_ROTATION_V1, b"alice-auth/rotate/v1////");
    for (i, a) in tags.iter().enumerate() {
        for b in &tags[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(ROTATION_LINK_LEN, 173);
}

#[test]
fn player_id_is_the_tagged_hash_of_the_first_key() {
    assert_eq!(identity(1).id(), key(K1));
    assert_eq!(PlayerId::from_genesis(&key(K1)), PlayerId(bytes(PLAYER)));
    assert_ne!(PlayerId::from_genesis(&key(K2)), PlayerId(bytes(PLAYER)));
}

#[test]
fn issued_links_are_the_reference_bytes() {
    let player = PlayerId::from_genesis(&key(K1));
    let l0 = RotationLink::issue(&identity(1), player, 0, key(K2), 1000).expect("issue 0");
    let l1 = RotationLink::issue(&identity(2), player, 1, key(K3), 2000).expect("issue 1");
    assert_eq!(l0.to_bytes(), bytes::<ROTATION_LINK_LEN>(LINK0));
    assert_eq!(l1.to_bytes(), bytes::<ROTATION_LINK_LEN>(LINK1));
    // same inputs, same bytes (Ed25519 signatures are deterministic)
    let again = RotationLink::issue(&identity(1), player, 0, key(K2), 1000).expect("issue 0");
    assert_eq!(again, l0);
}

#[test]
fn the_wire_form_round_trips_field_by_field() {
    let l = link0();
    assert_eq!(l.player, PlayerId(bytes(PLAYER)));
    assert_eq!(l.seq, 0);
    assert_eq!(l.old_key, key(K1));
    assert_eq!(l.new_key, key(K2));
    assert_eq!(l.issued_ms, 1000);
    assert_eq!(RotationLink::from_bytes(&l.to_bytes()), Ok(l));
}

#[test]
fn other_lengths_and_versions_are_refused() {
    let good = bytes::<ROTATION_LINK_LEN>(LINK0);
    for n in [0, 1, 108, 109, 172, 174, 200] {
        let mut v = vec![0u8; n];
        let k = n.min(ROTATION_LINK_LEN);
        v[..k].copy_from_slice(&good[..k]);
        assert_eq!(
            RotationLink::from_bytes(&v),
            Err(GrantError::Length),
            "length {n}"
        );
    }
    for version in [0u8, 2, 0xff] {
        let mut b = good;
        b[0] = version;
        assert_eq!(
            RotationLink::from_bytes(&b),
            Err(GrantError::Version),
            "version {version}"
        );
    }
}

#[test]
fn no_link_leaves_the_first_key_current_from_the_start() {
    assert_eq!(resolve_chain(&key(K1), &[]), Ok(head(PLAYER, K1, 0)));
}

#[test]
fn the_chain_ends_at_the_last_key_and_keeps_the_player() {
    assert_eq!(
        resolve_chain(&key(K1), &[link0()]),
        Ok(head(PLAYER, K2, 1000))
    );
    assert_eq!(
        resolve_chain(&key(K1), &[link0(), link1()]),
        Ok(head(PLAYER, K3, 2000))
    );
}

#[test]
fn every_flipped_bit_of_a_link_is_refused() {
    for (name, hex, prefix) in [("LINK0", LINK0, 0usize), ("LINK1", LINK1, 1)] {
        let good = bytes::<ROTATION_LINK_LEN>(hex);
        for bit in 0..ROTATION_LINK_LEN * 8 {
            let mut b = good;
            b[bit / 8] ^= 1 << (bit % 8);
            let refused = match RotationLink::from_bytes(&b) {
                Err(_) => true,
                Ok(l) => {
                    let mut links = vec![link0()];
                    links.truncate(prefix);
                    links.push(l);
                    resolve_chain(&key(K1), &links).is_err()
                }
            };
            assert!(refused, "{name} bit {bit} was accepted");
        }
    }
}

#[test]
fn links_out_of_order_or_skipped_are_refused() {
    assert_eq!(
        resolve_chain(&key(K1), &[link1()]),
        Err(GrantError::Signature)
    );
    assert_eq!(
        resolve_chain(&key(K1), &[link1(), link0()]),
        Err(GrantError::Signature)
    );
    assert_eq!(
        resolve_chain(&key(K1), &[link0(), link0()]),
        Err(GrantError::Signature)
    );
    assert_eq!(
        resolve_chain(&key(K2), &[link0()]),
        Err(GrantError::Signature)
    );
}

/// A link that its key really signed is still refused when a field does not continue
/// the chain: the signature binds the bytes, the chain rules bind the order.
#[test]
fn a_correctly_signed_link_that_breaks_the_chain_is_refused() {
    let player = PlayerId::from_genesis(&key(K1));
    let id1 = identity(1);
    let other = PlayerId::from_genesis(&key(K3));
    let cases: [(&str, Result<RotationLink, GrantError>); 4] = [
        (
            "seq 1 first",
            RotationLink::issue(&id1, player, 1, key(K2), 1000),
        ),
        (
            "another player",
            RotationLink::issue(&id1, other, 0, key(K2), 1000),
        ),
        (
            "issued at 0",
            RotationLink::issue(&id1, player, 0, key(K2), 0),
        ),
        (
            "seq u32::MAX",
            RotationLink::issue(&id1, player, u32::MAX, key(K2), 1000),
        ),
    ];
    for (name, l) in cases {
        let l = l.expect(name);
        assert_eq!(
            resolve_chain(&key(K1), &[l]),
            Err(GrantError::Chain),
            "{name}"
        );
    }
    // time must move forward: the second link at the first link's time, and before it
    for t in [1000, 999] {
        let l = RotationLink::issue(&identity(2), player, 1, key(K3), t).expect("issue");
        assert_eq!(
            resolve_chain(&key(K1), &[link0(), l]),
            Err(GrantError::Chain),
            "at {t}"
        );
    }
}

#[test]
fn rotating_to_the_same_key_or_a_weak_key_is_refused() {
    let player = PlayerId::from_genesis(&key(K1));
    assert_eq!(
        RotationLink::issue(&identity(1), player, 0, key(K1), 1000),
        Err(GrantError::Chain)
    );
    assert_eq!(
        RotationLink::issue(&identity(1), player, 0, key(SMALL_ORDER_KEY), 1000),
        Err(GrantError::Chain)
    );
    // the same links built by hand (no check at issue) are refused by the chain
    for new in [K1, SMALL_ORDER_KEY] {
        let l = hand_signed(&identity(1), player, 0, &key(K1), &key(new), 1000);
        assert_eq!(
            resolve_chain(&key(K1), &[l]),
            Err(GrantError::Chain),
            "to {new}"
        );
    }
}

/// The signature is checked under the key the chain is at, and the link must also name
/// that key: a link the current key signed but whose `old_key` names another key is not
/// a continuation.
#[test]
fn a_link_naming_another_old_key_is_refused() {
    let player = PlayerId::from_genesis(&key(K1));
    let l = hand_signed(&identity(1), player, 0, &key(K3), &key(K2), 1000);
    assert_eq!(resolve_chain(&key(K1), &[l]), Err(GrantError::Chain));
}

/// Every link is checked, not only the last one.
#[test]
fn a_bad_link_before_a_good_one_is_refused() {
    let mut bad = link0();
    bad.sig.0[0] ^= 1;
    assert_eq!(
        resolve_chain(&key(K1), &[bad, link1()]),
        Err(GrantError::Signature)
    );
    let mut bad = link0();
    bad.seq = 7;
    assert_eq!(
        resolve_chain(&key(K1), &[bad, link1()]),
        Err(GrantError::Signature)
    );
}

#[test]
fn a_link_with_a_small_order_r_is_refused() {
    let l = RotationLink {
        sig: AliceSig(bytes(LINK0_SMALL_ORDER_R_SIG)),
        ..link0()
    };
    assert_eq!(resolve_chain(&key(K1), &[l]), Err(GrantError::Signature));
}

#[test]
fn a_weak_first_key_is_refused() {
    assert_eq!(
        resolve_chain(&key(SMALL_ORDER_KEY), &[]),
        Err(GrantError::Chain)
    );
}

/// The small-order key with R = B, S = 1 passes a plain Ed25519 check for every message;
/// the chain refuses the weak key, and the strict check refuses the signature.
#[test]
fn a_link_signed_under_the_small_order_key_is_refused() {
    let genesis = key(SMALL_ORDER_KEY);
    let player = PlayerId::from_genesis(&genesis);
    let l = RotationLink {
        player,
        seq: 0,
        old_key: genesis,
        new_key: key(K2),
        issued_ms: 1000,
        sig: AliceSig(bytes(ANY_MESSAGE)),
    };
    assert!(resolve_chain(&genesis, &[l]).is_err());
}

/// The link's signature covers the rotation tag: the same bytes signed without the tag,
/// or under another tag of the crate, are not a link.
#[test]
fn a_signature_made_for_another_domain_is_refused() {
    let good = link0();
    let body: [u8; 109] = good.to_bytes()[..109].try_into().expect("109");
    let id1 = identity(1);
    let tagged = |tag: &[u8; 24]| {
        let mut m = tag.to_vec();
        m.extend_from_slice(&body);
        raw_sign(&id1, &m)
    };
    for (name, sig) in [
        ("untagged", raw_sign(&id1, &body)),
        ("grant tag", tagged(TAG_GRANT_V1)),
        ("revocation tag", tagged(TAG_REVOCATION_V1)),
        ("player id tag", tagged(TAG_PLAYER_ID_V1)),
    ] {
        let l = RotationLink { sig, ..good };
        assert_eq!(
            resolve_chain(&key(K1), &[l]),
            Err(GrantError::Signature),
            "{name}"
        );
    }
    // the rotation tag itself is the one that verifies
    let l = RotationLink {
        sig: tagged(TAG_ROTATION_V1),
        ..good
    };
    assert_eq!(resolve_chain(&key(K1), &[l]), Ok(head(PLAYER, K2, 1000)));
}

#[test]
fn error_codes_are_fixed() {
    let codes = [
        (GrantError::Null, -1),
        (GrantError::Length, -2),
        (GrantError::Version, -3),
        (GrantError::Signature, -4),
        (GrantError::WrongGame, -5),
        (GrantError::NotYetValid, -6),
        (GrantError::Expired, -7),
        (GrantError::Revoked, -8),
        (GrantError::Times, -9),
        (GrantError::WrongKey, -10),
        (GrantError::Overflow, -11),
        (GrantError::Full, -12),
        (GrantError::Chain, -13),
        (GrantError::Rng, -14),
    ];
    let mut texts = Vec::new();
    for (e, c) in codes {
        assert_eq!(e.code(), c, "{e:?}");
        let t = e.to_string();
        assert!(!t.is_empty(), "{e:?}");
        assert!(!texts.contains(&t), "{e:?} repeats {t}");
        texts.push(t);
    }
}

/// A link signed over the rotation tag without the checks `issue` makes.
fn hand_signed(
    signer: &Identity,
    player: PlayerId,
    seq: u32,
    old: &AliceId,
    new: &AliceId,
    issued_ms: u64,
) -> RotationLink {
    let mut m = TAG_ROTATION_V1.to_vec();
    m.push(1u8);
    m.extend_from_slice(&player.0);
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&old.0);
    m.extend_from_slice(&new.0);
    m.extend_from_slice(&issued_ms.to_le_bytes());
    RotationLink {
        player,
        seq,
        old_key: *old,
        new_key: *new,
        issued_ms,
        sig: raw_sign(signer, &m),
    }
}
