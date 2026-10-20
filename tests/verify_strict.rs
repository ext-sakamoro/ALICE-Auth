//! Signature verification is strict at every public entry.
//!
//! References: RFC 8032 section 7.1 TEST 1-3 (accepted), and vectors built by a separate
//! program with curve25519-dalek (values copied here) that a plain Ed25519 check accepts
//! and a strict one refuses: a signature under the small-order key (the identity point;
//! R = B, S = 1 verifies for every message with a plain check), a small-order R under an
//! ordinary key, and the small-order key in a non-canonical encoding. Both checks refuse
//! an S not reduced modulo the group order and a non-canonical encoding of R.
//!
//! Every entry below reaches the crate's single verification function; each route test
//! hands it the small-order key and the signature that verifies under it for any message.

use alice_auth::{
    check, ok, verify, verify32, verify_endorsement, verify_recovery_approval, AliceId, AliceSig,
    AuthResult, Endorsement, Identity, Pending, RecoveryApproval, Response,
};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "{hex}");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn message(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// RFC 8032 section 7.1 TEST 1, 2 and 3: (secret key, public key, message, signature)
const RFC8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

/// The message of the built vectors ("alice-sign strict")
const MSG: &str = "616c6963652d7369676e20737472696374";
/// The key of the seed [7; 32]
const KEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
/// A valid signature of MSG under KEY
const GOOD: &str = "6ced1642c551e1d628df7b945c52b2d7ea0837dea0e5a380617f94aaf99df8e7606989c853d91d97fe6a8493ef6ee5a980ca33684d316ca1229cf4eaf539dc0b";
/// The identity point (a small-order key)
const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
/// R = B, S = 1: verifies under IDENTITY for any message with a plain check
const ANY_MESSAGE: &str = "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000";
/// The identity point written as y = p + 1
const IDENTITY_NON_CANONICAL: &str =
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
/// Under KEY: R = identity, S = k·a
const SMALL_ORDER_R: &str = "0100000000000000000000000000000000000000000000000000000000000000327b035e297e0853b2a3d6866fbde47f8afcea8bca3fba0e17e6df3c85e84408";
/// GOOD with S + l
const S_PLUS_L: &str = "6ced1642c551e1d628df7b945c52b2d7ea0837dea0e5a380617f94aaf99df8e74d3d7f256e3c30efd4077c36ce68c4be80ca33684d316ca1229cf4eaf539dc1b";
/// Under KEY: R = identity written as y = p + 1
const R_NON_CANONICAL: &str = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f7d7e3e82cad0bb5a7cf936d4094d855a9ed420d9b7a00e0dc7f53fd3634ae708";

fn id(hex: &str) -> AliceId {
    AliceId(bytes::<32>(hex))
}

fn sig(hex: &str) -> AliceSig {
    AliceSig(bytes::<64>(hex))
}

#[test]
fn rfc8032_vectors_are_accepted() {
    for (secret, public, msg, s) in RFC8032 {
        let identity = Identity::from_seed(&bytes::<32>(secret));
        assert_eq!(identity.id(), id(public), "{public}");
        let msg = message(msg);
        assert_eq!(identity.sign(&msg), sig(s), "{s}");
        assert_eq!(verify(&id(public), &msg, &sig(s)), Ok(()), "{s}");
    }
}

#[test]
fn a_signature_under_the_small_order_key_is_refused() {
    for msg in [message(MSG), b"any other message".to_vec(), Vec::new()] {
        assert!(
            verify(&id(IDENTITY), &msg, &sig(ANY_MESSAGE)).is_err(),
            "{msg:?}"
        );
    }
}

#[test]
fn a_small_order_r_is_refused() {
    assert!(verify(&id(KEY), &message(MSG), &sig(SMALL_ORDER_R)).is_err());
}

#[test]
fn the_small_order_key_in_a_non_canonical_encoding_is_refused() {
    assert!(verify(
        &id(IDENTITY_NON_CANONICAL),
        &message(MSG),
        &sig(ANY_MESSAGE)
    )
    .is_err());
}

#[test]
fn non_canonical_s_and_r_are_refused_and_the_good_signature_is_accepted() {
    let msg = message(MSG);
    assert_eq!(verify(&id(KEY), &msg, &sig(GOOD)), Ok(()));
    assert!(verify(&id(KEY), &msg, &sig(S_PLUS_L)).is_err());
    assert!(verify(&id(KEY), &msg, &sig(R_NON_CANONICAL)).is_err());
}

// ── every public entry refuses the small-order key ──────────────────────────

#[test]
fn verify32_and_ok_refuse_the_small_order_key() {
    let c = [0x42u8; 32];
    assert!(verify32(&id(IDENTITY), &c, &sig(ANY_MESSAGE)).is_err());
    assert!(!ok(&id(IDENTITY), &c, &sig(ANY_MESSAGE)));
}

#[test]
fn the_challenge_response_check_refuses_the_small_order_key() {
    let p = Pending {
        id: id(IDENTITY),
        c: [0x17u8; 32],
    };
    let r = Response {
        s: sig(ANY_MESSAGE),
    };
    assert!(matches!(check(&p, &r), AuthResult::Fail));
    // and an ordinary key still authenticates
    let identity = Identity::from_seed(&[7u8; 32]);
    let p = Pending {
        id: identity.id(),
        c: [0x17u8; 32],
    };
    let r = Response {
        s: identity.sign32(&p.c),
    };
    assert!(matches!(check(&p, &r), AuthResult::Ok(_)));
}

#[test]
fn a_recovery_approval_by_the_small_order_key_is_refused() {
    let approval = RecoveryApproval {
        guardian: id(IDENTITY),
        old_id: id(KEY),
        new_id: Identity::from_seed(&[8u8; 32]).id(),
        sig: sig(ANY_MESSAGE),
        approved_ms: 1,
    };
    assert!(!verify_recovery_approval(&approval));
}

#[test]
fn an_endorsement_by_the_small_order_key_is_refused() {
    let e = Endorsement {
        endorser: id(IDENTITY),
        endorsed: id(KEY),
        sig: sig(ANY_MESSAGE),
        issued_ms: 0,
        expires_ms: u64::MAX,
    };
    assert!(!verify_endorsement(&e, 1));
}

#[cfg(feature = "std")]
#[test]
fn a_jwt_signed_by_the_small_order_key_is_refused() {
    use alice_auth::jwt::{create_jwt, verify_jwt, JwtClaims};
    let identity = Identity::from_seed(&[7u8; 32]);
    let token = create_jwt(&identity, &JwtClaims::new("iss", "sub", 3600));
    assert!(
        verify_jwt(&token, &identity.id()).is_some(),
        "an ordinary token verifies"
    );
    let (input, _) = token.rsplit_once('.').expect("signing input");
    let forged = format!("{input}.{}", base64url(&bytes::<64>(ANY_MESSAGE)));
    assert!(verify_jwt(&forged, &id(IDENTITY)).is_none());
}

#[cfg(feature = "std")]
#[test]
fn a_rotating_identity_refuses_the_small_order_key() {
    let r = alice_auth::RotatingIdentity::gen().expect("rng");
    assert!(!r.verify_any(&id(IDENTITY), b"m", &sig(ANY_MESSAGE)));
}

/// The previous-key arm of `verify_any`: after a rotation the seed-[7; 32] key (KEY) is the
/// previous key; its valid signature is accepted through that arm and a small-order R
/// under it is refused
#[cfg(feature = "std")]
#[test]
fn a_rotating_identity_refuses_a_small_order_r_under_its_previous_key() {
    let mut r =
        alice_auth::RotatingIdentity::with_max_generations(Identity::from_seed(&[7u8; 32]), 3);
    r.rotate(1).expect("rng");
    assert_eq!(r.previous_id().map(|(p, _)| p), Some(id(KEY)));
    let msg = message(MSG);
    assert!(
        r.verify_any(&id(KEY), &msg, &sig(GOOD)),
        "the previous key's signature is accepted"
    );
    assert!(!r.verify_any(&id(KEY), &msg, &sig(SMALL_ORDER_R)));
}

#[cfg(feature = "api")]
#[test]
fn the_api_middleware_refuses_the_small_order_key() {
    use alice_auth::api_bridge::{AuthMiddleware, AuthRequest, AuthResponse, AuthToken};
    let mut mw = AuthMiddleware::new();
    let req = AuthRequest {
        token: AuthToken::new(1_000, 60_000).unwrap().to_bytes().to_vec(),
        signature: sig(ANY_MESSAGE),
        identity: id(IDENTITY),
    };
    assert!(matches!(
        mw.verify_request(&req, 2_000),
        AuthResponse::Denied {
            reason: "Invalid signature"
        }
    ));
}

#[cfg(feature = "ffi")]
#[test]
fn the_c_abi_refuses_the_small_order_key() {
    let pk = bytes::<32>(IDENTITY);
    let s = bytes::<64>(ANY_MESSAGE);
    let m = b"any message";
    // SAFETY: the pointers are to live arrays of the lengths the functions read
    assert_eq!(
        unsafe { alice_auth::aa_verify(pk.as_ptr(), m.as_ptr(), m.len(), s.as_ptr()) },
        0
    );
    let mut e = [0u8; 144];
    e[..32].copy_from_slice(&pk);
    e[32..64].copy_from_slice(&bytes::<32>(KEY));
    e[64..128].copy_from_slice(&s);
    e[136..144].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        unsafe { alice_auth::aa_verify_endorsement(e.as_ptr(), 1) },
        0
    );
    // an ordinary key and signature are accepted through the C ABI
    let good = bytes::<64>(GOOD);
    let key = bytes::<32>(KEY);
    let msg = message(MSG);
    assert_eq!(
        unsafe { alice_auth::aa_verify(key.as_ptr(), msg.as_ptr(), msg.len(), good.as_ptr()) },
        1
    );
}

/// base64url without padding (RFC 4648 section 5), written here independently of the crate
fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
