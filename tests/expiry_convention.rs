//! One expiry convention across the crate: a thing that expires at `exp` is valid
//! while `now < exp` and expired from `now == exp` on (exclusive). Every site is
//! pinned at `exp - 1` (valid), `exp` (expired) and `exp + 1` (expired).

use alice_auth::{endorse, is_expired, verify_chain, verify_endorsement, AliceId, Identity};

const EXP: u64 = 5_000;

fn signer() -> Identity {
    Identity::from_seed(&[9u8; 32])
}

fn target() -> AliceId {
    Identity::from_seed(&[8u8; 32]).id()
}

#[test]
fn the_shared_function_is_exclusive() {
    assert!(!is_expired(EXP - 1, EXP));
    assert!(is_expired(EXP, EXP));
    assert!(is_expired(EXP + 1, EXP));
    assert!(!is_expired(0, 1));
    assert!(is_expired(0, 0));
    assert!(!is_expired(u64::MAX - 1, u64::MAX));
    assert!(is_expired(u64::MAX, u64::MAX));
}

#[test]
fn the_shared_function_is_const() {
    const { assert!(is_expired(EXP, EXP)) };
    const { assert!(!is_expired(EXP - 1, EXP)) };
}

#[test]
fn an_endorsement_expires_at_its_expires_ms() {
    let s = signer();
    let e = endorse(&s, &target(), 1_000, EXP - 1_000).expect("fits");
    assert_eq!(e.expires_ms, EXP);
    assert!(verify_endorsement(&e, EXP - 1));
    assert!(!verify_endorsement(&e, EXP));
    assert!(!verify_endorsement(&e, EXP + 1));
}

#[test]
fn a_zero_ttl_endorsement_is_never_valid() {
    let e = endorse(&signer(), &target(), 1_000, 0).expect("fits");
    assert!(!verify_endorsement(&e, 1_000));
}

#[test]
fn a_chain_expires_with_its_endorsement() {
    let s = signer();
    let e = endorse(&s, &target(), 1_000, EXP - 1_000).expect("fits");
    let chain = [e];
    assert!(verify_chain(&chain, &s.id(), EXP - 1));
    assert!(!verify_chain(&chain, &s.id(), EXP));
    assert!(!verify_chain(&chain, &s.id(), EXP + 1));
}

#[test]
fn a_timed_challenge_expires_when_its_age_reaches_the_ttl() {
    use alice_auth::{check_timed, make_timed_challenge, respond, AuthResult, Challenge};
    let i = signer();
    let p = make_timed_challenge(i.id(), 1_000).expect("rng");
    let r = respond(&i, &Challenge { n: p.c }).expect("ordinary challenge");
    let ttl = EXP - 1_000;
    assert!(matches!(
        check_timed(&p, &r, EXP - 1, ttl),
        AuthResult::Ok(_)
    ));
    assert!(matches!(check_timed(&p, &r, EXP, ttl), AuthResult::Fail));
    assert!(matches!(
        check_timed(&p, &r, EXP + 1, ttl),
        AuthResult::Fail
    ));
}

#[cfg(feature = "api")]
mod api {
    use super::{signer, EXP};
    use alice_auth::api_bridge::{AuthMiddleware, AuthRequest, AuthResponse, AuthToken};

    #[test]
    fn a_token_expires_at_its_expires_ms() {
        let t = AuthToken::new(1_000, EXP - 1_000).expect("fits");
        assert_eq!(t.expires_ms, EXP);
        assert!(!t.is_expired(EXP - 1));
        assert!(t.is_expired(EXP));
        assert!(t.is_expired(EXP + 1));
    }

    fn verify(token: Vec<u8>, now_ms: u64) -> AuthResponse {
        let i = signer();
        let req = AuthRequest {
            signature: i.sign(&token).expect("sign"),
            identity: i.id(),
            token,
        };
        AuthMiddleware::new().verify_request(&req, now_ms)
    }

    #[test]
    fn verify_request_refuses_a_token_from_its_expires_ms_on() {
        let token = AuthMiddleware::create_auth_token(1_000, EXP - 1_000).expect("fits");
        assert!(matches!(
            verify(token.clone(), EXP - 1),
            AuthResponse::Authorized {
                expires_ms: EXP,
                ..
            }
        ));
        for now in [EXP, EXP + 1] {
            assert!(matches!(
                verify(token.clone(), now),
                AuthResponse::Denied {
                    reason: "Token expired"
                }
            ));
        }
    }

    #[test]
    fn verify_request_refuses_a_legacy_token_from_its_expires_ms_on() {
        let token = EXP.to_le_bytes().to_vec();
        assert!(matches!(
            verify(token.clone(), EXP - 1),
            AuthResponse::Authorized { .. }
        ));
        for now in [EXP, EXP + 1] {
            assert!(matches!(
                verify(token.clone(), now),
                AuthResponse::Denied {
                    reason: "Token expired"
                }
            ));
        }
    }
}

#[cfg(feature = "std")]
mod jwt {
    use super::EXP;
    use alice_auth::jwt::JwtClaims;

    #[test]
    fn jwt_claims_expire_at_exp() {
        let c = JwtClaims::new("iss", "sub", EXP - 1_000)
            .with_iat(1_000)
            .expect("fits");
        assert_eq!(c.exp, EXP);
        assert!(!c.is_expired(EXP - 1));
        assert!(c.is_expired(EXP));
        assert!(c.is_expired(EXP + 1));
    }
}

#[cfg(feature = "ffi")]
mod c_abi {
    use super::{target, EXP};
    use alice_auth::{
        aa_endorse, aa_free, aa_new, aa_token_create, aa_token_is_expired, aa_verify_endorsement,
        AA_ENDORSE_OK, AA_TOKEN_OK,
    };

    #[test]
    fn aa_token_is_expired_from_its_expires_ms_on() {
        let mut t = [0u8; 17];
        // SAFETY: t is 17 writable bytes
        assert_eq!(
            unsafe { aa_token_create(1_000, EXP - 1_000, t.as_mut_ptr()) },
            AA_TOKEN_OK
        );
        // SAFETY: t is 17 readable bytes
        unsafe {
            assert_eq!(aa_token_is_expired(t.as_ptr(), EXP - 1), 0);
            assert_eq!(aa_token_is_expired(t.as_ptr(), EXP), 1);
            assert_eq!(aa_token_is_expired(t.as_ptr(), EXP + 1), 1);
        }
    }

    #[test]
    fn aa_verify_endorsement_refuses_from_its_expires_ms_on() {
        let h = aa_new();
        let tg = target();
        let mut out = [0u8; 176];
        // SAFETY: h from aa_new, tg 32 readable bytes, out 176 writable
        let rc = unsafe { aa_endorse(h, tg.0.as_ptr(), 1_000, EXP - 1_000, out.as_mut_ptr()) };
        assert_eq!(rc, AA_ENDORSE_OK);
        // SAFETY: out holds 144 readable bytes of an endorsement
        unsafe {
            assert_eq!(aa_verify_endorsement(out.as_ptr(), EXP - 1), 1);
            assert_eq!(aa_verify_endorsement(out.as_ptr(), EXP), 0);
            assert_eq!(aa_verify_endorsement(out.as_ptr(), EXP + 1), 0);
            aa_free(h);
        }
    }
}
