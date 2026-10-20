//! Messages that start with the reserved prefix `alice-auth/` are this crate's own
//! signed formats (each begins with a tag under that prefix). The public signing
//! paths refuse them, so a key handed to a host for signing arbitrary bytes (or a
//! challenge chosen by the other side) cannot be made to sign one of those formats.

use alice_auth::{
    respond, verify, AliceId, Challenge, Identity, RotatingIdentity, SignError, RESERVED_PREFIX,
};

fn id() -> Identity {
    Identity::from_seed(&[7u8; 32])
}

/// messages each public path must refuse: the prefix alone, the prefix plus a
/// body, and the 24-byte tags of the crate's formats
fn reserved() -> Vec<Vec<u8>> {
    let mut v = vec![
        b"alice-auth/".to_vec(),
        b"alice-auth/x".to_vec(),
        b"alice-auth/grant/v1/////".to_vec(),
        b"alice-auth/player-id/v1/".to_vec(),
        b"alice-auth/revoke/v1////".to_vec(),
        b"alice-auth/rotate/v1////".to_vec(),
    ];
    let mut long = b"alice-auth/grant/v1/////".to_vec();
    long.extend_from_slice(&[0xffu8; 200]);
    v.push(long);
    v
}

/// messages that only resemble the prefix: each is an ordinary message
fn ordinary() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"alice-auth".to_vec(),
        b"Alice-auth/".to_vec(),
        b"ALICE-AUTH/".to_vec(),
        b"alice_auth/".to_vec(),
        b"alice-auth\\".to_vec(),
        b" alice-auth/".to_vec(),
        b"x alice-auth/".to_vec(),
        b"alice-aut/".to_vec(),
        b"hello".to_vec(),
    ]
}

fn reserved32() -> Vec<[u8; 32]> {
    reserved()
        .into_iter()
        .map(|m| {
            let mut c = [0x5au8; 32];
            let n = m.len().min(32);
            c[..n].copy_from_slice(&m[..n]);
            c
        })
        .collect()
}

#[test]
fn the_prefix_is_the_eleven_ascii_bytes() {
    assert_eq!(RESERVED_PREFIX, b"alice-auth/");
    assert_eq!(RESERVED_PREFIX.len(), 11);
}

#[test]
fn identity_sign_refuses_every_reserved_message() {
    let i = id();
    for m in reserved() {
        assert_eq!(
            i.sign(&m),
            Err(SignError::ReservedPrefix),
            "{:?}",
            String::from_utf8_lossy(&m)
        );
    }
}

#[test]
fn identity_sign_signs_messages_that_only_resemble_the_prefix() {
    let i = id();
    for m in ordinary() {
        let s = i
            .sign(&m)
            .unwrap_or_else(|e| panic!("{:?}: {e}", String::from_utf8_lossy(&m)));
        assert!(verify(&i.id(), &m, &s).is_ok());
    }
    // the prefix not at offset 0
    let mut m = vec![0u8];
    m.extend_from_slice(RESERVED_PREFIX);
    assert!(i.sign(&m).is_ok());
}

#[test]
fn sign32_refuses_a_challenge_that_starts_with_the_prefix() {
    let i = id();
    for c in reserved32() {
        assert_eq!(i.sign32(&c), Err(SignError::ReservedPrefix));
    }
    let mut c = [0u8; 32];
    c[1..12].copy_from_slice(RESERVED_PREFIX);
    let s = i.sign32(&c).expect("prefix at offset 1");
    assert!(verify(&i.id(), &c, &s).is_ok());
}

#[test]
fn respond_refuses_a_reserved_challenge_and_answers_an_ordinary_one() {
    let i = id();
    for n in reserved32() {
        assert_eq!(
            respond(&i, &Challenge { n }).err(),
            Some(SignError::ReservedPrefix)
        );
    }
    let n = [0x11u8; 32];
    let r = respond(&i, &Challenge { n }).expect("ordinary challenge");
    assert!(verify(&i.id(), &n, &r.s).is_ok());
}

#[test]
fn rotating_identity_sign_refuses_every_reserved_message() {
    let mut r = RotatingIdentity::with_max_generations(Identity::from_seed(&[3u8; 32]), 4);
    for t in 0..2u64 {
        for m in reserved() {
            assert_eq!(r.sign(&m), Err(SignError::ReservedPrefix));
        }
        let s = r.sign(b"hello").expect("ordinary");
        assert!(verify(&r.id(), b"hello", &s).is_ok());
        r.rotate(t * 1_000).expect("rotate");
    }
}

#[test]
fn the_error_names_the_prefix() {
    let msg = SignError::ReservedPrefix.to_string();
    assert!(msg.contains("alice-auth/"), "{msg}");
}

#[test]
fn a_refusal_does_not_depend_on_the_key() {
    for seed in [[0u8; 32], [1u8; 32], [0xffu8; 32]] {
        let i = Identity::from_seed(&seed);
        assert_eq!(i.sign(RESERVED_PREFIX), Err(SignError::ReservedPrefix));
        let _: AliceId = i.id();
    }
}

#[cfg(feature = "ffi")]
mod c_abi {
    use super::{ordinary, reserved32};
    use alice_auth::{
        aa_clear_last_error, aa_free, aa_free_error_string, aa_last_error, aa_new, aa_sign, verify,
        AliceId, AliceSig, AA_SIGN_ERR_NULL, AA_SIGN_ERR_RESERVED, AA_SIGN_OK,
    };

    /// The message `aa_last_error` holds (reading it takes it: the slot is then empty)
    fn last_error() -> String {
        let p = aa_last_error();
        if p.is_null() {
            return String::new();
        }
        // SAFETY: a non-null pointer from aa_last_error, freed once
        let s = unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned();
        unsafe { aa_free_error_string(p) };
        s
    }

    fn id_of(h: *mut alice_auth::Handle) -> AliceId {
        let mut o = [0u8; 32];
        // SAFETY: h from aa_new, o is 32 writable bytes
        unsafe { alice_auth::aa_id(h, o.as_mut_ptr()) };
        AliceId(o)
    }

    #[test]
    fn aa_sign_refuses_a_reserved_challenge_and_leaves_the_output_untouched() {
        let h = aa_new();
        assert!(!h.is_null());
        aa_clear_last_error();
        for c in reserved32() {
            let mut out = [0xa5u8; 64];
            // SAFETY: h from aa_new, c is 32 readable bytes, out 64 writable
            let rc = unsafe { aa_sign(h, c.as_ptr(), out.as_mut_ptr()) };
            assert_eq!(rc, AA_SIGN_ERR_RESERVED);
            assert!(out.iter().all(|b| *b == 0xa5), "output written on error");
            let msg = last_error();
            assert!(msg.contains("alice-auth/"), "{msg}");
            assert_eq!(last_error(), "");
        }
        // SAFETY: h from aa_new, freed once
        unsafe { aa_free(h) };
    }

    #[test]
    fn aa_sign_signs_an_ordinary_challenge_and_records_nothing() {
        let h = aa_new();
        let pk = id_of(h);
        aa_clear_last_error();
        for m in ordinary() {
            let mut c = [0x5au8; 32];
            let n = m.len().min(32);
            c[..n].copy_from_slice(&m[..n]);
            let mut out = [0u8; 64];
            // SAFETY: as above
            let rc = unsafe { aa_sign(h, c.as_ptr(), out.as_mut_ptr()) };
            assert_eq!(rc, AA_SIGN_OK);
            assert!(verify(&pk, &c, &AliceSig(out)).is_ok());
            assert_eq!(last_error(), "", "a successful call recorded a message");
        }
        // SAFETY: h from aa_new, freed once
        unsafe { aa_free(h) };
    }

    #[test]
    fn aa_sign_reports_a_null_argument() {
        let h = aa_new();
        let c = [0u8; 32];
        let mut out = [0xa5u8; 64];
        aa_clear_last_error();
        // SAFETY: null pointers are checked before use
        let rc = unsafe { aa_sign(std::ptr::null(), c.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, AA_SIGN_ERR_NULL);
        assert!(last_error().contains("null"));
        let rc = unsafe { aa_sign(h, std::ptr::null(), out.as_mut_ptr()) };
        assert_eq!(rc, AA_SIGN_ERR_NULL);
        assert!(last_error().contains("null"));
        let rc = unsafe { aa_sign(h, c.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(rc, AA_SIGN_ERR_NULL);
        assert!(last_error().contains("null"));
        assert!(out.iter().all(|b| *b == 0xa5));
        // SAFETY: h from aa_new, freed once
        unsafe { aa_free(h) };
    }

    #[test]
    fn the_codes_are_fixed() {
        assert_eq!(
            (AA_SIGN_OK, AA_SIGN_ERR_NULL, AA_SIGN_ERR_RESERVED),
            (0, -1, -2)
        );
    }
}

/// every tag of the crate's own formats lies under the prefix, so a public path
/// cannot sign a grant, a revocation, a player id or a rotation link
#[test]
fn every_tag_of_the_crate_is_under_the_prefix_and_refused() {
    use alice_auth::{TAG_GRANT_V1, TAG_PLAYER_ID_V1, TAG_REVOCATION_V1, TAG_ROTATION_V1};
    let i = id();
    for tag in [
        TAG_GRANT_V1,
        TAG_PLAYER_ID_V1,
        TAG_REVOCATION_V1,
        TAG_ROTATION_V1,
    ] {
        assert!(
            tag.starts_with(RESERVED_PREFIX),
            "{:?}",
            String::from_utf8_lossy(tag)
        );
        let mut m = tag.to_vec();
        m.extend_from_slice(&[0x42u8; 109]);
        assert_eq!(i.sign(&m), Err(SignError::ReservedPrefix));
        assert_eq!(i.sign(tag), Err(SignError::ReservedPrefix));
    }
}
