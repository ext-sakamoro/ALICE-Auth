//! An endorsement signs `target(32) || issued_ms || expires_ms`, and `target` is
//! chosen by the caller. A target that starts with the reserved prefix
//! `alice-auth/` would make the endorser sign a message that starts like one of the
//! crate's tagged formats, so `endorse` refuses it, and `verify_endorsement`
//! refuses an endorsement whose endorsed id starts with it (no real key does).

use alice_auth::{
    endorse, verify, verify_chain, verify_endorsement, AliceId, AuthError, Endorsement, Identity,
    RESERVED_PREFIX, TAG_GRANT_V1,
};

fn signer() -> Identity {
    Identity::from_seed(&[9u8; 32])
}

/// targets under the prefix: a 24-byte tag padded with zeros, and the bare prefix
fn reserved_targets() -> Vec<AliceId> {
    let mut a = [0u8; 32];
    a[..24].copy_from_slice(TAG_GRANT_V1);
    let mut b = [0x77u8; 32];
    b[..11].copy_from_slice(RESERVED_PREFIX);
    vec![AliceId(a), AliceId(b)]
}

#[test]
fn endorse_refuses_a_target_under_the_reserved_prefix() {
    for t in reserved_targets() {
        assert_eq!(
            endorse(&signer(), &t, 1_000, 60_000).err(),
            Some(AuthError::E7)
        );
    }
}

#[test]
fn a_reserved_target_with_an_overflowing_window_is_refused() {
    let t = reserved_targets()[0];
    assert!(endorse(&signer(), &t, u64::MAX, 1).is_err());
}

#[test]
fn endorse_accepts_targets_that_only_resemble_the_prefix() {
    for head in [&b"Alice-auth/"[..], b"alice-auth", b"xalice-auth/"] {
        let mut a = [0u8; 32];
        a[..head.len()].copy_from_slice(head);
        let e = endorse(&signer(), &AliceId(a), 1_000, 60_000).expect("ordinary target");
        assert!(verify_endorsement(&e, 2_000));
    }
}

/// a signature over `target || issued || expires` made outside `endorse` (as an
/// internal tagged format of that length would be) is not accepted as an endorsement
#[test]
fn verify_endorsement_refuses_an_endorsed_id_under_the_reserved_prefix() {
    use ed25519_dalek::Signer;
    let s = signer();
    let sk = ed25519_dalek::SigningKey::from_bytes(&s.seed());
    for t in reserved_targets() {
        let mut m = [0u8; 48];
        m[..32].copy_from_slice(&t.0);
        m[32..40].copy_from_slice(&1_000u64.to_le_bytes());
        m[40..48].copy_from_slice(&61_000u64.to_le_bytes());
        let sig = alice_auth::AliceSig(sk.sign(&m).to_bytes());
        assert!(
            verify(&s.id(), &m, &sig).is_ok(),
            "the raw signature is valid"
        );
        let e = Endorsement {
            endorser: s.id(),
            endorsed: t,
            sig,
            issued_ms: 1_000,
            expires_ms: 61_000,
        };
        assert!(!verify_endorsement(&e, 2_000));
        assert!(!verify_chain(&[e], &s.id(), 2_000));
    }
}

#[test]
fn e7_keeps_its_number() {
    assert_eq!(AuthError::E7 as u8, 7);
    assert_eq!(AuthError::E7.to_string(), "E7");
}

#[cfg(feature = "ffi")]
mod c_abi {
    use super::reserved_targets;
    use alice_auth::{
        aa_clear_last_error, aa_endorse, aa_free, aa_free_error_string, aa_last_error, aa_new,
        aa_verify_endorsement, AA_ENDORSE_ERR_RESERVED, AA_ENDORSE_OK,
    };

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

    #[test]
    fn aa_endorse_refuses_a_reserved_target_and_leaves_the_output_untouched() {
        let h = aa_new();
        aa_clear_last_error();
        for t in reserved_targets() {
            let mut out = [0xa5u8; 176];
            // SAFETY: h from aa_new, t 32 readable bytes, out 176 writable
            let rc = unsafe { aa_endorse(h, t.0.as_ptr(), 1_000, 60_000, out.as_mut_ptr()) };
            assert_eq!(rc, AA_ENDORSE_ERR_RESERVED);
            assert!(out.iter().all(|b| *b == 0xa5), "output written on error");
            let msg = last_error();
            assert!(msg.contains("alice-auth/"), "{msg}");
            assert_eq!(last_error(), "");
        }
        let ok = [0x11u8; 32];
        let mut out = [0u8; 176];
        // SAFETY: as above
        let rc = unsafe { aa_endorse(h, ok.as_ptr(), 1_000, 60_000, out.as_mut_ptr()) };
        assert_eq!(rc, AA_ENDORSE_OK);
        assert_eq!(last_error(), "", "a successful call recorded a message");
        // SAFETY: out holds an endorsement
        assert_eq!(unsafe { aa_verify_endorsement(out.as_ptr(), 2_000) }, 1);
        // SAFETY: h from aa_new, freed once
        unsafe { aa_free(h) };
    }

    #[test]
    fn the_code_is_fixed() {
        assert_eq!(AA_ENDORSE_ERR_RESERVED, -3);
    }
}
