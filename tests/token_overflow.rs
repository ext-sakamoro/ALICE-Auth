//! A token or JWT whose expiry does not fit in u64 is refused instead of wrapping
//! (release) or panicking (debug). The expiry convention itself is unchanged.

#[cfg(feature = "api")]
mod auth_token {
    use alice_auth::api_bridge::AuthToken;
    use alice_auth::AuthError;

    #[test]
    fn an_expiry_past_u64_max_is_refused() {
        let r = std::panic::catch_unwind(|| AuthToken::new(u64::MAX - 1, 2));
        assert_eq!(r.expect("no panic").err(), Some(AuthError::E6));
        assert_eq!(AuthToken::new(1, u64::MAX).err(), Some(AuthError::E6));
    }

    #[test]
    fn an_expiry_at_u64_max_is_accepted() {
        let t = AuthToken::new(u64::MAX - 10, 10).expect("fits");
        assert_eq!((t.nonce_ms, t.expires_ms), (u64::MAX - 10, u64::MAX));
        let t = AuthToken::new(1_000, 0).expect("fits");
        assert_eq!(t.expires_ms, 1_000);
    }

    #[test]
    fn create_auth_token_refuses_the_overflow_and_accepts_the_boundary() {
        use alice_auth::api_bridge::AuthMiddleware;
        assert_eq!(
            AuthMiddleware::create_auth_token(u64::MAX, 1),
            Err(AuthError::E6)
        );
        let bytes = AuthMiddleware::create_auth_token(u64::MAX - 1, 1).expect("fits");
        let t = AuthToken::from_bytes(&bytes).expect("a token");
        assert_eq!((t.nonce_ms, t.expires_ms), (u64::MAX - 1, u64::MAX));
    }

    /// `new` stays usable in a const context
    #[test]
    fn new_is_const() {
        const T: Result<AuthToken, AuthError> = AuthToken::new(1_000, 60_000);
        assert_eq!(T.expect("fits").expires_ms, 61_000);
    }
}

#[cfg(feature = "std")]
mod jwt {
    use alice_auth::jwt::JwtClaims;
    use alice_auth::AuthError;

    #[test]
    fn an_expiry_past_u64_max_is_refused() {
        let c = JwtClaims::new("iss", "sub", 2);
        let r = std::panic::catch_unwind(move || c.with_iat(u64::MAX - 1));
        assert_eq!(r.expect("no panic").err(), Some(AuthError::E6));
    }

    #[test]
    fn an_expiry_at_u64_max_is_accepted() {
        let c = JwtClaims::new("iss", "sub", 10)
            .with_iat(u64::MAX - 10)
            .expect("fits");
        assert_eq!((c.iat, c.exp), (u64::MAX - 10, u64::MAX));
    }
}

#[cfg(feature = "ffi")]
mod c_abi {
    use alice_auth::{
        aa_clear_last_error, aa_free_error_string, aa_last_error, aa_token_create,
        AA_TOKEN_ERR_NULL, AA_TOKEN_ERR_OVERFLOW, AA_TOKEN_OK,
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

    #[test]
    fn the_c_abi_reports_the_overflow_and_leaves_the_output_untouched() {
        let mut out = [0xa5u8; 17];
        // SAFETY: out is 17 writable bytes
        let rc = unsafe { aa_token_create(u64::MAX - 1, 2, out.as_mut_ptr()) };
        assert_eq!(rc, AA_TOKEN_ERR_OVERFLOW);
        assert!(out.iter().all(|b| *b == 0xa5), "output written on error");
        let msg = last_error();
        assert!(msg.contains("u64::MAX"), "{msg}");
        assert_eq!(last_error(), "");

        aa_clear_last_error();
        let rc = unsafe { aa_token_create(1_000, 5_000, out.as_mut_ptr()) };
        assert_eq!(rc, AA_TOKEN_OK);
        assert_eq!(u64::from_le_bytes(out[1..9].try_into().unwrap()), 6_000);
        assert_eq!(last_error(), "", "a successful call recorded a message");

        let rc = unsafe { aa_token_create(1, 1, std::ptr::null_mut()) };
        assert_eq!(rc, AA_TOKEN_ERR_NULL);
        let msg = last_error();
        assert!(msg.contains("null"), "{msg}");
    }
}
