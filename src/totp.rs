//! TOTP/HOTP 二要素認証 (RFC 6238 / RFC 4226)
//!
//! HMAC-SHA1 ベースの時間ベースワンタイムパスワード。
//! 6桁コード生成・検証、時間ウィンドウ許容。
//!
//! # 使用例
//!
//! ```rust
//! use alice_auth::totp::{TotpConfig, generate_totp, verify_totp};
//!
//! let secret = b"12345678901234567890"; // 共有秘密
//! let config = TotpConfig::default();
//! let now = 59; // Unix timestamp
//! let code = generate_totp(secret, now, &config);
//! assert!(verify_totp(secret, now, &config, code));
//! ```

// ============================================================================
// HMAC-SHA1 (RFC 2104) — 最小実装
// ============================================================================

/// SHA-1 ハッシュ (FIPS 180-4)。
///
/// TOTP/HOTP のための最小実装。セキュリティ目的の署名には使用しないこと
/// （Ed25519を使用）。
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64) * 8;

    // パディング: data + 0x80 + zeros + length(8B)
    let pad_len = 64 - ((data.len() + 9) % 64);
    let total_len = data.len() + 1 + pad_len + 8;
    let mut padded = vec![0u8; total_len];
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;
    padded[total_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

    // ブロック処理
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80u32 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i as usize]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// HMAC-SHA1 (RFC 2104)。
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;

    // 鍵の正規化
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = sha1(key);
        k[..20].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // ipad = k XOR 0x36, opad = k XOR 0x5C
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5Cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    // inner = SHA1(ipad || message)
    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner = sha1(&inner_data);

    // outer = SHA1(opad || inner)
    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner);
    sha1(&outer_data)
}

// ============================================================================
// TOTP/HOTP
// ============================================================================

/// TOTP設定。
#[derive(Debug, Clone, Copy)]
pub struct TotpConfig {
    /// コードの桁数（6 or 8）。
    pub digits: u32,
    /// 時間ステップ（秒）。RFC 6238 推奨は30。
    pub period_secs: u64,
    /// 検証時の前後ウィンドウ数。1 = ±1ステップ許容。
    pub skew: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            period_secs: 30,
            skew: 1,
        }
    }
}

/// HOTP コード生成 (RFC 4226)。
///
/// `counter` は単調増加カウンタ。
#[must_use]
pub fn generate_hotp(secret: &[u8], counter: u64) -> u32 {
    generate_hotp_digits(secret, counter, 6)
}

/// 桁数指定 HOTP コード生成。
#[must_use]
pub fn generate_hotp_digits(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (mac[19] & 0x0F) as usize;
    let code = u32::from_be_bytes([
        mac[offset] & 0x7F,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);

    code % 10u32.pow(digits)
}

/// TOTP コード生成 (RFC 6238)。
///
/// `timestamp` は Unix epoch からの秒数。
#[must_use]
pub fn generate_totp(secret: &[u8], timestamp: u64, config: &TotpConfig) -> u32 {
    let counter = timestamp / config.period_secs;
    generate_hotp_digits(secret, counter, config.digits)
}

/// TOTP コード検証。
///
/// `skew` ウィンドウ内のいずれかのステップでマッチすれば `true`。
#[must_use]
pub fn verify_totp(secret: &[u8], timestamp: u64, config: &TotpConfig, code: u32) -> bool {
    let counter = timestamp / config.period_secs;

    let start = counter.saturating_sub(u64::from(config.skew));
    let end = counter + u64::from(config.skew);

    for c in start..=end {
        if generate_hotp_digits(secret, c, config.digits) == code {
            return true;
        }
    }
    false
}

/// HOTP コード検証。
#[must_use]
pub fn verify_hotp(secret: &[u8], counter: u64, code: u32) -> bool {
    generate_hotp(secret, counter) == code
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D — HOTP テストベクタ
    // Secret = "12345678901234567890" (ASCII)
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn sha1_empty() {
        let h = sha1(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn sha1_abc() {
        let h = sha1(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn hotp_rfc4226_test_vectors() {
        // RFC 4226 Appendix D: Expected HOTP values
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, &exp) in expected.iter().enumerate() {
            let code = generate_hotp(RFC_SECRET, counter as u64);
            assert_eq!(code, exp, "HOTP mismatch at counter {counter}");
        }
    }

    #[test]
    fn totp_rfc6238_test_vector_sha1() {
        // RFC 6238 Table 1: SHA1, time=59, expected=287082
        let config = TotpConfig {
            digits: 6,
            period_secs: 30,
            skew: 0,
        };
        // counter = 59/30 = 1
        let code = generate_totp(RFC_SECRET, 59, &config);
        // counter=1 → HOTP(1)=287082 (from RFC 4226)
        assert_eq!(code, 287_082);
    }

    #[test]
    fn totp_verify_exact() {
        let config = TotpConfig {
            digits: 6,
            period_secs: 30,
            skew: 0,
        };
        let code = generate_totp(RFC_SECRET, 90, &config); // counter=3
        assert!(verify_totp(RFC_SECRET, 90, &config, code));
    }

    #[test]
    fn totp_verify_with_skew() {
        let config = TotpConfig {
            digits: 6,
            period_secs: 30,
            skew: 1,
        };
        // Generate at t=90 (counter=3), verify at t=120 (counter=4), skew=1 → pass
        let code = generate_totp(RFC_SECRET, 90, &config);
        assert!(verify_totp(RFC_SECRET, 120, &config, code));
    }

    #[test]
    fn totp_reject_wrong_code() {
        let config = TotpConfig::default();
        assert!(!verify_totp(RFC_SECRET, 90, &config, 999_999));
    }

    #[test]
    fn totp_reject_out_of_skew() {
        let config = TotpConfig {
            digits: 6,
            period_secs: 30,
            skew: 0,
        };
        let code = generate_totp(RFC_SECRET, 0, &config); // counter=0
                                                          // counter=2 (t=60), skew=0 → reject
        assert!(!verify_totp(RFC_SECRET, 60, &config, code));
    }

    #[test]
    fn totp_8_digits() {
        let config = TotpConfig {
            digits: 8,
            period_secs: 30,
            skew: 0,
        };
        let code = generate_totp(RFC_SECRET, 59, &config);
        assert!(code < 100_000_000);
        assert!(verify_totp(RFC_SECRET, 59, &config, code));
    }

    #[test]
    fn hotp_verify() {
        let code = generate_hotp(RFC_SECRET, 0);
        assert!(verify_hotp(RFC_SECRET, 0, code));
        assert!(!verify_hotp(RFC_SECRET, 0, code + 1));
    }

    #[test]
    fn totp_config_default() {
        let cfg = TotpConfig::default();
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period_secs, 30);
        assert_eq!(cfg.skew, 1);
    }

    #[test]
    fn hmac_sha1_basic() {
        // RFC 2202 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha1(key, data);
        let expected = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn hotp_different_counters_differ() {
        let c0 = generate_hotp(RFC_SECRET, 0);
        let c1 = generate_hotp(RFC_SECRET, 1);
        assert_ne!(c0, c1);
    }

    #[test]
    fn hotp_deterministic() {
        let a = generate_hotp(RFC_SECRET, 42);
        let b = generate_hotp(RFC_SECRET, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn totp_code_range() {
        let config = TotpConfig::default();
        for t in (0..300).step_by(30) {
            let code = generate_totp(RFC_SECRET, t, &config);
            assert!(code < 1_000_000, "6-digit code should be < 1000000");
        }
    }
}
