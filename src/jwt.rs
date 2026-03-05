//! 軽量 JWT (JSON Web Token) — Ed25519 署名
//!
//! ALICE-Auth の Ed25519 鍵ペアを使用した JWT 生成・検証。
//! ヘッダー/ペイロード/署名の3部構成。Base64url エンコーディング。
//!
//! # 使用例
//!
//! ```rust
//! use alice_auth::Identity;
//! use alice_auth::jwt::{JwtClaims, create_jwt, verify_jwt};
//!
//! let id = Identity::gen().unwrap();
//! let claims = JwtClaims::new("alice-auth", "user-123", 3600);
//! let token = create_jwt(&id, &claims);
//! let verified = verify_jwt(&token, &id.id()).unwrap();
//! assert_eq!(verified.sub, "user-123");
//! ```

use crate::{AliceId, Identity};

// ============================================================================
// Base64url (RFC 4648 §5) — 最小実装
// ============================================================================

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let a = decode_b64_char(bytes[i])?;
        let b = if i + 1 < bytes.len() { decode_b64_char(bytes[i + 1])? } else { 0 };
        let c = if i + 2 < bytes.len() { decode_b64_char(bytes[i + 2])? } else { 0 };
        let d = if i + 3 < bytes.len() { decode_b64_char(bytes[i + 3])? } else { 0 };

        let triple = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);

        buf.push((triple >> 16) as u8);
        let remaining = bytes.len() - i;
        if remaining > 2 {
            buf.push((triple >> 8) as u8);
        }
        if remaining > 3 {
            buf.push(triple as u8);
        }

        i += 4;
    }
    Some(buf)
}

fn decode_b64_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

// ============================================================================
// JWT クレーム
// ============================================================================

/// JWT クレーム（ペイロード）。
#[derive(Debug, Clone)]
pub struct JwtClaims {
    /// 発行者 (issuer)。
    pub iss: String,
    /// 主題 (subject)。
    pub sub: String,
    /// 有効期限 (seconds since epoch)。
    pub exp: u64,
    /// 発行時刻 (seconds since epoch)。
    pub iat: u64,
}

impl JwtClaims {
    /// 新しいクレームを作成。
    ///
    /// `ttl_secs` は発行時刻からの有効期間（秒）。
    /// `iat` は0に設定（呼び出し側で設定可能）。
    #[must_use]
    pub fn new(iss: &str, sub: &str, ttl_secs: u64) -> Self {
        Self {
            iss: iss.into(),
            sub: sub.into(),
            exp: ttl_secs, // iat=0 基準
            iat: 0,
        }
    }

    /// 発行時刻を設定して有効期限を計算。
    #[must_use]
    pub fn with_iat(mut self, iat: u64) -> Self {
        let ttl = self.exp; // new() で ttl として格納
        self.iat = iat;
        self.exp = iat + ttl;
        self
    }

    /// 有効期限チェック。
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.exp
    }

    /// クレームをJSON文字列にシリアライズ（最小実装）。
    fn to_json(&self) -> String {
        format!(
            r#"{{"iss":"{}","sub":"{}","exp":{},"iat":{}}}"#,
            self.iss, self.sub, self.exp, self.iat
        )
    }

    /// JSON文字列からデシリアライズ（最小パーサ）。
    fn from_json(json: &str) -> Option<Self> {
        let iss = extract_string_field(json, "iss")?;
        let sub = extract_string_field(json, "sub")?;
        let exp = extract_number_field(json, "exp")?;
        let iat = extract_number_field(json, "iat")?;
        Some(Self { iss, sub, exp, iat })
    }
}

/// JSON文字列フィールド抽出。
fn extract_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!(r#""{key}":""#);
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

/// JSON数値フィールド抽出。
fn extract_number_field(json: &str, key: &str) -> Option<u64> {
    let needle = format!(r#""{key}":"#);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

// ============================================================================
// JWT 生成・検証
// ============================================================================

/// JWT ヘッダー（固定: Ed25519）。
const JWT_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

/// JWT トークンを生成。
///
/// フォーマット: `base64url(header).base64url(payload).base64url(signature)`
#[must_use]
pub fn create_jwt(identity: &Identity, claims: &JwtClaims) -> String {
    let header_b64 = base64url_encode(JWT_HEADER.as_bytes());
    let payload_b64 = base64url_encode(claims.to_json().as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = identity.sign(signing_input.as_bytes());

    format!("{signing_input}.{}", base64url_encode(&sig.0))
}

/// JWT トークンを検証。
///
/// # Errors
/// 不正なフォーマット、署名不一致、パース失敗の場合 `None`。
#[must_use]
pub fn verify_jwt(token: &str, verifier: &AliceId) -> Option<JwtClaims> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    // 署名デコード
    let sig_bytes = base64url_decode(parts[2])?;
    if sig_bytes.len() != 64 {
        return None;
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let sig = crate::AliceSig(sig_arr);

    // 検証
    if crate::verify(verifier, signing_input.as_bytes(), &sig).is_err() {
        return None;
    }

    // ペイロードデコード
    let payload_bytes = base64url_decode(parts[1])?;
    let payload_str = core::str::from_utf8(&payload_bytes).ok()?;
    JwtClaims::from_json(payload_str)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        let data = b"hello, ALICE-Auth JWT!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_empty() {
        let encoded = base64url_encode(b"");
        assert_eq!(encoded, "");
        let decoded = base64url_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base64url_single_byte() {
        let encoded = base64url_encode(b"a");
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, b"a");
    }

    #[test]
    fn base64url_two_bytes() {
        let encoded = base64url_encode(b"ab");
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, b"ab");
    }

    #[test]
    fn jwt_create_and_verify() {
        let id = Identity::gen().unwrap();
        let claims = JwtClaims::new("alice", "user-42", 3600).with_iat(1000);

        let token = create_jwt(&id, &claims);

        // 3パートに分割できる
        assert_eq!(token.matches('.').count(), 2);

        // 検証成功
        let verified = verify_jwt(&token, &id.id()).unwrap();
        assert_eq!(verified.iss, "alice");
        assert_eq!(verified.sub, "user-42");
        assert_eq!(verified.iat, 1000);
        assert_eq!(verified.exp, 4600);
    }

    #[test]
    fn jwt_reject_tampered_payload() {
        let id = Identity::gen().unwrap();
        let claims = JwtClaims::new("alice", "user-1", 3600);
        let token = create_jwt(&id, &claims);

        // ペイロードを改竄
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], base64url_encode(b"tampered"), parts[2]);

        assert!(verify_jwt(&tampered, &id.id()).is_none());
    }

    #[test]
    fn jwt_reject_wrong_key() {
        let id1 = Identity::gen().unwrap();
        let id2 = Identity::gen().unwrap();
        let claims = JwtClaims::new("alice", "user-1", 3600);
        let token = create_jwt(&id1, &claims);

        // 異なる鍵で検証 → 失敗
        assert!(verify_jwt(&token, &id2.id()).is_none());
    }

    #[test]
    fn jwt_reject_invalid_format() {
        let id = Identity::gen().unwrap();
        assert!(verify_jwt("not-a-jwt", &id.id()).is_none());
        assert!(verify_jwt("a.b", &id.id()).is_none());
    }

    #[test]
    fn claims_is_expired() {
        let claims = JwtClaims::new("a", "b", 100).with_iat(1000);
        assert!(!claims.is_expired(1050));
        assert!(claims.is_expired(1100));
        assert!(claims.is_expired(2000));
    }

    #[test]
    fn claims_json_roundtrip() {
        let claims = JwtClaims {
            iss: "alice-auth".into(),
            sub: "user-99".into(),
            exp: 9999,
            iat: 1000,
        };
        let json = claims.to_json();
        let parsed = JwtClaims::from_json(&json).unwrap();
        assert_eq!(parsed.iss, "alice-auth");
        assert_eq!(parsed.sub, "user-99");
        assert_eq!(parsed.exp, 9999);
        assert_eq!(parsed.iat, 1000);
    }

    #[test]
    fn claims_new_defaults() {
        let claims = JwtClaims::new("iss", "sub", 3600);
        assert_eq!(claims.iat, 0);
        assert_eq!(claims.exp, 3600); // ttl stored as exp before with_iat
    }

    #[test]
    fn jwt_header_is_eddsa() {
        let id = Identity::gen().unwrap();
        let claims = JwtClaims::new("a", "b", 100);
        let token = create_jwt(&id, &claims);
        let header_b64 = token.split('.').next().unwrap();
        let header = base64url_decode(header_b64).unwrap();
        let header_str = core::str::from_utf8(&header).unwrap();
        assert!(header_str.contains("EdDSA"));
        assert!(header_str.contains("JWT"));
    }

    #[test]
    fn base64url_no_padding() {
        let encoded = base64url_encode(b"test");
        // Base64url should not contain padding '='
        assert!(!encoded.contains('='));
    }

    #[test]
    fn base64url_url_safe() {
        // Ensure no '+' or '/' characters
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}
