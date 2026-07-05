//! types.

use crate::hex::{hex32, hex4, hex8};
use core::fmt;

// Types
// ============================================================================

/// 32-byte Ed25519 public key identifier. Supports `alice://did:ed25519:` DID encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AliceId(pub [u8; 32]);

impl AliceId {
    pub const N: usize = 32;
    pub const DID_N: usize = 84;

    #[inline(always)]
    #[must_use]
    pub const fn new(b: [u8; 32]) -> Self {
        Self(b)
    }
    #[inline(always)]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    #[inline(always)]
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn write_did<'a>(&self, buf: &'a mut [u8; 84]) -> &'a str {
        buf[0] = b'a';
        buf[1] = b'l';
        buf[2] = b'i';
        buf[3] = b'c';
        buf[4] = b'e';
        buf[5] = b':';
        buf[6] = b'/';
        buf[7] = b'/';
        buf[8] = b'd';
        buf[9] = b'i';
        buf[10] = b'd';
        buf[11] = b':';
        buf[12] = b'e';
        buf[13] = b'd';
        buf[14] = b'2';
        buf[15] = b'5';
        buf[16] = b'5';
        buf[17] = b'1';
        buf[18] = b'9';
        buf[19] = b':';
        let mut hex_buf = [0u8; 64];
        hex32(&self.0, &mut hex_buf);
        buf[20..84].copy_from_slice(&hex_buf);
        // SAFETY: buf contains only ASCII bytes (a-z, :, /, 0-9) — all valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(buf) }
    }

    #[inline(always)]
    #[must_use]
    pub fn to_did_bytes(&self) -> [u8; 84] {
        let mut b = [0u8; 84];
        self.write_did(&mut b);
        b
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for AliceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = [0u8; 8];
        hex4(&self.0, &mut h);
        f.write_str("Id(")?;
        f.write_str(unsafe { core::str::from_utf8_unchecked(&h) })?;
        f.write_str(")")
    }
}
#[cfg(not(debug_assertions))]
impl fmt::Debug for AliceId {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl fmt::Display for AliceId {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = [0u8; 84];
        f.write_str(self.write_did(&mut b))
    }
}

/// 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct AliceSig(pub [u8; 64]);

impl AliceSig {
    pub const N: usize = 64;
    #[inline(always)]
    #[must_use]
    pub const fn new(b: [u8; 64]) -> Self {
        Self(b)
    }
    #[inline(always)]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    #[inline(always)]
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for AliceSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = [0u8; 16];
        hex8(&self.0, &mut h);
        f.write_str("Sig(")?;
        f.write_str(unsafe { core::str::from_utf8_unchecked(&h) })?;
        f.write_str(")")
    }
}
#[cfg(not(debug_assertions))]
impl fmt::Debug for AliceSig {
    #[inline(always)]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AliceSig {
    #[inline(always)]
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AliceSig {
    #[inline(always)]
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = AliceSig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("64")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> core::result::Result<Self::Value, E> {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut a = [0u8; 64];
                a.copy_from_slice(v);
                Ok(AliceSig(a))
            }
        }
        d.deserialize_bytes(V)
    }
}
