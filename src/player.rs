//! player: one id for a player across games, and the chain of its keys.
//!
//! A [`PlayerId`] is the SHA-256 of [`TAG_PLAYER_ID_V1`] and the player's first key, so it
//! does not change when the key does. Each key change is a [`RotationLink`] signed by the
//! key it leaves; [`resolve_chain`] checks a list of links from the first key and returns
//! the current key and the time it became current. There is no overlap: once a link
//! moves the player to a new key, the old key no longer speaks for the player.
//!
//! Every signed message of this module is a 24-byte tag followed by the fixed-length body,
//! and every signature is checked strictly ([`crate::verify`]). The wire forms are fixed
//! length, little-endian, and start with the version byte [`PLAYER_WIRE_VERSION`].

use crate::types::{AliceId, AliceSig};
use crate::Identity;
use core::fmt;

/// The version byte every wire form of this module starts with.
pub const PLAYER_WIRE_VERSION: u8 = 1;

/// Domain tag of [`PlayerId::from_genesis`].
pub const TAG_PLAYER_ID_V1: &[u8; 24] = b"alice-auth/player-id/v1/";
/// Domain tag of a grant's signature.
pub const TAG_GRANT_V1: &[u8; 24] = b"alice-auth/grant/v1/////";
/// Domain tag of a revocation's signature.
pub const TAG_REVOCATION_V1: &[u8; 24] = b"alice-auth/revoke/v1////";
/// Domain tag of a [`RotationLink`]'s signature.
pub const TAG_ROTATION_V1: &[u8; 24] = b"alice-auth/rotate/v1////";

/// Length of a [`RotationLink`] on the wire.
pub const ROTATION_LINK_LEN: usize = 173;

/// Why a player value was refused. The codes are fixed (they cross the C ABI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantError {
    /// A null pointer was passed through the C ABI.
    Null,
    /// The bytes are not the length of the wire form.
    Length,
    /// The version byte is not [`PLAYER_WIRE_VERSION`].
    Version,
    /// The signature does not verify strictly under the key that must have made it.
    Signature,
    /// The grant was issued by another game than the one checking it.
    WrongGame,
    /// The grant is not valid yet (`now < issued`).
    NotYetValid,
    /// The grant has expired (`now >= expires`).
    Expired,
    /// The grant was revoked.
    Revoked,
    /// The validity window is empty (`issued >= expires`).
    Times,
    /// The grant names a key that is not the player's current key.
    WrongKey,
    /// A time does not fit in `u64` milliseconds.
    Overflow,
    /// The revocation set is full; nothing was stored.
    Full,
    /// A rotation link does not continue the chain.
    Chain,
    /// The platform random number generator failed.
    Rng,
}

impl GrantError {
    /// The fixed C ABI code (negative; 0 is success).
    #[must_use]
    pub const fn code(self) -> i32 {
        panic!("not yet implemented: GrantError::code")
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("GrantError::fmt")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GrantError {}

/// A player's id: SHA-256 of [`TAG_PLAYER_ID_V1`] and the player's first key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlayerId(pub [u8; 32]);

impl PlayerId {
    /// The id of the player whose first key is `genesis`.
    #[must_use]
    pub fn from_genesis(_genesis: &AliceId) -> Self {
        todo!("PlayerId::from_genesis")
    }
}

/// One key change of a player, signed by the key it leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationLink {
    pub player: PlayerId,
    /// The link's place in the chain, from 0.
    pub seq: u32,
    pub old_key: AliceId,
    pub new_key: AliceId,
    /// When `new_key` becomes the player's key (ms).
    pub issued_ms: u64,
    pub sig: AliceSig,
}

impl RotationLink {
    /// Sign a link that moves `player` from `old`'s key to `new_key` at `issued_ms`.
    ///
    /// # Errors
    /// [`GrantError::Chain`] when `new_key` is `old`'s key, is not a valid key, or is a
    /// small-order key.
    pub fn issue(
        _old: &Identity,
        _player: PlayerId,
        _seq: u32,
        _new_key: AliceId,
        _issued_ms: u64,
    ) -> Result<Self, GrantError> {
        todo!("RotationLink::issue")
    }

    /// The wire form ([`ROTATION_LINK_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ROTATION_LINK_LEN] {
        todo!("RotationLink::to_bytes")
    }

    /// Read the wire form. The signature is not checked here ([`resolve_chain`] does).
    ///
    /// # Errors
    /// [`GrantError::Length`] for any other length, [`GrantError::Version`] for another
    /// version byte.
    pub fn from_bytes(_b: &[u8]) -> Result<Self, GrantError> {
        todo!("RotationLink::from_bytes")
    }
}

/// The end of a player's chain: the id, the current key and when it became current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub player: PlayerId,
    pub key: AliceId,
    /// 0 for the first key.
    pub since_ms: u64,
}

/// Check `links` from the first key `genesis` and return the chain's end.
///
/// # Errors
/// [`GrantError::Signature`] when a link is not signed by the key the chain is at;
/// [`GrantError::Chain`] when a signed link does not continue the chain (another player,
/// a sequence number out of place, a time that does not move forward, the same key, or a
/// key that is not a valid or is a small-order key, the first key included).
pub fn resolve_chain(_genesis: &AliceId, _links: &[RotationLink]) -> Result<ChainHead, GrantError> {
    todo!("resolve_chain")
}
