//! player: one id for a player across games, and the chain of its keys.
//!
//! A [`PlayerId`] is the SHA-256 of [`TAG_PLAYER_ID_V1`] and the player's first key, so it
//! does not change when the key does. Each key change is a [`RotationLink`] signed by the
//! key it leaves; [`resolve_chain`] checks a list of links from the first key and returns
//! the current key and the time it became current. There is no overlap: once a link
//! moves the player to a new key, the old key no longer speaks for the player.
//!
//! Every signed message of this module is a 24-byte tag followed by the fixed-length body,
//! and every signature is checked strictly ([`crate::verify()`]). The wire forms are fixed
//! length, little-endian, and start with the version byte [`PLAYER_WIRE_VERSION`].
//!
//! A link whose signature does not verify under the key the chain is at is refused with
//! [`GrantError::Signature`]; [`GrantError::Chain`] is only for a link that key really
//! signed but that does not continue the chain.
//!
//! This module is not complete yet: it has the id and the key chain, and the grant, its
//! revocation and their C ABI come later. [`TAG_GRANT_V1`] and [`TAG_REVOCATION_V1`] are
//! reserved for them; nothing in this version issues or checks a grant.

use crate::types::{AliceId, AliceSig};
use crate::verify::verify;
use crate::Identity;
use core::fmt;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

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
        match self {
            Self::Null => -1,
            Self::Length => -2,
            Self::Version => -3,
            Self::Signature => -4,
            Self::WrongGame => -5,
            Self::NotYetValid => -6,
            Self::Expired => -7,
            Self::Revoked => -8,
            Self::Times => -9,
            Self::WrongKey => -10,
            Self::Overflow => -11,
            Self::Full => -12,
            Self::Chain => -13,
            Self::Rng => -14,
        }
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "a required pointer is null",
            Self::Length => "the bytes are not the length of the wire form",
            Self::Version => "the version byte is not 1",
            Self::Signature => "the signature does not verify strictly under the expected key",
            Self::WrongGame => "the grant was issued by another game",
            Self::NotYetValid => "the grant is not valid yet",
            Self::Expired => "the grant has expired",
            Self::Revoked => "the grant was revoked",
            Self::Times => "the validity window is empty",
            Self::WrongKey => "the grant names a key that is not the player's current key",
            Self::Overflow => "a time does not fit in u64 milliseconds",
            Self::Full => "the revocation set is full; nothing was stored",
            Self::Chain => "a rotation link does not continue the chain",
            Self::Rng => "the platform random number generator failed",
        })
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
    pub fn from_genesis(genesis: &AliceId) -> Self {
        let mut h = Sha256::new();
        h.update(TAG_PLAYER_ID_V1);
        h.update(genesis.0);
        Self(h.finalize().into())
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
        old: &Identity,
        player: PlayerId,
        seq: u32,
        new_key: AliceId,
        issued_ms: u64,
    ) -> Result<Self, GrantError> {
        let old_key = old.id();
        if new_key == old_key || !usable_key(&new_key) {
            return Err(GrantError::Chain);
        }
        let mut link = Self {
            player,
            seq,
            old_key,
            new_key,
            issued_ms,
            sig: AliceSig([0; 64]),
        };
        link.sig = sign_tagged(old, TAG_ROTATION_V1, &link.body());
        Ok(link)
    }

    /// The signed part of the wire form (everything but the signature).
    fn body(&self) -> [u8; ROTATION_BODY_LEN] {
        let mut b = [0u8; ROTATION_BODY_LEN];
        b[0] = PLAYER_WIRE_VERSION;
        b[1..33].copy_from_slice(&self.player.0);
        b[33..37].copy_from_slice(&self.seq.to_le_bytes());
        b[37..69].copy_from_slice(&self.old_key.0);
        b[69..101].copy_from_slice(&self.new_key.0);
        b[101..109].copy_from_slice(&self.issued_ms.to_le_bytes());
        b
    }

    /// The wire form ([`ROTATION_LINK_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ROTATION_LINK_LEN] {
        let mut b = [0u8; ROTATION_LINK_LEN];
        b[..ROTATION_BODY_LEN].copy_from_slice(&self.body());
        b[ROTATION_BODY_LEN..].copy_from_slice(&self.sig.0);
        b
    }

    /// Read the wire form. The signature is not checked here ([`resolve_chain`] does).
    ///
    /// # Errors
    /// [`GrantError::Length`] for any other length, [`GrantError::Version`] for another
    /// version byte.
    pub fn from_bytes(b: &[u8]) -> Result<Self, GrantError> {
        let b: &[u8; ROTATION_LINK_LEN] = b.try_into().map_err(|_| GrantError::Length)?;
        if b[0] != PLAYER_WIRE_VERSION {
            return Err(GrantError::Version);
        }
        Ok(Self {
            player: PlayerId(array(&b[1..33])),
            seq: u32::from_le_bytes(array(&b[33..37])),
            old_key: AliceId(array(&b[37..69])),
            new_key: AliceId(array(&b[69..101])),
            issued_ms: u64::from_le_bytes(array(&b[101..109])),
            sig: AliceSig(array(&b[ROTATION_BODY_LEN..])),
        })
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
pub fn resolve_chain(genesis: &AliceId, links: &[RotationLink]) -> Result<ChainHead, GrantError> {
    if !usable_key(genesis) {
        return Err(GrantError::Chain);
    }
    let player = PlayerId::from_genesis(genesis);
    let mut key = *genesis;
    let mut since_ms = 0u64;
    for (i, link) in links.iter().enumerate() {
        // the signature first, under the key the chain is at (not the link's own claim)
        if !verify_tagged(&key, TAG_ROTATION_V1, &link.body(), &link.sig) {
            return Err(GrantError::Signature);
        }
        let continues = link.old_key == key
            && link.player == player
            && u32::try_from(i).is_ok_and(|i| link.seq == i)
            && link.issued_ms > since_ms
            && link.new_key != key
            && usable_key(&link.new_key);
        if !continues {
            return Err(GrantError::Chain);
        }
        key = link.new_key;
        since_ms = link.issued_ms;
    }
    Ok(ChainHead {
        player,
        key,
        since_ms,
    })
}

/// Length of a [`Grant`] on the wire.
pub const GRANT_LEN: usize = 201;

/// Length of a [`Revocation`] on the wire.
pub const REVOCATION_LEN: usize = 129;

/// A game's grant to a player: the scope it allows, under the player's key at the time,
/// for `issued_ms <= now < expires_ms`. Signed by the game's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub player: PlayerId,
    /// The player's key when the grant was issued; it must still be current.
    pub player_key: AliceId,
    /// The issuing game's key.
    pub game: AliceId,
    /// What the grant allows; the game defines its meaning.
    pub scope: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// Chosen by the game, unique among its grants (a revocation names it).
    pub nonce: [u8; 16],
    pub sig: AliceSig,
}

/// What a grant that passed [`Grant::verify`] allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub player: PlayerId,
    pub scope: u64,
    pub expires_ms: u64,
}

impl Grant {
    /// Sign a grant valid from `now_ms` for `ttl_ms`.
    ///
    /// # Errors
    /// [`GrantError::Times`] when `ttl_ms` is 0, [`GrantError::Overflow`] when
    /// `now_ms + ttl_ms` does not fit in `u64`.
    pub fn issue(
        _game: &Identity,
        _player: PlayerId,
        _player_key: AliceId,
        _scope: u64,
        _now_ms: u64,
        _ttl_ms: u64,
        _nonce: [u8; 16],
    ) -> Result<Self, GrantError> {
        todo!("Grant::issue")
    }

    /// The wire form ([`GRANT_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; GRANT_LEN] {
        todo!("Grant::to_bytes")
    }

    /// Read the wire form. The signature is not checked here ([`Grant::verify`] does).
    ///
    /// # Errors
    /// [`GrantError::Length`] for any other length, [`GrantError::Version`] for another
    /// version byte.
    pub fn from_bytes(_b: &[u8]) -> Result<Self, GrantError> {
        todo!("Grant::from_bytes")
    }

    /// Check the grant for `expected_game` at `now_ms`, against the player's chain end
    /// `head` and the revocations in `revoked`.
    ///
    /// The checks run in a fixed order and the first that fails is returned: the
    /// signature under the grant's game key ([`GrantError::Signature`]), the game
    /// ([`GrantError::WrongGame`]), the window ([`GrantError::Times`],
    /// [`GrantError::NotYetValid`], [`GrantError::Expired`] for `now >= expires`), the key
    /// ([`GrantError::WrongKey`]: another player, a key that is not current, or a key that
    /// became current after the grant was issued) and last the revocation
    /// ([`GrantError::Revoked`]).
    ///
    /// # Errors
    /// The first check that fails, as above.
    #[cfg(feature = "alloc")]
    pub fn verify(
        &self,
        _expected_game: &AliceId,
        _head: &ChainHead,
        _now_ms: u64,
        _revoked: &RevocationSet,
    ) -> Result<VerifiedGrant, GrantError> {
        todo!("Grant::verify")
    }
}

/// A game's revocation of one of its grants, named by the grant's nonce. It carries the
/// grant's expiry so a [`RevocationSet`] can drop it once the grant has expired anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub game: AliceId,
    pub nonce: [u8; 16],
    pub grant_expires_ms: u64,
    pub revoked_ms: u64,
    pub sig: AliceSig,
}

impl Revocation {
    /// Sign the revocation of `grant` at `revoked_ms`.
    ///
    /// # Errors
    /// [`GrantError::WrongGame`] when `game` did not issue `grant`.
    pub fn issue(_game: &Identity, _grant: &Grant, _revoked_ms: u64) -> Result<Self, GrantError> {
        todo!("Revocation::issue")
    }

    /// The wire form ([`REVOCATION_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; REVOCATION_LEN] {
        todo!("Revocation::to_bytes")
    }

    /// Read the wire form. The signature is not checked here ([`RevocationSet::add`] does).
    ///
    /// # Errors
    /// [`GrantError::Length`] for any other length, [`GrantError::Version`] for another
    /// version byte.
    pub fn from_bytes(_b: &[u8]) -> Result<Self, GrantError> {
        todo!("Revocation::from_bytes")
    }
}

/// The revocations a verifier knows, with a fixed capacity. A full set refuses a new
/// revocation and keeps every one it holds; entries leave only by [`RevocationSet::purge`],
/// once the revoked grant has expired.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct RevocationSet {
    entries: alloc::collections::BTreeMap<([u8; 32], [u8; 16]), u64>,
    capacity: usize,
}

#[cfg(feature = "alloc")]
impl RevocationSet {
    /// An empty set that holds at most `capacity` revocations.
    ///
    /// # Errors
    /// [`GrantError::Full`] when `capacity` is 0.
    pub fn new(_capacity: usize) -> Result<Self, GrantError> {
        todo!("RevocationSet::new")
    }

    /// Add a revocation after checking its signature under its game's key. Adding one the
    /// set already holds succeeds and keeps the first.
    ///
    /// # Errors
    /// [`GrantError::Signature`] when the signature does not verify, [`GrantError::Full`]
    /// when the set is full (nothing is stored).
    pub fn add(&mut self, _rev: &Revocation) -> Result<(), GrantError> {
        todo!("RevocationSet::add")
    }

    /// Whether the grant `nonce` of `game` is revoked.
    #[must_use]
    pub fn contains(&self, _game: &AliceId, _nonce: &[u8; 16]) -> bool {
        todo!("RevocationSet::contains")
    }

    /// Drop the revocations whose grant has expired (`grant_expires <= now_ms`); returns
    /// how many were dropped.
    pub fn purge(&mut self, _now_ms: u64) -> usize {
        todo!("RevocationSet::purge")
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Length of a [`RotationLink`] without its signature.
const ROTATION_BODY_LEN: usize = ROTATION_LINK_LEN - 64;

/// The longest body this module signs (a grant without its signature).
const MAX_BODY_LEN: usize = 137;

/// A key a chain may move to: a valid point that is not of small order.
fn usable_key(key: &AliceId) -> bool {
    VerifyingKey::from_bytes(&key.0).is_ok_and(|k| !k.is_weak())
}

/// Sign `tag` followed by `body`. Every signature this module makes goes through here.
fn sign_tagged(signer: &Identity, tag: &[u8; 24], body: &[u8]) -> AliceSig {
    let mut m = [0u8; 24 + MAX_BODY_LEN];
    let n = tagged(&mut m, tag, body);
    signer.sign(&m[..n])
}

/// Check strictly that `sig` is `key`'s signature of `tag` followed by `body`.
fn verify_tagged(key: &AliceId, tag: &[u8; 24], body: &[u8], sig: &AliceSig) -> bool {
    let mut m = [0u8; 24 + MAX_BODY_LEN];
    let n = tagged(&mut m, tag, body);
    verify(key, &m[..n], sig).is_ok()
}

fn tagged(m: &mut [u8; 24 + MAX_BODY_LEN], tag: &[u8; 24], body: &[u8]) -> usize {
    assert!(
        body.len() <= MAX_BODY_LEN,
        "a body of this module is at most 137 bytes"
    );
    m[..24].copy_from_slice(tag);
    m[24..24 + body.len()].copy_from_slice(body);
    24 + body.len()
}

fn array<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    a
}
