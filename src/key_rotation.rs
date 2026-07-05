//! key rotation.

use crate::errors::*;
use crate::identity::*;
use crate::types::*;
use crate::verify::ok;
use zeroize::Zeroize;

// Key Rotation
// ============================================================================

/// Identity with key rotation support.
///
/// Maintains a current keypair and up to `max_generations` previous keys
/// (for graceful transition). Callers should verify signatures against
/// all retained keys during the rotation window.
#[cfg(feature = "std")]
pub struct RotatingIdentity {
    current: Identity,
    previous: Vec<(Identity, u64)>,
    max_generations: usize,
}

#[cfg(feature = "std")]
impl RotatingIdentity {
    /// Default maximum number of previous key generations to retain.
    pub const DEFAULT_MAX_GENERATIONS: usize = 2;

    /// Create a new rotating identity from a fresh keypair.
    /// # Errors
    /// Returns `AuthError::E5` if the platform RNG fails.
    pub fn gen() -> Result<Self> {
        Ok(Self {
            current: Identity::gen()?,
            previous: Vec::new(),
            max_generations: Self::DEFAULT_MAX_GENERATIONS,
        })
    }

    /// Create from an existing identity.
    #[must_use]
    pub const fn from_identity(id: Identity) -> Self {
        Self {
            current: id,
            previous: Vec::new(),
            max_generations: Self::DEFAULT_MAX_GENERATIONS,
        }
    }

    /// Create with a custom maximum number of previous generations.
    #[must_use]
    pub fn with_max_generations(id: Identity, max: usize) -> Self {
        Self {
            current: id,
            previous: Vec::new(),
            max_generations: max.max(1),
        }
    }

    /// Rotate to a new keypair. The old key is archived with a timestamp.
    /// Oldest generations beyond `max_generations` are evicted (and zeroized).
    /// Returns the new public `AliceId`.
    /// # Errors
    /// Returns `AuthError::E5` if the platform RNG fails.
    pub fn rotate(&mut self, now_ms: u64) -> Result<AliceId> {
        let mut old_seed = self.current.seed();
        let old = Identity::from_seed(&old_seed);
        old_seed.zeroize();
        let new = Identity::gen()?;
        self.previous.push((old, now_ms));
        // Evict oldest generations beyond limit (dropped Identity runs Drop → zeroize)
        while self.previous.len() > self.max_generations {
            self.previous.remove(0);
        }
        self.current = new;
        Ok(self.current.id())
    }

    /// Get the current public identity.
    #[inline]
    #[must_use]
    pub fn id(&self) -> AliceId {
        self.current.id()
    }

    /// Get the most recent previous public identity (if rotation has occurred).
    #[must_use]
    pub fn previous_id(&self) -> Option<(AliceId, u64)> {
        self.previous.last().map(|(id, ts)| (id.id(), *ts))
    }

    /// Get all previous public identities (oldest first).
    #[must_use]
    pub fn previous_ids(&self) -> Vec<(AliceId, u64)> {
        self.previous
            .iter()
            .map(|(id, ts)| (id.id(), *ts))
            .collect()
    }

    /// Sign with the current key.
    #[inline]
    #[must_use]
    pub fn sign(&self, m: &[u8]) -> AliceSig {
        self.current.sign(m)
    }

    /// Verify a signature against the current key, falling back to all
    /// previous keys. Returns true if any key matches.
    #[must_use]
    pub fn verify_any(&self, id: &AliceId, m: &[u8], s: &AliceSig) -> bool {
        if ok(id, m, s) {
            return true;
        }
        for (prev, _) in &self.previous {
            if ok(&prev.id(), m, s) {
                return true;
            }
        }
        false
    }

    /// Clear all previous keys (after rotation window expires).
    pub fn clear_previous(&mut self) {
        self.previous.clear();
    }

    /// Check if rotation has occurred and previous keys exist.
    #[must_use]
    pub const fn has_previous(&self) -> bool {
        !self.previous.is_empty()
    }

    /// Number of retained previous generations.
    #[must_use]
    pub const fn generation_count(&self) -> usize {
        self.previous.len()
    }
}
