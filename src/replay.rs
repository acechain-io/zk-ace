//! Replay prevention logic for ZK-ACE STARK-based system.
//!
//! Provides two replay-prevention strategies:
//! - **Nonce Registry**: tracks per-identity monotonic nonces (rp_com = H(id_com || nonce)).
//! - **Nullifier Set**: tracks one-time nullifiers (rp_com = H(auth || domain)).

use std::collections::{HashMap, HashSet};

use stwo::core::fields::m31::M31;

use crate::stwo::types::{elements_to_bytes, ELEMENTS_PER_HASH};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors raised during replay-state checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStateError {
    /// The nonce presented is not strictly greater than the last recorded nonce.
    NonceNotMonotonic { last: u64, presented: u64 },
    /// The nullifier has already been consumed.
    NullifierAlreadyUsed,
}

impl std::fmt::Display for ReplayStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayStateError::NonceNotMonotonic { last, presented } => {
                write!(f, "nonce not monotonic: last={last}, presented={presented}")
            }
            ReplayStateError::NullifierAlreadyUsed => {
                write!(f, "nullifier already used")
            }
        }
    }
}

impl std::error::Error for ReplayStateError {}

// ---------------------------------------------------------------------------
// Helper: deterministic key from 8 field elements
// ---------------------------------------------------------------------------

/// Serialize 8 M31 elements to a `Vec<u8>` for use as a HashMap/HashSet key.
pub fn elements_key(elems: &[M31; ELEMENTS_PER_HASH]) -> Vec<u8> {
    elements_to_bytes(elems).to_vec()
}

// ---------------------------------------------------------------------------
// Store traits
// ---------------------------------------------------------------------------

/// Persistent store for per-identity nonce tracking.
pub trait NonceRegistryStore {
    /// Return the last recorded nonce for the given identity commitment, or `None`.
    fn get_last_nonce(&self, id_com: &[M31; ELEMENTS_PER_HASH]) -> Option<u64>;

    /// Atomically ensure the nonce is strictly greater than the stored value
    /// and persist it when accepted.
    fn check_and_record_nonce(
        &mut self,
        id_com: &[M31; ELEMENTS_PER_HASH],
        nonce: u64,
    ) -> Result<(), ReplayStateError>;
}

/// Persistent store for one-time nullifiers.
pub trait NullifierSetStore {
    /// Check whether the nullifier has already been consumed.
    fn contains(&self, nullifier: &[M31; ELEMENTS_PER_HASH]) -> bool;

    /// Atomically mark a nullifier as consumed iff it has not been seen before.
    fn check_and_insert_nullifier(
        &mut self,
        nullifier: &[M31; ELEMENTS_PER_HASH],
    ) -> Result<(), ReplayStateError>;
}

// ---------------------------------------------------------------------------
// In-memory implementations
// ---------------------------------------------------------------------------

/// In-memory nonce registry backed by a `HashMap`.
#[derive(Debug, Default)]
pub struct InMemoryNonceRegistry {
    map: HashMap<Vec<u8>, u64>,
}

impl InMemoryNonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceRegistryStore for InMemoryNonceRegistry {
    fn get_last_nonce(&self, id_com: &[M31; ELEMENTS_PER_HASH]) -> Option<u64> {
        self.map.get(&elements_key(id_com)).copied()
    }

    fn check_and_record_nonce(
        &mut self,
        id_com: &[M31; ELEMENTS_PER_HASH],
        nonce: u64,
    ) -> Result<(), ReplayStateError> {
        let key = elements_key(id_com);
        if let Some(&last) = self.map.get(&key) {
            if nonce <= last {
                return Err(ReplayStateError::NonceNotMonotonic {
                    last,
                    presented: nonce,
                });
            }
        }
        self.map.insert(key, nonce);
        Ok(())
    }
}

/// In-memory nullifier set backed by a `HashSet`.
#[derive(Debug, Default)]
pub struct InMemoryNullifierSet {
    set: HashSet<Vec<u8>>,
}

impl InMemoryNullifierSet {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NullifierSetStore for InMemoryNullifierSet {
    fn contains(&self, nullifier: &[M31; ELEMENTS_PER_HASH]) -> bool {
        self.set.contains(&elements_key(nullifier))
    }

    fn check_and_insert_nullifier(
        &mut self,
        nullifier: &[M31; ELEMENTS_PER_HASH],
    ) -> Result<(), ReplayStateError> {
        let key = elements_key(nullifier);
        if !self.set.insert(key) {
            return Err(ReplayStateError::NullifierAlreadyUsed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReplayGuard
// ---------------------------------------------------------------------------

/// Combined replay-prevention guard that delegates to a nonce registry and a
/// nullifier set depending on the replay mode encoded in the public inputs.
pub struct ReplayGuard<N: NonceRegistryStore, U: NullifierSetStore> {
    pub nonce_registry: N,
    pub nullifier_set: U,
}

impl<N: NonceRegistryStore, U: NullifierSetStore> ReplayGuard<N, U> {
    pub fn new(nonce_registry: N, nullifier_set: U) -> Self {
        Self {
            nonce_registry,
            nullifier_set,
        }
    }

    pub fn check_nonce(
        &self,
        id_com: &[M31; ELEMENTS_PER_HASH],
        nonce: u64,
    ) -> Result<(), ReplayStateError> {
        match self.nonce_registry.get_last_nonce(id_com) {
            Some(last) if nonce <= last => Err(ReplayStateError::NonceNotMonotonic {
                last,
                presented: nonce,
            }),
            _ => Ok(()),
        }
    }

    pub fn check_nullifier(
        &self,
        rp_com: &[M31; ELEMENTS_PER_HASH],
    ) -> Result<(), ReplayStateError> {
        if self.nullifier_set.contains(rp_com) {
            return Err(ReplayStateError::NullifierAlreadyUsed);
        }
        Ok(())
    }

    pub fn check_and_record_nonce(
        &mut self,
        id_com: &[M31; ELEMENTS_PER_HASH],
        nonce: u64,
    ) -> Result<(), ReplayStateError> {
        self.nonce_registry.check_and_record_nonce(id_com, nonce)
    }

    pub fn check_and_record_nullifier(
        &mut self,
        rp_com: &[M31; ELEMENTS_PER_HASH],
    ) -> Result<(), ReplayStateError> {
        self.nullifier_set.check_and_insert_nullifier(rp_com)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id_com() -> [M31; ELEMENTS_PER_HASH] {
        [
            M31(1),
            M31(2),
            M31(3),
            M31(4),
            M31(5),
            M31(6),
            M31(7),
            M31(8),
        ]
    }

    fn make_rp_com() -> [M31; ELEMENTS_PER_HASH] {
        [
            M31(10),
            M31(20),
            M31(30),
            M31(40),
            M31(50),
            M31(60),
            M31(70),
            M31(80),
        ]
    }

    #[test]
    fn elements_key_deterministic() {
        let a = make_id_com();
        assert_eq!(elements_key(&a), elements_key(&a));
    }

    #[test]
    fn nonce_registry_basic() {
        let mut reg = InMemoryNonceRegistry::new();
        let id = make_id_com();
        assert_eq!(reg.get_last_nonce(&id), None);
        reg.check_and_record_nonce(&id, 5).unwrap();
        assert_eq!(reg.get_last_nonce(&id), Some(5));
    }

    #[test]
    fn nullifier_set_basic() {
        let mut ns = InMemoryNullifierSet::new();
        let n = make_rp_com();
        assert!(!ns.contains(&n));
        ns.check_and_insert_nullifier(&n).unwrap();
        assert!(ns.contains(&n));
    }

    #[test]
    fn replay_guard_nonce_accepts_increasing() {
        let mut guard = ReplayGuard::new(InMemoryNonceRegistry::new(), InMemoryNullifierSet::new());
        let id = make_id_com();
        assert!(guard.check_and_record_nonce(&id, 1).is_ok());
        assert!(guard.check_and_record_nonce(&id, 2).is_ok());
        assert!(guard.check_and_record_nonce(&id, 5).is_ok());
    }

    #[test]
    fn replay_guard_nonce_rejects_stale() {
        let mut guard = ReplayGuard::new(InMemoryNonceRegistry::new(), InMemoryNullifierSet::new());
        let id = make_id_com();
        guard.check_and_record_nonce(&id, 3).unwrap();
        let err = guard.check_and_record_nonce(&id, 2).unwrap_err();
        assert_eq!(
            err,
            ReplayStateError::NonceNotMonotonic {
                last: 3,
                presented: 2,
            }
        );
    }

    #[test]
    fn replay_guard_nonce_rejects_equal() {
        let mut guard = ReplayGuard::new(InMemoryNonceRegistry::new(), InMemoryNullifierSet::new());
        let id = make_id_com();
        guard.check_and_record_nonce(&id, 3).unwrap();
        assert!(guard.check_and_record_nonce(&id, 3).is_err());
    }

    #[test]
    fn replay_guard_nullifier_rejects_replay() {
        let mut guard = ReplayGuard::new(InMemoryNonceRegistry::new(), InMemoryNullifierSet::new());
        let rp = make_rp_com();
        assert!(guard.check_and_record_nullifier(&rp).is_ok());
        assert_eq!(
            guard.check_and_record_nullifier(&rp).unwrap_err(),
            ReplayStateError::NullifierAlreadyUsed,
        );
    }
}
