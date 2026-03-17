//! Backend trait for pluggable proof systems.
//!
//! Each backend (Stwo Circle STARK, Groth16, etc.) implements `ZkAceEngine`
//! to provide proving, verification, and public input computation using its
//! native field and proof system.

use crate::errors::ZkAceError;
use crate::types::{PublicInputs, ReplayMode, Witness};

/// Core engine trait that every ZK-ACE backend must implement.
///
/// The trait operates on byte-based types so callers are decoupled from the
/// backend's internal field representation (M31, BN254 Fr, etc.).
pub trait ZkAceEngine {
    /// Compute public inputs from a witness, transaction hash, and domain.
    fn compute_public_inputs(
        witness: &Witness,
        tx_hash: &[u8; 32],
        domain: u64,
        mode: ReplayMode,
    ) -> Result<PublicInputs, ZkAceError>;

    /// Generate a proof for the given witness and public inputs.
    fn prove(
        witness: &Witness,
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<Vec<u8>, ZkAceError>;

    /// Verify a proof against the given public inputs.
    fn verify(
        proof: &[u8],
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<bool, ZkAceError>;

    /// Human-readable name of this backend (e.g., "stwo", "groth16").
    fn name() -> &'static str;
}
