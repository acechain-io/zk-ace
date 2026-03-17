//! Groth16 verifier (delegates to prover module's verify function).
//!
//! This module exists for API symmetry with the Stwo backend.
//! The actual verification logic is in prover.rs alongside the setup.

use super::commitment::Groth16PublicInputs;
use crate::errors::ZkAceError;
use crate::types::ReplayMode;

/// Verify a Groth16 proof.
pub fn verify(
    proof_bytes: &[u8],
    public_inputs: &Groth16PublicInputs,
    mode: ReplayMode,
) -> Result<bool, ZkAceError> {
    super::prover::verify(proof_bytes, public_inputs, mode)
}
