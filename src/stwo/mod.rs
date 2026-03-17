//! Stwo Circle STARK backend for ZK-ACE.
//!
//! Post-quantum secure: verification relies only on hash functions (Blake2s)
//! and the FRI protocol. No elliptic curve assumptions.

pub mod air;
pub mod native;
pub mod prover;
pub mod serde_utils;
pub mod trace;
pub mod types;
pub mod verifier;

use stwo::core::fields::m31::M31;

use crate::errors::ZkAceError;
use crate::traits::ZkAceEngine;
use crate::types::{PublicInputs, ReplayMode, Witness};

use self::types as stwo_types;

/// Stwo Circle STARK backend.
pub struct StwoEngine;

impl StwoEngine {
    /// Convert a core `Witness` to Stwo-internal `ZkAceWitness`.
    fn to_internal_witness(witness: &Witness) -> Result<stwo_types::ZkAceWitness, ZkAceError> {
        let rev = stwo_types::bytes_to_elements(&witness.rev);
        let salt = stwo_types::bytes_to_elements(&witness.salt);
        let ctx = stwo_types::DerivationContext {
            alg_id: stwo_types::try_u64_to_element(witness.alg_id).ok_or_else(|| {
                ZkAceError::InvalidInput(format!(
                    "alg_id={} does not fit in a canonical M31 element",
                    witness.alg_id
                ))
            })?,
            domain: stwo_types::try_u64_to_element(witness.domain).ok_or_else(|| {
                ZkAceError::InvalidInput(format!(
                    "domain={} does not fit in a canonical M31 element",
                    witness.domain
                ))
            })?,
            index: stwo_types::try_u64_to_element(witness.index).ok_or_else(|| {
                ZkAceError::InvalidInput(format!(
                    "index={} does not fit in a canonical M31 element",
                    witness.index
                ))
            })?,
        };
        let nonce = stwo_types::u64_to_domain_elements(witness.nonce);
        Ok(stwo_types::ZkAceWitness {
            rev,
            salt,
            ctx,
            nonce,
        })
    }

    /// Convert core `PublicInputs` to Stwo-internal `ZkAcePublicInputs`.
    fn to_internal_pi(pi: &PublicInputs) -> Result<stwo_types::ZkAcePublicInputs, ZkAceError> {
        Ok(stwo_types::ZkAcePublicInputs {
            id_com: bytes32_to_hash8(&pi.id_com)?,
            tx_hash: stwo_types::bytes_to_elements(&pi.tx_hash),
            domain: stwo_types::u64_to_domain_elements(pi.domain),
            target: bytes32_to_hash8(&pi.target)?,
            rp_com: bytes32_to_hash8(&pi.rp_com)?,
        })
    }

    /// Convert Stwo-internal `ZkAcePublicInputs` to core `PublicInputs`.
    fn from_internal_pi(pi: &stwo_types::ZkAcePublicInputs) -> PublicInputs {
        PublicInputs {
            id_com: hash8_to_bytes32(&pi.id_com),
            tx_hash: stwo_types::bytes32_from_elements(&pi.tx_hash),
            domain: stwo_types::domain_elements_to_u64(&pi.domain),
            target: hash8_to_bytes32(&pi.target),
            rp_com: hash8_to_bytes32(&pi.rp_com),
        }
    }

    /// Convert core `ReplayMode` to Stwo-internal `ReplayMode`.
    fn to_internal_mode(mode: ReplayMode) -> stwo_types::ReplayMode {
        match mode {
            ReplayMode::NonceRegistry => stwo_types::ReplayMode::NonceRegistry,
            ReplayMode::NullifierSet => stwo_types::ReplayMode::NullifierSet,
        }
    }
}

impl ZkAceEngine for StwoEngine {
    fn compute_public_inputs(
        witness: &Witness,
        tx_hash: &[u8; 32],
        domain: u64,
        mode: ReplayMode,
    ) -> Result<PublicInputs, ZkAceError> {
        let w = Self::to_internal_witness(witness)?;
        let tx = stwo_types::bytes_to_elements(tx_hash);
        let d = stwo_types::u64_to_domain_elements(domain);
        let internal_mode = Self::to_internal_mode(mode);
        let pi = native::commitment::compute_public_inputs(&w, &tx, &d, internal_mode);
        Ok(Self::from_internal_pi(&pi))
    }

    fn prove(
        witness: &Witness,
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<Vec<u8>, ZkAceError> {
        let w = Self::to_internal_witness(witness)?;
        let pi = Self::to_internal_pi(public_inputs)?;
        let internal_mode = Self::to_internal_mode(mode);
        prover::prove(&w, &pi, internal_mode)
    }

    fn verify(
        proof: &[u8],
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<bool, ZkAceError> {
        let pi = Self::to_internal_pi(public_inputs)?;
        let internal_mode = Self::to_internal_mode(mode);
        let proof_vec = proof.to_vec();
        verifier::verify(&proof_vec, &pi, internal_mode)
    }

    fn name() -> &'static str {
        "stwo"
    }
}

/// Convert 32 bytes to canonical [M31; 8] hash elements.
fn bytes32_to_hash8(bytes: &[u8; 32]) -> Result<[M31; stwo_types::ELEMENTS_PER_HASH], ZkAceError> {
    stwo_types::try_bytes32_to_hash_elements(bytes).ok_or_else(|| {
        ZkAceError::InvalidInput(
            "hash-shaped public input is not canonically encoded as 8 M31 elements".to_string(),
        )
    })
}

/// Convert [M31; 8] to 32 bytes.
fn hash8_to_bytes32(elems: &[M31; stwo_types::ELEMENTS_PER_HASH]) -> [u8; 32] {
    stwo_types::elements_to_bytes(elems)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_witness() -> Witness {
        let mut rev = [0u8; 32];
        rev[0] = 42;
        let mut salt = [0u8; 32];
        salt[0] = 9;
        Witness {
            rev,
            salt,
            alg_id: 0,
            domain: 1,
            index: 0,
            nonce: 7,
        }
    }

    fn test_tx_hash() -> [u8; 32] {
        let mut tx = [0u8; 32];
        tx[0] = 0xAA;
        tx[1] = 0xBB;
        tx
    }

    #[test]
    fn compute_public_inputs_rejects_large_context_scalars() {
        let mut witness = test_witness();
        witness.alg_id = (1u64 << 31) - 1;
        let err = StwoEngine::compute_public_inputs(
            &witness,
            &test_tx_hash(),
            1,
            ReplayMode::NonceRegistry,
        )
        .unwrap_err();
        assert!(matches!(err, ZkAceError::InvalidInput(_)));
    }

    #[test]
    fn verify_rejects_noncanonical_hash_public_input_encoding() {
        let witness = test_witness();
        let tx_hash = test_tx_hash();
        let pi =
            StwoEngine::compute_public_inputs(&witness, &tx_hash, 1, ReplayMode::NonceRegistry)
                .unwrap();
        let proof = StwoEngine::prove(&witness, &pi, ReplayMode::NonceRegistry).unwrap();

        let mut bad_pi = pi.clone();
        bad_pi.id_com[0..4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());

        let err = StwoEngine::verify(&proof, &bad_pi, ReplayMode::NonceRegistry).unwrap_err();
        assert!(matches!(err, ZkAceError::InvalidInput(_)));
    }
}
