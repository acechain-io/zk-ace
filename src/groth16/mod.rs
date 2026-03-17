//! Groth16/BN254 backend for ZK-ACE.
//!
//! Compact proofs (~128 bytes) with trusted setup.
//! NOT post-quantum secure — suitable for non-PQC deployments
//! or as a migration stepping stone.
//!
//! Uses Poseidon hash over BN254 Fr and arkworks Groth16 prover/verifier.

pub mod circuit;
pub mod commitment;
pub mod derive;
pub mod hash;
pub mod prover;
pub mod types;
pub mod verifier;

use ark_bn254::Fr;

use crate::errors::ZkAceError;
use crate::traits::ZkAceEngine;
use crate::types::{PublicInputs, ReplayMode, Witness};

use self::types as g16_types;

/// Groth16/BN254 backend.
pub struct Groth16Engine;

impl Groth16Engine {
    /// Convert a core `Witness` to Groth16-internal Fr values.
    fn to_internal(witness: &Witness) -> (Fr, Fr, g16_types::DerivationContext, Fr) {
        let rev = g16_types::bytes32_to_fr(&witness.rev);
        let salt = g16_types::bytes32_to_fr(&witness.salt);
        let ctx = g16_types::DerivationContext {
            alg_id: g16_types::u64_to_fr(witness.alg_id),
            domain: g16_types::u64_to_fr(witness.domain),
            index: g16_types::u64_to_fr(witness.index),
        };
        let nonce = g16_types::u64_to_fr(witness.nonce);
        (rev, salt, ctx, nonce)
    }

    /// Convert core `PublicInputs` to Groth16-internal `Groth16PublicInputs`.
    fn to_internal_pi(pi: &PublicInputs) -> Result<commitment::Groth16PublicInputs, ZkAceError> {
        Ok(commitment::Groth16PublicInputs {
            id_com: g16_types::try_bytes32_to_fr(&pi.id_com).ok_or_else(|| {
                ZkAceError::InvalidInput(
                    "id_com is not canonically encoded for BN254 Fr".to_string(),
                )
            })?,
            tx_hash: g16_types::try_bytes32_to_fr(&pi.tx_hash).ok_or_else(|| {
                ZkAceError::InvalidInput(
                    "tx_hash is not canonically encoded for BN254 Fr".to_string(),
                )
            })?,
            domain: g16_types::u64_to_fr(pi.domain),
            target: g16_types::try_bytes32_to_fr(&pi.target).ok_or_else(|| {
                ZkAceError::InvalidInput(
                    "target is not canonically encoded for BN254 Fr".to_string(),
                )
            })?,
            rp_com: g16_types::try_bytes32_to_fr(&pi.rp_com).ok_or_else(|| {
                ZkAceError::InvalidInput(
                    "rp_com is not canonically encoded for BN254 Fr".to_string(),
                )
            })?,
        })
    }

    /// Convert Groth16-internal `Groth16PublicInputs` to core `PublicInputs`.
    fn from_internal_pi(pi: &commitment::Groth16PublicInputs) -> PublicInputs {
        PublicInputs {
            id_com: g16_types::fr_to_bytes32(&pi.id_com),
            tx_hash: g16_types::fr_to_bytes32(&pi.tx_hash),
            domain: g16_types::fr_to_u64(&pi.domain),
            target: g16_types::fr_to_bytes32(&pi.target),
            rp_com: g16_types::fr_to_bytes32(&pi.rp_com),
        }
    }
}

impl ZkAceEngine for Groth16Engine {
    fn compute_public_inputs(
        witness: &Witness,
        tx_hash: &[u8; 32],
        domain: u64,
        mode: ReplayMode,
    ) -> Result<PublicInputs, ZkAceError> {
        let (rev, salt, ctx, nonce) = Self::to_internal(witness);
        let tx = g16_types::bytes32_to_fr(tx_hash);
        let d = g16_types::u64_to_fr(domain);
        let pi = commitment::compute_public_inputs(&rev, &salt, &ctx, &nonce, &tx, &d, mode);
        Ok(Self::from_internal_pi(&pi))
    }

    fn prove(
        witness: &Witness,
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<Vec<u8>, ZkAceError> {
        let (rev, salt, ctx, nonce) = Self::to_internal(witness);
        let pi = Self::to_internal_pi(public_inputs)?;

        let circuit = circuit::ZkAceCircuit {
            rev: Some(rev),
            salt: Some(salt),
            alg_id: Some(ctx.alg_id),
            domain_ctx: Some(ctx.domain),
            index: Some(ctx.index),
            nonce: Some(nonce),
            id_com: Some(pi.id_com),
            tx_hash: Some(pi.tx_hash),
            domain: Some(pi.domain),
            target: Some(pi.target),
            rp_com: Some(pi.rp_com),
            mode,
        };

        prover::prove(circuit, mode)
    }

    fn verify(
        proof: &[u8],
        public_inputs: &PublicInputs,
        mode: ReplayMode,
    ) -> Result<bool, ZkAceError> {
        let pi = Self::to_internal_pi(public_inputs)?;
        verifier::verify(proof, &pi, mode)
    }

    fn name() -> &'static str {
        "groth16"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_witness() -> Witness {
        let mut rev = [0u8; 32];
        rev[0] = 42;
        rev[1] = 43;
        let mut salt = [0u8; 32];
        salt[0] = 100;
        salt[1] = 101;
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
        tx[0] = 0xFF;
        tx[1] = 0xAB;
        tx
    }

    #[test]
    fn engine_compute_public_inputs_deterministic() {
        let w = test_witness();
        let tx = test_tx_hash();
        let pi1 =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NonceRegistry).unwrap();
        let pi2 =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NonceRegistry).unwrap();
        assert_eq!(pi1, pi2);
    }

    #[test]
    fn engine_prove_verify_nonce_registry() {
        let w = test_witness();
        let tx = test_tx_hash();
        let pi =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NonceRegistry).unwrap();
        let proof = Groth16Engine::prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();
        assert_eq!(
            proof.len(),
            128,
            "Groth16 compressed proof should be 128 bytes"
        );
        let valid = Groth16Engine::verify(&proof, &pi, ReplayMode::NonceRegistry).unwrap();
        assert!(valid, "valid proof rejected");
    }

    #[test]
    fn engine_prove_verify_nullifier_set() {
        let w = test_witness();
        let tx = test_tx_hash();
        let pi =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NullifierSet).unwrap();
        let proof = Groth16Engine::prove(&w, &pi, ReplayMode::NullifierSet).unwrap();
        let valid = Groth16Engine::verify(&proof, &pi, ReplayMode::NullifierSet).unwrap();
        assert!(valid, "valid proof rejected");
    }

    #[test]
    fn engine_tampered_proof_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let pi =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NonceRegistry).unwrap();
        let proof = Groth16Engine::prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        // Tamper with public inputs
        let mut bad_pi = pi.clone();
        bad_pi.id_com[0] ^= 0xFF;
        let valid = Groth16Engine::verify(&proof, &bad_pi, ReplayMode::NonceRegistry).unwrap();
        assert!(!valid, "tampered public inputs should be rejected");
    }

    #[test]
    fn engine_rejects_noncanonical_public_input_encoding() {
        let w = test_witness();
        let tx = test_tx_hash();
        let pi =
            Groth16Engine::compute_public_inputs(&w, &tx, 1, ReplayMode::NonceRegistry).unwrap();
        let proof = Groth16Engine::prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        let mut bad_pi = pi.clone();
        bad_pi.id_com = [0xFF; 32];

        let err = Groth16Engine::verify(&proof, &bad_pi, ReplayMode::NonceRegistry).unwrap_err();
        assert!(matches!(err, ZkAceError::InvalidInput(_)));
    }

    #[test]
    fn engine_name() {
        assert_eq!(Groth16Engine::name(), "groth16");
    }
}
