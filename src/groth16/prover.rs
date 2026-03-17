//! Groth16 prover with deterministic trusted setup.
//!
//! SECURITY NOTE: The trusted setup uses a deterministic seed for the
//! reference implementation. A production deployment MUST use a proper
//! multi-party computation (MPC) ceremony.

use std::sync::OnceLock;

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

use super::circuit::ZkAceCircuit;
use super::commitment::Groth16PublicInputs;
use crate::errors::ZkAceError;
use crate::types::ReplayMode;

/// Cached proving/verifying keys per replay mode.
static NONCE_REGISTRY_KEYS: OnceLock<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> = OnceLock::new();
static NULLIFIER_SET_KEYS: OnceLock<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> = OnceLock::new();

/// Get (or compute) the proving and verifying keys for a given mode.
pub fn get_keys(mode: ReplayMode) -> &'static (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let cell = match mode {
        ReplayMode::NonceRegistry => &NONCE_REGISTRY_KEYS,
        ReplayMode::NullifierSet => &NULLIFIER_SET_KEYS,
    };
    cell.get_or_init(|| setup(mode).expect("Groth16 trusted setup failed"))
}

/// Run Groth16 trusted setup for the given replay mode.
fn setup(mode: ReplayMode) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), ZkAceError> {
    let circuit = ZkAceCircuit::for_setup(mode);
    let mut rng = deterministic_rng();
    Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| ZkAceError::ProvingFailed(format!("setup failed: {e}")))
}

/// Generate a Groth16 proof.
pub fn prove(circuit: ZkAceCircuit, mode: ReplayMode) -> Result<Vec<u8>, ZkAceError> {
    let (pk, _vk) = get_keys(mode);
    let mut rng = deterministic_rng();

    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ZkAceError::ProvingFailed(format!("prove failed: {e}")))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ZkAceError::SerializationError(format!("proof serialization: {e}")))?;

    Ok(proof_bytes)
}

/// Verify a Groth16 proof against public inputs.
pub fn verify(
    proof_bytes: &[u8],
    public_inputs: &Groth16PublicInputs,
    mode: ReplayMode,
) -> Result<bool, ZkAceError> {
    let (_pk, vk) = get_keys(mode);

    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ZkAceError::SerializationError(format!("proof deserialization: {e}")))?;

    let pvk = ark_groth16::prepare_verifying_key(vk);
    let pi_vec = public_inputs.to_vec();

    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &pi_vec, &proof)
        .map_err(|e| ZkAceError::VerificationFailed(format!("verify failed: {e}")))
}

/// Deterministic RNG for trusted setup and proving.
fn deterministic_rng() -> ark_std::rand::rngs::StdRng {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(b"ZK-ACE-GROTH16-TRUSTED-SETUP-v1");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    ark_std::rand::rngs::StdRng::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::commitment::compute_public_inputs;
    use crate::groth16::types::DerivationContext;
    use ark_bn254::Fr;

    fn make_circuit_and_pi(mode: ReplayMode) -> (ZkAceCircuit, Groth16PublicInputs) {
        let rev = Fr::from(42u64);
        let salt = Fr::from(100u64);
        let ctx = DerivationContext {
            alg_id: Fr::from(0u64),
            domain: Fr::from(1u64),
            index: Fr::from(0u64),
        };
        let nonce = Fr::from(7u64);
        let tx_hash = Fr::from(999u64);
        let domain = Fr::from(1u64);

        let pi = compute_public_inputs(&rev, &salt, &ctx, &nonce, &tx_hash, &domain, mode);

        let circuit = ZkAceCircuit {
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
        (circuit, pi)
    }

    #[test]
    fn prove_verify_nonce_registry() {
        let (circuit, pi) = make_circuit_and_pi(ReplayMode::NonceRegistry);
        let proof_bytes = prove(circuit, ReplayMode::NonceRegistry).unwrap();
        assert!(
            proof_bytes.len() <= 256,
            "proof too large: {} bytes",
            proof_bytes.len()
        );
        let valid = verify(&proof_bytes, &pi, ReplayMode::NonceRegistry).unwrap();
        assert!(valid, "valid proof rejected");
    }

    #[test]
    fn prove_verify_nullifier_set() {
        let (circuit, pi) = make_circuit_and_pi(ReplayMode::NullifierSet);
        let proof_bytes = prove(circuit, ReplayMode::NullifierSet).unwrap();
        let valid = verify(&proof_bytes, &pi, ReplayMode::NullifierSet).unwrap();
        assert!(valid, "valid proof rejected");
    }

    #[test]
    fn tampered_public_inputs_rejected() {
        let (circuit, mut pi) = make_circuit_and_pi(ReplayMode::NonceRegistry);
        let proof_bytes = prove(circuit, ReplayMode::NonceRegistry).unwrap();
        pi.id_com = Fr::from(9999u64); // tamper
        let valid = verify(&proof_bytes, &pi, ReplayMode::NonceRegistry).unwrap();
        assert!(!valid, "tampered proof should be rejected");
    }

    #[test]
    fn proof_size() {
        let (circuit, _pi) = make_circuit_and_pi(ReplayMode::NonceRegistry);
        let proof_bytes = prove(circuit, ReplayMode::NonceRegistry).unwrap();
        // Groth16 compressed proof: 2 G1 (32 bytes each) + 1 G2 (64 bytes) = 128 bytes
        assert_eq!(
            proof_bytes.len(),
            128,
            "unexpected proof size: {} bytes",
            proof_bytes.len()
        );
    }
}
