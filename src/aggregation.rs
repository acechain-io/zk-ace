//! Verified proof bundling for ZK-ACE.
//!
//! This module packages multiple individual ZK-ACE proofs with a deterministic
//! commitment over their public inputs. Unlike cryptographic aggregation, the
//! bundled verifier still re-verifies every constituent proof. The commitment
//! is an integrity checksum for the ordered bundle, not a standalone proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::ZkAceError;
use crate::traits::ZkAceEngine;
use crate::types::{PublicInputs, ReplayMode};

/// An individual proof bundled with its public inputs and replay mode.
#[derive(Clone, Debug)]
pub struct ProofEntry {
    pub proof: Vec<u8>,
    pub public_inputs: PublicInputs,
    pub replay_mode: ReplayMode,
}

/// The result of proof aggregation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedProof {
    /// Number of constituent proofs that were verified.
    pub num_proofs: u32,
    /// The ordered list of serialized constituent proofs.
    pub proofs: Vec<Vec<u8>>,
    /// The ordered list of public inputs from each constituent proof.
    pub all_public_inputs: Vec<PublicInputs>,
    /// The replay mode for each proof.
    pub replay_modes: Vec<ReplayMode>,
    /// SHA-256 commitment over all public inputs (deterministic, recomputable).
    pub commitment: [u8; 32],
}

/// Domain separator for aggregation commitments.
const AGG_DOMAIN_TAG: &[u8] = b"ZK-ACE-AGG-v1";

/// Compute the aggregation commitment over an ordered set of public inputs.
fn compute_aggregation_commitment(
    public_inputs: &[PublicInputs],
    replay_modes: &[ReplayMode],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AGG_DOMAIN_TAG);
    hasher.update((public_inputs.len() as u32).to_le_bytes());
    for (pi, mode) in public_inputs.iter().zip(replay_modes.iter()) {
        hasher.update(&pi.id_com);
        hasher.update(&pi.tx_hash);
        hasher.update(pi.domain.to_le_bytes());
        hasher.update(&pi.target);
        hasher.update(&pi.rp_com);
        hasher.update(match mode {
            ReplayMode::NonceRegistry => [0u8],
            ReplayMode::NullifierSet => [1u8],
        });
    }
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Verify each individual proof natively, then produce a bundled commitment.
///
/// Returns `Err` if any individual proof fails verification.
pub fn aggregate<E: ZkAceEngine>(proofs: &[ProofEntry]) -> Result<AggregatedProof, ZkAceError> {
    if proofs.is_empty() {
        return Err(ZkAceError::AggregationFailed(
            "cannot aggregate zero proofs".to_string(),
        ));
    }

    // Verify each proof
    for (i, entry) in proofs.iter().enumerate() {
        let valid =
            E::verify(&entry.proof, &entry.public_inputs, entry.replay_mode).map_err(|e| {
                ZkAceError::AggregationFailed(format!("proof {i} verification failed: {e}"))
            })?;
        if !valid {
            return Err(ZkAceError::AggregationFailed(format!(
                "proof {i} verification returned false"
            )));
        }
    }

    let bundled_proofs: Vec<Vec<u8>> = proofs.iter().map(|p| p.proof.clone()).collect();
    let all_public_inputs: Vec<PublicInputs> =
        proofs.iter().map(|p| p.public_inputs.clone()).collect();
    let replay_modes: Vec<ReplayMode> = proofs.iter().map(|p| p.replay_mode).collect();
    let commitment = compute_aggregation_commitment(&all_public_inputs, &replay_modes);

    Ok(AggregatedProof {
        num_proofs: proofs.len() as u32,
        proofs: bundled_proofs,
        all_public_inputs,
        replay_modes,
        commitment,
    })
}

/// Verify a bundled proof by recomputing the commitment and re-verifying each
/// constituent proof.
///
/// The commitment alone is not sufficient to establish validity.
pub fn verify_aggregated<E: ZkAceEngine>(agg: &AggregatedProof) -> Result<bool, ZkAceError> {
    if agg.num_proofs == 0 {
        return Err(ZkAceError::AggregatedVerificationFailed(
            "zero proofs".to_string(),
        ));
    }
    if agg.proofs.len() != agg.num_proofs as usize {
        return Err(ZkAceError::AggregatedVerificationFailed(format!(
            "num_proofs={} but {} proofs",
            agg.num_proofs,
            agg.proofs.len()
        )));
    }
    if agg.all_public_inputs.len() != agg.num_proofs as usize {
        return Err(ZkAceError::AggregatedVerificationFailed(format!(
            "num_proofs={} but {} public inputs",
            agg.num_proofs,
            agg.all_public_inputs.len()
        )));
    }
    if agg.replay_modes.len() != agg.num_proofs as usize {
        return Err(ZkAceError::AggregatedVerificationFailed(format!(
            "num_proofs={} but {} replay modes",
            agg.num_proofs,
            agg.replay_modes.len()
        )));
    }

    let expected = compute_aggregation_commitment(&agg.all_public_inputs, &agg.replay_modes);
    if expected != agg.commitment {
        return Err(ZkAceError::AggregatedVerificationFailed(
            "commitment mismatch".to_string(),
        ));
    }

    for (i, ((proof, public_inputs), replay_mode)) in agg
        .proofs
        .iter()
        .zip(agg.all_public_inputs.iter())
        .zip(agg.replay_modes.iter())
        .enumerate()
    {
        let valid = E::verify(proof, public_inputs, *replay_mode).map_err(|e| {
            ZkAceError::AggregatedVerificationFailed(format!("proof {i} verification failed: {e}"))
        })?;
        if !valid {
            return Err(ZkAceError::AggregatedVerificationFailed(format!(
                "proof {i} verification returned false"
            )));
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Witness;

    struct MockEngine;

    impl ZkAceEngine for MockEngine {
        fn compute_public_inputs(
            _witness: &Witness,
            _tx_hash: &[u8; 32],
            _domain: u64,
            _mode: ReplayMode,
        ) -> Result<PublicInputs, ZkAceError> {
            Err(ZkAceError::InvalidInput(
                "mock engine does not implement compute_public_inputs".to_string(),
            ))
        }

        fn prove(
            _witness: &Witness,
            _public_inputs: &PublicInputs,
            _mode: ReplayMode,
        ) -> Result<Vec<u8>, ZkAceError> {
            Err(ZkAceError::ProvingFailed(
                "mock engine does not implement prove".to_string(),
            ))
        }

        fn verify(
            proof: &[u8],
            public_inputs: &PublicInputs,
            mode: ReplayMode,
        ) -> Result<bool, ZkAceError> {
            let expected = vec![
                public_inputs.domain as u8,
                match mode {
                    ReplayMode::NonceRegistry => 0,
                    ReplayMode::NullifierSet => 1,
                },
            ];
            Ok(proof == expected)
        }

        fn name() -> &'static str {
            "mock"
        }
    }

    fn mock_pi(seed: u8) -> PublicInputs {
        PublicInputs {
            id_com: [seed; 32],
            tx_hash: [seed.wrapping_add(1); 32],
            domain: seed as u64,
            target: [seed.wrapping_add(2); 32],
            rp_com: [seed.wrapping_add(3); 32],
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let pis = vec![mock_pi(1), mock_pi(2)];
        let modes = vec![ReplayMode::NonceRegistry, ReplayMode::NullifierSet];
        let c1 = compute_aggregation_commitment(&pis, &modes);
        let c2 = compute_aggregation_commitment(&pis, &modes);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_differs_on_reorder() {
        let pis_a = vec![mock_pi(1), mock_pi(2)];
        let pis_b = vec![mock_pi(2), mock_pi(1)];
        let modes = vec![ReplayMode::NonceRegistry, ReplayMode::NonceRegistry];
        let c1 = compute_aggregation_commitment(&pis_a, &modes);
        let c2 = compute_aggregation_commitment(&pis_b, &modes);
        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_aggregated_rejects_tampered_commitment() {
        let pis = vec![mock_pi(1)];
        let modes = vec![ReplayMode::NonceRegistry];
        let commitment = compute_aggregation_commitment(&pis, &modes);
        let mut agg = AggregatedProof {
            num_proofs: 1,
            proofs: vec![vec![1, 0]],
            all_public_inputs: pis,
            replay_modes: modes,
            commitment,
        };
        agg.commitment[0] ^= 0xFF;
        assert!(verify_aggregated::<MockEngine>(&agg).is_err());
    }

    #[test]
    fn verify_aggregated_rejects_count_mismatch() {
        let agg = AggregatedProof {
            num_proofs: 5,
            proofs: vec![vec![1, 0]],
            all_public_inputs: vec![mock_pi(1)],
            replay_modes: vec![ReplayMode::NonceRegistry],
            commitment: [0; 32],
        };
        assert!(verify_aggregated::<MockEngine>(&agg).is_err());
    }

    #[test]
    fn verify_aggregated_rejects_tampered_pi() {
        let pis = vec![mock_pi(1), mock_pi(2)];
        let modes = vec![ReplayMode::NonceRegistry, ReplayMode::NullifierSet];
        let commitment = compute_aggregation_commitment(&pis, &modes);
        let mut agg = AggregatedProof {
            num_proofs: 2,
            proofs: vec![vec![1, 0], vec![2, 1]],
            all_public_inputs: pis,
            replay_modes: modes,
            commitment,
        };
        agg.all_public_inputs[0].id_com[0] ^= 0xFF;
        assert!(verify_aggregated::<MockEngine>(&agg).is_err());
    }

    #[test]
    fn verify_aggregated_accepts_valid_bundle() {
        let pis = vec![mock_pi(1), mock_pi(2), mock_pi(3)];
        let modes = vec![
            ReplayMode::NonceRegistry,
            ReplayMode::NullifierSet,
            ReplayMode::NonceRegistry,
        ];
        let commitment = compute_aggregation_commitment(&pis, &modes);
        let agg = AggregatedProof {
            num_proofs: 3,
            proofs: vec![vec![1, 0], vec![2, 1], vec![3, 0]],
            all_public_inputs: pis,
            replay_modes: modes,
            commitment,
        };
        assert!(verify_aggregated::<MockEngine>(&agg).unwrap());
    }

    #[test]
    fn aggregate_rejects_proof_that_verifies_false() {
        let proofs = vec![ProofEntry {
            proof: vec![9, 9],
            public_inputs: mock_pi(1),
            replay_mode: ReplayMode::NonceRegistry,
        }];
        assert!(aggregate::<MockEngine>(&proofs).is_err());
    }

    #[test]
    fn verify_aggregated_rejects_forged_proof_bytes() {
        let pis = vec![mock_pi(1)];
        let modes = vec![ReplayMode::NonceRegistry];
        let commitment = compute_aggregation_commitment(&pis, &modes);
        let agg = AggregatedProof {
            num_proofs: 1,
            proofs: vec![vec![9, 9]],
            all_public_inputs: pis,
            replay_modes: modes,
            commitment,
        };
        assert!(verify_aggregated::<MockEngine>(&agg).is_err());
    }
}
