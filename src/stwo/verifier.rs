use num_traits::Zero;
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::air::preprocessed::generate_preprocessed_trace;
use super::air::schedule::{LOG_TRACE_SIZE, NUM_MAIN_COLUMNS};
use super::air::zkace_air::ZkAceEval;
use super::prover::{default_pcs_config, ZkAceProof};
use super::types::{ReplayMode, ZkAcePublicInputs};
use crate::errors::ZkAceError;

/// Verify a Circle STARK proof for a ZK-ACE authorization.
///
/// Deserialises the proof bytes and delegates to Stwo's verifier.
/// Returns `Ok(true)` when the proof is valid, or an error otherwise.
pub fn verify(
    proof_bytes: &ZkAceProof,
    public_inputs: &ZkAcePublicInputs,
    replay_mode: ReplayMode,
) -> Result<bool, ZkAceError> {
    // Deserialize the proof
    let proof: StarkProof<Blake2sMerkleHasher> = bincode::deserialize(proof_bytes)
        .map_err(|e| ZkAceError::VerificationFailed(format!("proof deserialization: {e}")))?;

    let config = default_pcs_config();

    // Reconstruct the component
    let eval = ZkAceEval::new(public_inputs.clone(), replay_mode);
    let mut location_allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut location_allocator, eval, SecureField::zero());

    // Set up the verification channel
    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    // Set up the commitment scheme verifier
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // Commit the preprocessed trace
    let num_preprocessed_cols = generate_preprocessed_trace().len();
    let preprocessed_sizes: Vec<u32> = vec![LOG_TRACE_SIZE; num_preprocessed_cols];
    commitment_scheme.commit(
        *proof.commitments.first().ok_or_else(|| {
            ZkAceError::VerificationFailed("missing preprocessed commitment".into())
        })?,
        &preprocessed_sizes,
        &mut channel,
    );

    // Commit the main trace
    let trace_sizes: Vec<u32> = vec![LOG_TRACE_SIZE; NUM_MAIN_COLUMNS];
    commitment_scheme.commit(
        *proof
            .commitments
            .get(1)
            .ok_or_else(|| ZkAceError::VerificationFailed("missing trace commitment".into()))?,
        &trace_sizes,
        &mut channel,
    );

    // Verify the proof
    let components: Vec<&dyn stwo::core::air::Component> = vec![&component];
    stwo::core::verifier::verify::<Blake2sMerkleChannel>(
        &components,
        &mut channel,
        &mut commitment_scheme,
        proof,
    )
    .map_err(|e| ZkAceError::VerificationFailed(format!("{e}")))?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo::native::commitment::compute_public_inputs;
    use crate::stwo::prover::prove;
    use crate::stwo::types::{
        DerivationContext, ZkAceWitness, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN,
    };
    use stwo::core::fields::m31::M31;

    fn test_witness() -> ZkAceWitness {
        ZkAceWitness {
            rev: [
                M31(42),
                M31(43),
                M31(44),
                M31(45),
                M31(46),
                M31(47),
                M31(48),
                M31(49),
                M31(0),
            ],
            salt: [
                M31(100),
                M31(101),
                M31(102),
                M31(103),
                M31(104),
                M31(105),
                M31(106),
                M31(107),
                M31(0),
            ],
            ctx: DerivationContext {
                alg_id: M31(0),
                domain: M31(1),
                index: M31(0),
            },
            nonce: [M31(7), M31(0), M31(0)],
        }
    }

    fn test_tx_hash() -> [M31; ELEMENTS_PER_BYTES32] {
        [
            M31(999),
            M31(998),
            M31(997),
            M31(996),
            M31(995),
            M31(994),
            M31(993),
            M31(992),
            M31(0),
        ]
    }

    fn test_domain() -> [M31; ELEMENTS_PER_DOMAIN] {
        [M31(1), M31(0), M31(0)]
    }

    #[test]
    fn prove_then_verify_roundtrip() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();
        let ok = verify(&proof, &pi, ReplayMode::NonceRegistry).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_rejects_wrong_public_inputs() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        // Tamper with a constrained public input field (id_com).
        let mut bad_pi = pi.clone();
        bad_pi.id_com[0] = M31(12345);

        let result = verify(&proof, &bad_pi, ReplayMode::NonceRegistry);
        // Should fail since constraints bind trace to public inputs
        assert!(result.is_err(), "tampered id_com must be rejected");
    }

    #[test]
    fn prove_verify_nullifier_mode() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NullifierSet);
        let proof = prove(&w, &pi, ReplayMode::NullifierSet).unwrap();
        let ok = verify(&proof, &pi, ReplayMode::NullifierSet).unwrap();
        assert!(ok);
    }

    #[test]
    fn soundness_tampered_idcom_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        let mut forged_pi = pi.clone();
        forged_pi.id_com[0] = M31(0xDEAD);

        let result = verify(&proof, &forged_pi, ReplayMode::NonceRegistry);
        assert!(result.is_err(), "forged id_com must be rejected");
    }

    #[test]
    fn soundness_tampered_target_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        let mut forged_pi = pi.clone();
        forged_pi.target[2] = M31(0xBEEF);

        let result = verify(&proof, &forged_pi, ReplayMode::NonceRegistry);
        assert!(result.is_err(), "forged target must be rejected");
    }

    #[test]
    fn soundness_cross_identity_proof_rejected() {
        let domain = test_domain();
        // Alice's witness
        let alice = ZkAceWitness {
            rev: [
                M31(42),
                M31(43),
                M31(44),
                M31(45),
                M31(46),
                M31(47),
                M31(48),
                M31(49),
                M31(0),
            ],
            salt: [
                M31(100),
                M31(101),
                M31(102),
                M31(103),
                M31(104),
                M31(105),
                M31(106),
                M31(107),
                M31(0),
            ],
            ctx: DerivationContext {
                alg_id: M31(0),
                domain: M31(1),
                index: M31(0),
            },
            nonce: [M31(7), M31(0), M31(0)],
        };
        let tx = test_tx_hash();
        let alice_pi = compute_public_inputs(&alice, &tx, &domain, ReplayMode::NonceRegistry);
        let alice_proof = prove(&alice, &alice_pi, ReplayMode::NonceRegistry).unwrap();

        // Bob has a different identity (different rev and salt)
        let bob = ZkAceWitness {
            rev: [
                M31(200),
                M31(201),
                M31(202),
                M31(203),
                M31(204),
                M31(205),
                M31(206),
                M31(207),
                M31(0),
            ],
            salt: [
                M31(300),
                M31(301),
                M31(302),
                M31(303),
                M31(304),
                M31(305),
                M31(306),
                M31(307),
                M31(0),
            ],
            ctx: DerivationContext {
                alg_id: M31(0),
                domain: M31(1),
                index: M31(0),
            },
            nonce: [M31(7), M31(0), M31(0)],
        };
        let bob_pi = compute_public_inputs(&bob, &tx, &domain, ReplayMode::NonceRegistry);

        // Bob's id_com should differ from Alice's
        assert_ne!(
            alice_pi.id_com, bob_pi.id_com,
            "different witnesses must produce different id_com"
        );

        // Alice's proof must fail against Bob's public inputs
        let result = verify(&alice_proof, &bob_pi, ReplayMode::NonceRegistry);
        assert!(
            result.is_err(),
            "cross-identity proof reuse must be rejected"
        );
    }

    #[test]
    fn soundness_tampered_rp_com_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        let mut forged_pi = pi.clone();
        forged_pi.rp_com[1] = M31(0xCAFE);

        let result = verify(&proof, &forged_pi, ReplayMode::NonceRegistry);
        assert!(result.is_err(), "forged rp_com must be rejected");
    }

    #[test]
    fn soundness_tampered_tx_hash_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();
        let mut forged_pi = pi.clone();
        forged_pi.tx_hash[0] = M31(0xDEAD);
        let result = verify(&proof, &forged_pi, ReplayMode::NonceRegistry);
        assert!(result.is_err(), "forged tx_hash must be rejected");
    }

    #[test]
    fn soundness_tampered_domain_rejected() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();
        let mut forged_pi = pi.clone();
        forged_pi.domain[0] = M31(999);
        let result = verify(&proof, &forged_pi, ReplayMode::NonceRegistry);
        assert!(result.is_err(), "forged domain must be rejected");
    }
}
