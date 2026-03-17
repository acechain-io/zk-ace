use num_traits::Zero;
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::NaturalOrder;
use stwo::prover::CommitmentSchemeProver;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::air::preprocessed::generate_preprocessed_trace;
use super::air::schedule::{coset_order_to_circle_domain_order, LOG_TRACE_SIZE};
use super::air::zkace_air::ZkAceEval;
use super::trace::build_trace;
use super::types::{ReplayMode, ZkAcePublicInputs, ZkAceWitness};
use crate::errors::ZkAceError;

/// Type alias for serialized STARK proofs.
pub type ZkAceProof = Vec<u8>;

/// Returns PCS config for ~128-bit conjectured security.
pub fn default_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 16,
        fri_config: FriConfig::new(1, 3, 70, 1),
        lifting_log_size: None,
    }
}

/// Generate a Circle STARK proof for a ZK-ACE authorization.
///
/// The prover:
/// 1. Builds the preprocessed trace (schedule selectors and round constants).
/// 2. Builds the main execution trace from the witness and public inputs.
/// 3. Invokes the Stwo STARK prover.
/// 4. Serialises the proof to bytes via bincode.
pub fn prove(
    witness: &ZkAceWitness,
    public_inputs: &ZkAcePublicInputs,
    replay_mode: ReplayMode,
) -> Result<ZkAceProof, ZkAceError> {
    let config = default_pcs_config();

    // Create the component evaluator
    let eval = ZkAceEval::new(public_inputs.clone(), replay_mode);
    let mut location_allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut location_allocator, eval, SecureField::zero());

    // Precompute twiddles for the evaluation domain
    let log_domain_size = LOG_TRACE_SIZE + config.fri_config.log_blowup_factor;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(log_domain_size).half_coset());

    // Set up the commitment scheme
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // Set up channel
    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    // 1. Commit preprocessed trace
    // Trace/preprocessed data is built in coset (step) order. Convert to
    // circle-domain natural order before creating CircleEvaluation.
    let preprocessed_columns = generate_preprocessed_trace();
    let domain = CanonicCoset::new(LOG_TRACE_SIZE).circle_domain();
    let preprocessed_evals: Vec<CircleEvaluation<SimdBackend, M31, _>> = preprocessed_columns
        .into_iter()
        .map(|col_data| {
            let cd_data = coset_order_to_circle_domain_order(&col_data);
            let eval: CircleEvaluation<SimdBackend, M31, NaturalOrder> =
                CircleEvaluation::new(domain, cd_data.into_iter().collect());
            eval.bit_reverse()
        })
        .collect();
    let mut preprocessed_builder = commitment_scheme.tree_builder();
    preprocessed_builder.extend_evals(preprocessed_evals);
    preprocessed_builder.commit(&mut channel);

    // 2. Build and commit main trace
    let columns = build_trace(witness, public_inputs, replay_mode);
    let trace_evals: Vec<CircleEvaluation<SimdBackend, M31, _>> = columns
        .into_iter()
        .map(|col_data| {
            let cd_data = coset_order_to_circle_domain_order(&col_data);
            let eval: CircleEvaluation<SimdBackend, M31, NaturalOrder> =
                CircleEvaluation::new(domain, cd_data.into_iter().collect());
            eval.bit_reverse()
        })
        .collect();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace_evals);
    tree_builder.commit(&mut channel);

    // 3. Generate the proof
    let components: Vec<&dyn stwo::prover::ComponentProver<SimdBackend>> = vec![&component];
    let proof = stwo::prover::prove(&components, &mut channel, commitment_scheme)
        .map_err(|e| ZkAceError::ProvingFailed(format!("{e:?}")))?;

    // Serialize the proof
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| ZkAceError::ProvingFailed(format!("proof serialization: {e}")))?;

    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo::native::commitment::compute_public_inputs;
    use crate::stwo::types::{DerivationContext, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN};

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
    fn prove_produces_non_empty_proof() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();
        assert!(!proof.is_empty());
    }
}
