//! R1CS circuit for ZK-ACE Groth16 backend.
//!
//! Enforces constraints C1-C5 using in-circuit Poseidon hash over BN254 Fr.
//! The replay mode (NonceRegistry vs NullifierSet) is baked into the circuit
//! at construction time, producing two distinct circuit structures.

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::hash::{
    mds_matrix, round_constants, CAPACITY, FULL_ROUNDS_BEGIN, FULL_ROUNDS_END, PARTIAL_ROUNDS,
    RATE, WIDTH,
};
use crate::types::ReplayMode;

// ---------------------------------------------------------------------------
// In-circuit Poseidon primitives
// ---------------------------------------------------------------------------

/// S-box in R1CS: x^5
fn sbox_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    Ok(&x4 * x)
}

/// Apply MDS matrix in R1CS (linear operation, no constraints added).
fn apply_mds_var(state: &mut [FpVar<Fr>; WIDTH]) {
    let mds = mds_matrix();
    let old = state.clone();
    for i in 0..WIDTH {
        state[i] = FpVar::zero();
        for j in 0..WIDTH {
            // Constant * variable is a linear combination (free in R1CS)
            state[i] = &state[i] + &(&old[j] * FpVar::constant(mds[i][j]));
        }
    }
}

/// Full round in R1CS: S-box on all, MDS, add constants.
fn full_round_var(state: &mut [FpVar<Fr>; WIDTH], rc: &[Fr; WIDTH]) -> Result<(), SynthesisError> {
    for i in 0..WIDTH {
        state[i] = sbox_var(&state[i])?;
    }
    apply_mds_var(state);
    for i in 0..WIDTH {
        state[i] = &state[i] + FpVar::constant(rc[i]);
    }
    Ok(())
}

/// Partial round in R1CS: S-box on first element, MDS, add constants.
fn partial_round_var(
    state: &mut [FpVar<Fr>; WIDTH],
    rc: &[Fr; WIDTH],
) -> Result<(), SynthesisError> {
    state[0] = sbox_var(&state[0])?;
    apply_mds_var(state);
    for i in 0..WIDTH {
        state[i] = &state[i] + FpVar::constant(rc[i]);
    }
    Ok(())
}

/// Poseidon permutation in R1CS.
fn poseidon_permutation_var(state: &mut [FpVar<Fr>; WIDTH]) -> Result<(), SynthesisError> {
    let rc = round_constants();
    let mut round = 0;
    for _ in 0..FULL_ROUNDS_BEGIN {
        full_round_var(state, &rc[round])?;
        round += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        partial_round_var(state, &rc[round])?;
        round += 1;
    }
    for _ in 0..FULL_ROUNDS_END {
        full_round_var(state, &rc[round])?;
        round += 1;
    }
    Ok(())
}

/// Poseidon sponge hash in R1CS: absorbs FpVar elements, returns single FpVar digest.
fn poseidon_hash_var(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state: [FpVar<Fr>; WIDTH] = [
        FpVar::constant(Fr::from(inputs.len() as u64)), // domain separation
        FpVar::zero(),
        FpVar::zero(),
    ];

    let mut rate_idx = 0;
    for element in inputs {
        state[CAPACITY + rate_idx] = &state[CAPACITY + rate_idx] + element;
        rate_idx += 1;
        if rate_idx == RATE {
            poseidon_permutation_var(&mut state)?;
            rate_idx = 0;
        }
    }

    poseidon_permutation_var(&mut state)?;
    Ok(state[CAPACITY].clone())
}

// ---------------------------------------------------------------------------
// ZK-ACE Circuit
// ---------------------------------------------------------------------------

/// ZK-ACE Groth16 R1CS circuit.
///
/// Private witnesses: rev, salt, alg_id, domain_ctx, index, nonce
/// Public inputs: id_com, tx_hash, domain, target, rp_com
///
/// The replay mode is baked in at construction time.
#[derive(Clone)]
pub struct ZkAceCircuit {
    // Private witnesses
    pub rev: Option<Fr>,
    pub salt: Option<Fr>,
    pub alg_id: Option<Fr>,
    pub domain_ctx: Option<Fr>,
    pub index: Option<Fr>,
    pub nonce: Option<Fr>,
    // Public inputs
    pub id_com: Option<Fr>,
    pub tx_hash: Option<Fr>,
    pub domain: Option<Fr>,
    pub target: Option<Fr>,
    pub rp_com: Option<Fr>,
    // Replay mode (determines circuit structure)
    pub mode: ReplayMode,
}

impl ZkAceCircuit {
    /// Create a circuit with dummy values for setup (constraint structure only).
    pub fn for_setup(mode: ReplayMode) -> Self {
        ZkAceCircuit {
            rev: Some(Fr::zero()),
            salt: Some(Fr::zero()),
            alg_id: Some(Fr::zero()),
            domain_ctx: Some(Fr::zero()),
            index: Some(Fr::zero()),
            nonce: Some(Fr::zero()),
            id_com: Some(Fr::zero()),
            tx_hash: Some(Fr::zero()),
            domain: Some(Fr::zero()),
            target: Some(Fr::zero()),
            rp_com: Some(Fr::zero()),
            mode,
        }
    }
}

impl ConstraintSynthesizer<Fr> for ZkAceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- Allocate private witnesses ---
        let rev_var = FpVar::new_witness(cs.clone(), || {
            self.rev.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let salt_var = FpVar::new_witness(cs.clone(), || {
            self.salt.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let alg_id_var = FpVar::new_witness(cs.clone(), || {
            self.alg_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let domain_ctx_var = FpVar::new_witness(cs.clone(), || {
            self.domain_ctx.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let index_var = FpVar::new_witness(cs.clone(), || {
            self.index.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nonce_var = FpVar::new_witness(cs.clone(), || {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // --- Allocate public inputs ---
        let id_com_var = FpVar::new_input(cs.clone(), || {
            self.id_com.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let tx_hash_var = FpVar::new_input(cs.clone(), || {
            self.tx_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let domain_var = FpVar::new_input(cs.clone(), || {
            self.domain.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let target_var = FpVar::new_input(cs.clone(), || {
            self.target.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let rp_com_var = FpVar::new_input(cs.clone(), || {
            self.rp_com.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // --- C1: id_com == Poseidon(rev, salt, domain) ---
        let computed_id_com =
            poseidon_hash_var(&[rev_var.clone(), salt_var.clone(), domain_var.clone()])?;
        computed_id_com.enforce_equal(&id_com_var)?;

        // --- C2: target == Poseidon(Derive(rev, ctx)) ---
        // Derive = Poseidon(rev, alg_id, domain_ctx, index)
        let derived = poseidon_hash_var(&[
            rev_var.clone(),
            alg_id_var.clone(),
            domain_ctx_var.clone(),
            index_var.clone(),
        ])?;
        let computed_target = poseidon_hash_var(&[derived])?;
        computed_target.enforce_equal(&target_var)?;

        // --- C3: auth = Poseidon(rev, alg_id, domain_ctx, index, tx_hash, domain, nonce) ---
        let auth = poseidon_hash_var(&[
            rev_var,
            alg_id_var,
            domain_ctx_var,
            index_var,
            tx_hash_var.clone(),
            domain_var.clone(),
            nonce_var.clone(),
        ])?;

        // --- C4: rp_com based on replay mode ---
        let computed_rp_com = match self.mode {
            ReplayMode::NonceRegistry => {
                // C4A: rp_com = Poseidon(id_com, nonce)
                poseidon_hash_var(&[computed_id_com, nonce_var])?
            }
            ReplayMode::NullifierSet => {
                // C4B: rp_com = Poseidon(auth, domain)
                poseidon_hash_var(&[auth, domain_var])?
            }
        };
        computed_rp_com.enforce_equal(&rp_com_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::commitment::compute_public_inputs;
    use crate::groth16::types::DerivationContext;
    use ark_relations::r1cs::ConstraintSystem;

    fn test_circuit(mode: ReplayMode) -> ZkAceCircuit {
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

        ZkAceCircuit {
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
        }
    }

    #[test]
    fn circuit_satisfies_nonce_registry() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = test_circuit(ReplayMode::NonceRegistry);
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit not satisfied (NonceRegistry)"
        );
    }

    #[test]
    fn circuit_satisfies_nullifier_set() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = test_circuit(ReplayMode::NullifierSet);
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit not satisfied (NullifierSet)"
        );
    }

    #[test]
    fn circuit_rejects_wrong_id_com() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut circuit = test_circuit(ReplayMode::NonceRegistry);
        circuit.id_com = Some(Fr::from(9999u64)); // wrong value
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "should reject wrong id_com");
    }

    #[test]
    fn circuit_rejects_wrong_target() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut circuit = test_circuit(ReplayMode::NonceRegistry);
        circuit.target = Some(Fr::from(9999u64));
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "should reject wrong target");
    }

    #[test]
    fn circuit_rejects_wrong_rp_com() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut circuit = test_circuit(ReplayMode::NonceRegistry);
        circuit.rp_com = Some(Fr::from(9999u64));
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "should reject wrong rp_com");
    }

    #[test]
    fn constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = test_circuit(ReplayMode::NonceRegistry);
        circuit.generate_constraints(cs.clone()).unwrap();
        let num = cs.num_constraints();
        // Expect ~1200 constraints (5 Poseidon calls * ~240 each + equality checks)
        assert!(num > 500, "too few constraints: {num}");
        assert!(num < 5000, "too many constraints: {num}");
    }
}
