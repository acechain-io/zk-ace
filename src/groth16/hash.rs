//! Poseidon hash over BN254 Fr field.
//!
//! Parameters:
//! - Width: 3 (capacity=1, rate=2)
//! - S-box: x^5
//! - Full rounds: 8 (4 begin + 4 end)
//! - Partial rounds: 56
//! - MDS: circulant(2, 1, 1)
//! - Round constants: deterministic from SHA-256

use ark_bn254::Fr;
use ark_ff::{Field, One, PrimeField, Zero};
use std::sync::OnceLock;

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const CAPACITY: usize = 1;
pub const FULL_ROUNDS_BEGIN: usize = 4;
pub const PARTIAL_ROUNDS: usize = 56;
pub const FULL_ROUNDS_END: usize = 4;
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END;

/// MDS matrix coefficients: circulant(2, 1, 1).
pub fn mds_matrix() -> [[Fr; WIDTH]; WIDTH] {
    let two = Fr::from(2u64);
    let one = Fr::one();
    [[two, one, one], [one, two, one], [one, one, two]]
}

/// Generate round constants deterministically from SHA-256.
pub fn round_constants() -> &'static Vec<[Fr; WIDTH]> {
    static RC: OnceLock<Vec<[Fr; WIDTH]>> = OnceLock::new();
    RC.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut rc = Vec::with_capacity(TOTAL_ROUNDS);
        for round in 0..TOTAL_ROUNDS {
            let mut row = [Fr::zero(); WIDTH];
            for index in 0..WIDTH {
                let mut hasher = Sha256::new();
                hasher.update(format!("ACE-ZK-POSEIDON-BN254-RC-{round}-{index}").as_bytes());
                let hash = hasher.finalize();
                // Use first 31 bytes to ensure value is well within field range
                let mut bytes = [0u8; 32];
                bytes[..31].copy_from_slice(&hash[..31]);
                row[index] = Fr::from_le_bytes_mod_order(&bytes);
            }
            rc.push(row);
        }
        rc
    })
}

/// S-box: x^5 in BN254 Fr.
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Apply MDS (circulant matrix multiplication).
fn apply_mds(state: &mut [Fr; WIDTH]) {
    let mds = mds_matrix();
    let old = *state;
    for i in 0..WIDTH {
        state[i] = Fr::zero();
        for j in 0..WIDTH {
            state[i] += mds[i][j] * old[j];
        }
    }
}

/// Full round: S-box on all elements, MDS, add round constants.
fn full_round(state: &mut [Fr; WIDTH], rc: &[Fr; WIDTH]) {
    for i in 0..WIDTH {
        state[i] = sbox(state[i]);
    }
    apply_mds(state);
    for i in 0..WIDTH {
        state[i] += rc[i];
    }
}

/// Partial round: S-box on first element only, MDS, add round constants.
fn partial_round(state: &mut [Fr; WIDTH], rc: &[Fr; WIDTH]) {
    state[0] = sbox(state[0]);
    apply_mds(state);
    for i in 0..WIDTH {
        state[i] += rc[i];
    }
}

/// Apply the full Poseidon permutation.
fn poseidon_permutation(state: &mut [Fr; WIDTH]) {
    let rc = round_constants();
    let mut round = 0;
    for _ in 0..FULL_ROUNDS_BEGIN {
        full_round(state, &rc[round]);
        round += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        partial_round(state, &rc[round]);
        round += 1;
    }
    for _ in 0..FULL_ROUNDS_END {
        full_round(state, &rc[round]);
        round += 1;
    }
}

/// Poseidon sponge hash: absorbs Fr elements, returns single Fr digest.
///
/// Sponge construction:
/// - State: [capacity (1) | rate (2)]
/// - capacity[0] = input length (domain separation)
/// - Absorb rate-sized blocks, applying permutation after each
/// - Squeeze first rate element as digest
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); WIDTH];
    // Domain separation: encode input length in capacity
    state[0] = Fr::from(inputs.len() as u64);

    let mut rate_idx = 0;
    for &element in inputs {
        state[CAPACITY + rate_idx] += element;
        rate_idx += 1;
        if rate_idx == RATE {
            poseidon_permutation(&mut state);
            rate_idx = 0;
        }
    }

    // Final permutation (always applied for domain separation mixing)
    poseidon_permutation(&mut state);

    // Squeeze: return first element from rate portion
    state[CAPACITY]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = Fr::from(42u64);
        let b = Fr::from(123u64);
        let h1 = poseidon_hash(&[a, b]);
        let h2 = poseidon_hash(&[a, b]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_outputs() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h1 = poseidon_hash(&[a, b]);
        let h2 = poseidon_hash(&[b, a]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn single_element_hash() {
        let h = poseidon_hash(&[Fr::from(99u64)]);
        assert_ne!(h, Fr::zero());
    }

    #[test]
    fn empty_input_hash() {
        let h = poseidon_hash(&[]);
        assert_ne!(h, Fr::zero());
    }

    #[test]
    fn large_input_hash() {
        let inputs: Vec<Fr> = (1..=20).map(Fr::from).collect();
        let h = poseidon_hash(&inputs);
        assert_ne!(h, Fr::zero());
    }

    #[test]
    fn domain_separation() {
        // Same value but different input lengths should produce different hashes
        let h1 = poseidon_hash(&[Fr::from(1u64)]);
        let h2 = poseidon_hash(&[Fr::from(1u64), Fr::zero()]);
        assert_ne!(h1, h2);
    }
}
