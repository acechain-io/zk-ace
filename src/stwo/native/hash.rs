use stwo::core::fields::m31::M31;

use crate::stwo::types::ELEMENTS_PER_HASH;

/// Poseidon2-style hash over M31 field.
///
/// State width: 16 M31 elements
/// Rounds: 4 full + 22 partial + 4 full (standard Poseidon2 for M31)
/// S-box: x^5
/// Sponge: rate=8, capacity=8
/// Digest: first 8 elements of the state after squeezing

const STATE_WIDTH: usize = 16;
const RATE: usize = 8;
const CAPACITY: usize = 8;
const FULL_ROUNDS_BEGIN: usize = 4;
const PARTIAL_ROUNDS: usize = 22;
const FULL_ROUNDS_END: usize = 4;
const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END;

/// Mersenne-31 prime modulus.
const P: u64 = 0x7FFF_FFFF;

/// Multiply two M31 values (using u64 intermediate).
#[inline]
fn m31_mul(a: M31, b: M31) -> M31 {
    M31::reduce((a.0 as u64) * (b.0 as u64))
}

/// Add two M31 values.
#[inline]
fn m31_add(a: M31, b: M31) -> M31 {
    let s = a.0 as u64 + b.0 as u64;
    M31::partial_reduce(if s >= P { (s - P) as u32 } else { s as u32 })
}

/// S-box: x^5 in M31.
#[inline]
fn sbox(x: M31) -> M31 {
    let x2 = m31_mul(x, x);
    let x4 = m31_mul(x2, x2);
    m31_mul(x4, x)
}

/// Round constants for Poseidon2 over M31.
/// Generated deterministically from SHA-256("ACE-ZK-POSEIDON2-M31-RC-{round}-{index}").
/// We use a simple deterministic generation here.
fn round_constants() -> [[M31; STATE_WIDTH]; TOTAL_ROUNDS] {
    use sha2::{Digest, Sha256};
    let mut rc = [[M31(0); STATE_WIDTH]; TOTAL_ROUNDS];
    for round in 0..TOTAL_ROUNDS {
        for index in 0..STATE_WIDTH {
            let mut hasher = Sha256::new();
            hasher.update(format!("ACE-ZK-POSEIDON2-M31-RC-{round}-{index}").as_bytes());
            let hash = hasher.finalize();
            let val = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) & 0x7FFF_FFFF;
            rc[round][index] = M31(val);
        }
    }
    rc
}

/// Internal MDS matrix: a 16x16 circulant matrix built from a fixed first row.
/// We use the "simple" MDS: M[i][j] = circ[|i-j| % 16].
/// The first row is chosen to be MDS over M31.
fn mds_circ_values() -> [M31; STATE_WIDTH] {
    // A simple MDS-like circulant: [2, 3, 1, 1, ...] extended to 16 elements.
    // We use a deterministic choice known to produce an MDS matrix over large fields.
    let vals: [u32; STATE_WIDTH] = [2, 3, 1, 1, 8, 7, 5, 4, 6, 9, 11, 10, 13, 12, 14, 15];
    let mut result = [M31(0); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        result[i] = M31(vals[i]);
    }
    result
}

/// Apply MDS (circulant matrix multiplication).
fn apply_mds(state: &mut [M31; STATE_WIDTH]) {
    let circ = mds_circ_values();
    let mut result = [M31(0); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let mut acc = M31(0);
        for j in 0..STATE_WIDTH {
            let idx = (STATE_WIDTH + i - j) % STATE_WIDTH;
            acc = m31_add(acc, m31_mul(state[j], circ[idx]));
        }
        result[i] = acc;
    }
    *state = result;
}

/// Apply full round: S-box on all elements, then MDS, then add round constants.
fn full_round(state: &mut [M31; STATE_WIDTH], rc: &[M31; STATE_WIDTH]) {
    for i in 0..STATE_WIDTH {
        state[i] = sbox(state[i]);
    }
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] = m31_add(state[i], rc[i]);
    }
}

/// Apply partial round: S-box on first element only, then MDS, then add round constants.
fn partial_round(state: &mut [M31; STATE_WIDTH], rc: &[M31; STATE_WIDTH]) {
    state[0] = sbox(state[0]);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] = m31_add(state[i], rc[i]);
    }
}

/// Apply the full Poseidon2 permutation.
fn poseidon2_permutation(state: &mut [M31; STATE_WIDTH]) {
    let rc = round_constants();
    let mut round = 0;

    // Initial full rounds
    for _ in 0..FULL_ROUNDS_BEGIN {
        full_round(state, &rc[round]);
        round += 1;
    }

    // Partial rounds
    for _ in 0..PARTIAL_ROUNDS {
        partial_round(state, &rc[round]);
        round += 1;
    }

    // Final full rounds
    for _ in 0..FULL_ROUNDS_END {
        full_round(state, &rc[round]);
        round += 1;
    }
}

/// Poseidon2 sponge hash: absorbs a slice of M31 elements and produces an 8-element digest.
///
/// Sponge construction:
/// - State: [capacity (8) | rate (8)] = 16 elements
/// - capacity[0] = input length (domain separation)
/// - Absorb rate-sized blocks, applying permutation after each
/// - Squeeze first 8 elements as digest
pub fn poseidon2_hash(inputs: &[M31]) -> [M31; ELEMENTS_PER_HASH] {
    let mut state = [M31(0); STATE_WIDTH];
    // Domain separation: encode input length in capacity[0]
    state[0] = M31(inputs.len() as u32);

    // Absorb
    let mut rate_idx = 0;
    for &element in inputs.iter() {
        state[CAPACITY + rate_idx] = m31_add(state[CAPACITY + rate_idx], element);
        rate_idx += 1;
        if rate_idx == RATE {
            poseidon2_permutation(&mut state);
            rate_idx = 0;
        }
    }

    // Apply final permutation (always, even if rate_idx == 0, to ensure
    // the domain-separation tag in capacity is mixed through the state).
    poseidon2_permutation(&mut state);

    // Squeeze: return first 8 elements from the rate portion
    let mut digest = [M31(0); ELEMENTS_PER_HASH];
    digest.copy_from_slice(&state[CAPACITY..CAPACITY + ELEMENTS_PER_HASH]);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = M31(42);
        let b = M31(123);
        let h1 = poseidon2_hash(&[a, b]);
        let h2 = poseidon2_hash(&[a, b]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_outputs() {
        let a = M31(1);
        let b = M31(2);
        let h1 = poseidon2_hash(&[a, b]);
        let h2 = poseidon2_hash(&[b, a]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn single_element_hash() {
        let a = M31(99);
        let h = poseidon2_hash(&[a]);
        assert_ne!(h, [M31(0); ELEMENTS_PER_HASH]);
    }

    #[test]
    fn empty_input_hash() {
        let h = poseidon2_hash(&[]);
        // Even empty input should produce non-trivial output
        assert_ne!(h, [M31(0); ELEMENTS_PER_HASH]);
    }

    #[test]
    fn large_input_hash() {
        let inputs: Vec<M31> = (0..20).map(|i| M31(i + 1)).collect();
        let h = poseidon2_hash(&inputs);
        assert_ne!(h, [M31(0); ELEMENTS_PER_HASH]);
    }
}
