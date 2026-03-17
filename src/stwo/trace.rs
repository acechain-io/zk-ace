//! Trace builder for ZK-ACE Stwo proofs.
//!
//! Builds the execution trace for the full Poseidon2 constraint circuit.
//! The trace contains 13 Poseidon2 permutations computed step-by-step,
//! along with S-box intermediates and constant witness columns.

use stwo::core::fields::m31::M31;

use crate::stwo::air::schedule::*;
use crate::stwo::native::commitment::{
    compute_auth, compute_id_com, compute_rp_com_nonce, compute_rp_com_nullifier, compute_target,
};
use crate::stwo::types::{
    ReplayMode, ZkAcePublicInputs, ZkAceWitness, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN,
};

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

/// Apply the MDS circulant matrix to a state.
fn apply_mds(state: &[M31; STATE_WIDTH]) -> [M31; STATE_WIDTH] {
    let circ = mds_circ_m31();
    let mut result = [M31(0); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let mut acc = M31(0);
        for j in 0..STATE_WIDTH {
            let idx = (STATE_WIDTH + i - j) % STATE_WIDTH;
            acc = m31_add(acc, m31_mul(state[j], circ[idx]));
        }
        result[i] = acc;
    }
    result
}

/// Compute one Poseidon2 round (full or partial), returning (next_state, x2, x4, x5).
///
/// For a full round: S-box on all elements, then MDS, then add RC.
/// For a partial round: S-box on element 0 only, then MDS, then add RC.
fn compute_round(
    state: &[M31; STATE_WIDTH],
    round: usize,
    rc: &[M31; STATE_WIDTH],
) -> (
    [M31; STATE_WIDTH],
    [M31; STATE_WIDTH],
    [M31; STATE_WIDTH],
    [M31; STATE_WIDTH],
) {
    let is_full = is_full_round_idx(round);

    let mut x2 = [M31(0); STATE_WIDTH];
    let mut x4 = [M31(0); STATE_WIDTH];
    let mut x5 = [M31(0); STATE_WIDTH];

    // Compute S-box outputs
    for k in 0..STATE_WIDTH {
        x2[k] = m31_mul(state[k], state[k]);
        x4[k] = m31_mul(x2[k], x2[k]);
        x5[k] = m31_mul(x4[k], state[k]);
    }

    // Build MDS input: x5 for S-boxed elements, state for non-S-boxed
    let mut mds_input = [M31(0); STATE_WIDTH];
    if is_full {
        mds_input = x5;
    } else {
        mds_input[0] = x5[0];
        for k in 1..STATE_WIDTH {
            mds_input[k] = state[k];
        }
    }

    let mds_out = apply_mds(&mds_input);

    let mut next_state = [M31(0); STATE_WIDTH];
    for k in 0..STATE_WIDTH {
        next_state[k] = m31_add(mds_out[k], rc[k]);
    }

    (next_state, x2, x4, x5)
}

/// Build the execution trace columns for a ZK-ACE proof.
///
/// Returns a vector of 100 columns, each `Vec<M31>` of length `TRACE_LEN` (512).
///
/// Column layout:
///   [0..16]   : state[0..16]
///   [16..32]  : x2[0..16]
///   [32..48]  : x4[0..16]
///   [48..64]  : x5[0..16]
///   [64..73]  : w_rev[0..9]
///   [73..82]  : w_salt[0..9]
///   [82..85]  : w_nonce[0..3]
///   [85..88]  : w_ctx[0..3]
///   [88..97]  : w_tx_hash[0..9]
///   [97..100] : w_domain[0..3]
pub fn build_trace(
    witness: &ZkAceWitness,
    public_inputs: &ZkAcePublicInputs,
    replay_mode: ReplayMode,
) -> Vec<Vec<M31>> {
    // Verify computed values match public inputs (sanity check)
    let domain = &public_inputs.domain;
    let id_com = compute_id_com(&witness.rev, &witness.salt, domain);
    let target = compute_target(&witness.rev, &witness.ctx);
    let auth = compute_auth(
        &witness.rev,
        &witness.ctx,
        &public_inputs.tx_hash,
        domain,
        &witness.nonce,
    );
    let rp_com = match replay_mode {
        ReplayMode::NonceRegistry => compute_rp_com_nonce(&id_com, &witness.nonce),
        ReplayMode::NullifierSet => compute_rp_com_nullifier(&auth, domain),
    };
    assert_eq!(id_com, public_inputs.id_com, "id_com mismatch");
    assert_eq!(target, public_inputs.target, "target mismatch");
    assert_eq!(rp_com, public_inputs.rp_com, "rp_com mismatch");

    let rc_all = round_constants();

    // Collect all Poseidon2 sponge input sequences for the 5 hashes.
    // We'll step through the sponge manually to fill the trace.

    // Build initial states and absorption data for each permutation.
    // We store the state at each row in the active region.
    let mut row_state: Vec<[M31; STATE_WIDTH]> = vec![[M31(0); STATE_WIDTH]; TRACE_LEN];
    let mut row_x2: Vec<[M31; STATE_WIDTH]> = vec![[M31(0); STATE_WIDTH]; TRACE_LEN];
    let mut row_x4: Vec<[M31; STATE_WIDTH]> = vec![[M31(0); STATE_WIDTH]; TRACE_LEN];
    let mut row_x5: Vec<[M31; STATE_WIDTH]> = vec![[M31(0); STATE_WIDTH]; TRACE_LEN];

    // Step through each permutation
    let derive_output;
    let auth_output;

    // =========================================================================
    // Hash 1: id_com = Poseidon2(rev || salt || domain)
    // Input length = 9 + 9 + 3 = 21
    // Perms 0, 1, 2
    // =========================================================================
    {
        // Perm 0: fresh init, domain_sep=21, absorb rev[0..8]
        let mut state = [M31(0); STATE_WIDTH];
        state[0] = M31(21); // domain separation
        for k in 0..RATE {
            state[CAPACITY + k] = witness.rev[k];
        }
        let perm0_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            0,
            state,
            &rc_all,
        );

        // Perm 1: continue, absorb [rev[8], salt[0..7]]
        let mut state = perm0_output;
        state[8] = m31_add(state[8], witness.rev[8]);
        for i in 0..7 {
            state[9 + i] = m31_add(state[9 + i], witness.salt[i]);
        }
        let perm1_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            1,
            state,
            &rc_all,
        );

        // Perm 2: continue, absorb [salt[7], salt[8], domain[0], domain[1], domain[2]]
        let mut state = perm1_output;
        state[8] = m31_add(state[8], witness.salt[7]);
        state[9] = m31_add(state[9], witness.salt[8]);
        state[10] = m31_add(state[10], domain[0]);
        state[11] = m31_add(state[11], domain[1]);
        state[12] = m31_add(state[12], domain[2]);
        let _perm2_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            2,
            state,
            &rc_all,
        );
    }

    // =========================================================================
    // Hash 2: derive_out = Poseidon2(rev || ctx)
    // Input length = 9 + 3 = 12
    // Perms 3, 4
    // =========================================================================
    {
        // Perm 3: fresh init, domain_sep=12, absorb rev[0..8]
        let mut state = [M31(0); STATE_WIDTH];
        state[0] = M31(12);
        for k in 0..RATE {
            state[CAPACITY + k] = witness.rev[k];
        }
        let perm3_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            3,
            state,
            &rc_all,
        );

        // Perm 4: continue, absorb [rev[8], ctx.alg_id, ctx.domain, ctx.index]
        let mut state = perm3_output;
        state[8] = m31_add(state[8], witness.rev[8]);
        state[9] = m31_add(state[9], witness.ctx.alg_id);
        state[10] = m31_add(state[10], witness.ctx.domain);
        state[11] = m31_add(state[11], witness.ctx.index);
        let perm4_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            4,
            state,
            &rc_all,
        );

        derive_output = perm4_output;
    }

    // =========================================================================
    // Hash 3: target = Poseidon2(derive_output)
    // Input length = 8
    // Perms 5, 6
    // =========================================================================
    {
        // Perm 5: fresh init, domain_sep=8, rate = derive_output[8..16]
        let mut state = [M31(0); STATE_WIDTH];
        state[0] = M31(8);
        for k in 0..RATE {
            state[CAPACITY + k] = derive_output[CAPACITY + k];
        }
        let perm5_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            5,
            state,
            &rc_all,
        );

        // Perm 6: no-absorb continue (final permutation for padding)
        let state = perm5_output;
        let _perm6_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            6,
            state,
            &rc_all,
        );
    }

    // =========================================================================
    // Hash 4: auth = Poseidon2(rev || ctx || tx_hash || domain || nonce)
    // Input length = 9 + 3 + 9 + 3 + 3 = 28 (but domain is 1 alg_id, 1 domain, 1 index = 3 scalars)
    // Actually: rev(9) + alg_id(1) + domain(1) + index(1) + tx_hash(9) + domain(3) + nonce(3) = 28
    // Perms 7, 8, 9, 10
    // =========================================================================
    {
        // Perm 7: fresh init, domain_sep=28, absorb rev[0..8]
        let mut state = [M31(0); STATE_WIDTH];
        state[0] = M31(27);
        for k in 0..RATE {
            state[CAPACITY + k] = witness.rev[k];
        }
        let perm7_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            7,
            state,
            &rc_all,
        );

        // Perm 8: continue, absorb [rev[8], ctx.alg_id, ctx.domain, ctx.index, tx_hash[0..4]]
        let mut state = perm7_output;
        state[8] = m31_add(state[8], witness.rev[8]);
        state[9] = m31_add(state[9], witness.ctx.alg_id);
        state[10] = m31_add(state[10], witness.ctx.domain);
        state[11] = m31_add(state[11], witness.ctx.index);
        state[12] = m31_add(state[12], public_inputs.tx_hash[0]);
        state[13] = m31_add(state[13], public_inputs.tx_hash[1]);
        state[14] = m31_add(state[14], public_inputs.tx_hash[2]);
        state[15] = m31_add(state[15], public_inputs.tx_hash[3]);
        let perm8_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            8,
            state,
            &rc_all,
        );

        // Perm 9: continue, absorb [tx_hash[4..9], domain[0..3]]
        let mut state = perm8_output;
        state[8] = m31_add(state[8], public_inputs.tx_hash[4]);
        state[9] = m31_add(state[9], public_inputs.tx_hash[5]);
        state[10] = m31_add(state[10], public_inputs.tx_hash[6]);
        state[11] = m31_add(state[11], public_inputs.tx_hash[7]);
        state[12] = m31_add(state[12], public_inputs.tx_hash[8]);
        state[13] = m31_add(state[13], domain[0]);
        state[14] = m31_add(state[14], domain[1]);
        state[15] = m31_add(state[15], domain[2]);
        let perm9_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            9,
            state,
            &rc_all,
        );

        // Perm 10: continue, absorb [nonce[0], nonce[1], nonce[2]]
        let mut state = perm9_output;
        state[8] = m31_add(state[8], witness.nonce[0]);
        state[9] = m31_add(state[9], witness.nonce[1]);
        state[10] = m31_add(state[10], witness.nonce[2]);
        let perm10_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            10,
            state,
            &rc_all,
        );

        auth_output = perm10_output;
    }

    // =========================================================================
    // Hash 5: rp_com
    // NonceRegistry: Poseidon2(id_com || nonce), input_len = 8 + 3 = 11
    // NullifierSet: Poseidon2(auth || domain), input_len = 8 + 3 = 11
    // Perms 11, 12
    // =========================================================================
    {
        // Perm 11: fresh init, domain_sep=11
        let mut state = [M31(0); STATE_WIDTH];
        state[0] = M31(11);
        match replay_mode {
            ReplayMode::NonceRegistry => {
                for k in 0..RATE {
                    state[CAPACITY + k] = id_com[k];
                }
            }
            ReplayMode::NullifierSet => {
                // auth output rate portion
                for k in 0..RATE {
                    state[CAPACITY + k] = auth_output[CAPACITY + k];
                }
            }
        }
        let perm11_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            11,
            state,
            &rc_all,
        );

        // Perm 12: continue, absorb partial
        let mut state = perm11_output;
        match replay_mode {
            ReplayMode::NonceRegistry => {
                state[8] = m31_add(state[8], witness.nonce[0]);
                state[9] = m31_add(state[9], witness.nonce[1]);
                state[10] = m31_add(state[10], witness.nonce[2]);
            }
            ReplayMode::NullifierSet => {
                state[8] = m31_add(state[8], domain[0]);
                state[9] = m31_add(state[9], domain[1]);
                state[10] = m31_add(state[10], domain[2]);
            }
        }
        let _perm12_output = run_permutation(
            &mut row_state,
            &mut row_x2,
            &mut row_x4,
            &mut row_x5,
            12,
            state,
            &rc_all,
        );
    }

    // =========================================================================
    // Fill padding rows (403..512) — copy the state from row 402
    // =========================================================================
    let pad_state = row_state[402];
    for row in ACTIVE_ROWS..TRACE_LEN {
        row_state[row] = pad_state;
        // x2, x4, x5 for padding: compute from pad_state for S-box constraint satisfaction
        for k in 0..STATE_WIDTH {
            row_x2[row][k] = m31_mul(pad_state[k], pad_state[k]);
            row_x4[row][k] = m31_mul(row_x2[row][k], row_x2[row][k]);
            row_x5[row][k] = m31_mul(row_x4[row][k], pad_state[k]);
        }
    }

    // =========================================================================
    // Build column vectors
    // =========================================================================
    let mut columns: Vec<Vec<M31>> = Vec::with_capacity(NUM_MAIN_COLUMNS);

    // State columns (16)
    for k in 0..STATE_WIDTH {
        columns.push((0..TRACE_LEN).map(|row| row_state[row][k]).collect());
    }
    // x2 columns (16)
    for k in 0..STATE_WIDTH {
        columns.push((0..TRACE_LEN).map(|row| row_x2[row][k]).collect());
    }
    // x4 columns (16)
    for k in 0..STATE_WIDTH {
        columns.push((0..TRACE_LEN).map(|row| row_x4[row][k]).collect());
    }
    // x5 columns (16)
    for k in 0..STATE_WIDTH {
        columns.push((0..TRACE_LEN).map(|row| row_x5[row][k]).collect());
    }

    // Witness columns (constant across all rows)
    // w_rev[0..9]
    for k in 0..ELEMENTS_PER_BYTES32 {
        columns.push(vec![witness.rev[k]; TRACE_LEN]);
    }
    // w_salt[0..9]
    for k in 0..ELEMENTS_PER_BYTES32 {
        columns.push(vec![witness.salt[k]; TRACE_LEN]);
    }
    // w_nonce[0..3]
    for k in 0..ELEMENTS_PER_DOMAIN {
        columns.push(vec![witness.nonce[k]; TRACE_LEN]);
    }
    // w_ctx[0..3]
    columns.push(vec![witness.ctx.alg_id; TRACE_LEN]);
    columns.push(vec![witness.ctx.domain; TRACE_LEN]);
    columns.push(vec![witness.ctx.index; TRACE_LEN]);
    // w_tx_hash[0..9]
    for k in 0..ELEMENTS_PER_BYTES32 {
        columns.push(vec![public_inputs.tx_hash[k]; TRACE_LEN]);
    }
    // w_domain[0..3]
    for k in 0..ELEMENTS_PER_DOMAIN {
        columns.push(vec![public_inputs.domain[k]; TRACE_LEN]);
    }

    assert_eq!(columns.len(), NUM_MAIN_COLUMNS);
    columns
}

/// Run a single Poseidon2 permutation for `perm_idx`, filling the trace arrays.
/// Returns the final state after all 30 rounds.
fn run_permutation(
    row_state: &mut [[M31; STATE_WIDTH]],
    row_x2: &mut [[M31; STATE_WIDTH]],
    row_x4: &mut [[M31; STATE_WIDTH]],
    row_x5: &mut [[M31; STATE_WIDTH]],
    perm_idx: usize,
    init_state: [M31; STATE_WIDTH],
    rc: &[[M31; STATE_WIDTH]; TOTAL_ROUNDS],
) -> [M31; STATE_WIDTH] {
    let base = perm_start_row(perm_idx);

    // Row base+0: initial state
    row_state[base] = init_state;

    let mut state = init_state;
    for round in 0..TOTAL_ROUNDS {
        let row = base + round;
        // Compute S-box intermediates for the current state
        let (next_state, x2, x4, x5) = compute_round(&state, round, &rc[round]);

        row_x2[row] = x2;
        row_x4[row] = x4;
        row_x5[row] = x5;

        // Next row gets the next state
        row_state[row + 1] = next_state;
        state = next_state;
    }

    // The output row (base + TOTAL_ROUNDS) needs S-box intermediates too
    // for the S-box decomposition constraint. These won't be used by any
    // transition constraint, but the S-box constraints apply everywhere.
    let output_row = base + TOTAL_ROUNDS;
    for k in 0..STATE_WIDTH {
        row_x2[output_row][k] = m31_mul(state[k], state[k]);
        row_x4[output_row][k] = m31_mul(row_x2[output_row][k], row_x2[output_row][k]);
        row_x5[output_row][k] = m31_mul(row_x4[output_row][k], state[k]);
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo::native::commitment::compute_public_inputs;
    use crate::stwo::types::{DerivationContext, ELEMENTS_PER_HASH};

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
    fn trace_has_correct_dimensions() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let columns = build_trace(&w, &pi, ReplayMode::NonceRegistry);
        assert_eq!(columns.len(), NUM_MAIN_COLUMNS);
        for col in &columns {
            assert_eq!(col.len(), TRACE_LEN);
        }
    }

    #[test]
    fn trace_output_matches_public_inputs() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let columns = build_trace(&w, &pi, ReplayMode::NonceRegistry);

        // id_com output at row 92, state columns 8..16
        for k in 0..ELEMENTS_PER_HASH {
            assert_eq!(
                columns[CAPACITY + k][92],
                pi.id_com[k],
                "id_com mismatch at element {k}"
            );
        }
        // target output at row 216, state columns 8..16
        for k in 0..ELEMENTS_PER_HASH {
            assert_eq!(
                columns[CAPACITY + k][216],
                pi.target[k],
                "target mismatch at element {k}"
            );
        }
        // rp_com output at row 402, state columns 8..16
        for k in 0..ELEMENTS_PER_HASH {
            assert_eq!(
                columns[CAPACITY + k][402],
                pi.rp_com[k],
                "rp_com mismatch at element {k}"
            );
        }
    }

    #[test]
    fn trace_matches_native_hash() {
        // Verify that the step-by-step trace produces the same results as the native hash
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();

        // Compute with native hash
        let id_com = compute_id_com(&w.rev, &w.salt, &domain);
        let target = compute_target(&w.rev, &w.ctx);

        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        assert_eq!(pi.id_com, id_com);
        assert_eq!(pi.target, target);

        // Build trace and check outputs
        let columns = build_trace(&w, &pi, ReplayMode::NonceRegistry);
        for k in 0..ELEMENTS_PER_HASH {
            assert_eq!(columns[CAPACITY + k][92], id_com[k]);
            assert_eq!(columns[CAPACITY + k][216], target[k]);
        }
    }

    #[test]
    fn trace_nullifier_mode() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NullifierSet);
        let columns = build_trace(&w, &pi, ReplayMode::NullifierSet);

        // rp_com output at row 402
        for k in 0..ELEMENTS_PER_HASH {
            assert_eq!(
                columns[CAPACITY + k][402],
                pi.rp_com[k],
                "rp_com nullifier mismatch at element {k}"
            );
        }
    }
}
