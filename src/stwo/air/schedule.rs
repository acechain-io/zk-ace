//! Computation schedule for the ZK-ACE Poseidon2 constraint circuit.
//!
//! Defines constants, row classification, and round-constant generation
//! for the 13-permutation trace layout.

use stwo::core::fields::m31::M31;

pub const LOG_TRACE_SIZE: u32 = 9;
pub const TRACE_LEN: usize = 1 << LOG_TRACE_SIZE; // 512
pub const STATE_WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const CAPACITY: usize = 8;
pub const FULL_ROUNDS_BEGIN: usize = 4;
pub const PARTIAL_ROUNDS: usize = 22;
pub const FULL_ROUNDS_END: usize = 4;
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END; // 30
pub const ROWS_PER_PERM: usize = TOTAL_ROUNDS + 1; // 31
pub const NUM_PERMS: usize = 13;
pub const ACTIVE_ROWS: usize = NUM_PERMS * ROWS_PER_PERM; // 403

/// MDS circulant first row.
pub const MDS_CIRC: [u32; STATE_WIDTH] = [2, 3, 1, 1, 8, 7, 5, 4, 6, 9, 11, 10, 13, 12, 14, 15];

/// Number of main trace columns: 16 state + 16 x2 + 16 x4 + 16 x5 + 36 witness = 100.
pub const NUM_MAIN_COLUMNS: usize = 64 + NUM_WITNESS_COLUMNS;

/// Number of witness/PI trace columns.
pub const NUM_WITNESS_COLUMNS: usize = 9 + 9 + 3 + 3 + 9 + 3; // 36

/// Number of preprocessed columns.
pub const NUM_PREPROCESSED_COLUMNS: usize = 16 + 3 + 13 + 3 + 1; // 36

/// Start row of permutation `perm` (0-indexed).
pub fn perm_start_row(perm: usize) -> usize {
    perm * ROWS_PER_PERM
}

/// End row (final output) of permutation `perm`.
pub fn perm_end_row(perm: usize) -> usize {
    perm_start_row(perm) + TOTAL_ROUNDS
}

/// Whether a given round index (0..29) within a permutation is a full round.
pub fn is_full_round_idx(round: usize) -> bool {
    round < FULL_ROUNDS_BEGIN || round >= FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS
}

/// Row classification for constraint selection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RowKind {
    /// Full-round transition row (S-box on all 16 elements).
    FullRound { round: usize },
    /// Partial-round transition row (S-box on element 0 only).
    PartialRound { round: usize },
    /// Permutation output row (last row of a perm, before next perm boundary).
    PermOutput { perm: usize },
    /// Padding row (inactive).
    Padding,
}

/// Classify a row by its function in the trace.
pub fn row_kind(row: usize) -> RowKind {
    if row >= ACTIVE_ROWS {
        return RowKind::Padding;
    }
    let perm = row / ROWS_PER_PERM;
    let offset = row % ROWS_PER_PERM;
    if offset == TOTAL_ROUNDS {
        // This is the final output row of the permutation
        RowKind::PermOutput { perm }
    } else {
        // offset 0..29 are round transition rows
        // offset k applies round k
        let round = offset;
        if is_full_round_idx(round) {
            RowKind::FullRound { round }
        } else {
            RowKind::PartialRound { round }
        }
    }
}

/// Generate Poseidon2 round constants (same algorithm as native/hash.rs).
pub fn round_constants() -> [[M31; STATE_WIDTH]; TOTAL_ROUNDS] {
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

/// Precomputed MDS circulant as M31 values.
pub fn mds_circ_m31() -> [M31; STATE_WIDTH] {
    let mut result = [M31(0); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        result[i] = M31(MDS_CIRC[i]);
    }
    result
}

/// Reorder a column from coset (step) order to circle-domain natural order.
///
/// The Stwo `CircleEvaluation::new(domain, data)` expects data in circle-domain
/// order, but `build_trace` and `generate_preprocessed_trace` produce data in
/// coset order (step 0, step 1, ...).  The coset-to-circle-domain mapping is:
///
///   circle_domain[i]       = coset[2*i]          for i < n/2
///   circle_domain[n-1-i]   = coset[2*i + 1]      for i < n/2
///
/// Equivalently, for each circle-domain index `cd`:
///   coset_idx = circle_domain_index_to_coset_index(cd, log_size)
///   circle_data[cd] = coset_data[coset_idx]
pub fn coset_order_to_circle_domain_order(coset_data: &[M31]) -> Vec<M31> {
    let n = coset_data.len();
    let half = n / 2;
    let mut out = vec![M31(0); n];
    for i in 0..half {
        out[i] = coset_data[2 * i];
    }
    for i in 0..half {
        out[n - 1 - i] = coset_data[2 * i + 1];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_rows_fit_in_trace() {
        assert!(ACTIVE_ROWS <= TRACE_LEN);
    }

    #[test]
    fn perm_layout() {
        assert_eq!(perm_start_row(0), 0);
        assert_eq!(perm_end_row(0), 30);
        assert_eq!(perm_start_row(1), 31);
        assert_eq!(perm_end_row(12), 402);
    }

    #[test]
    fn round_constants_are_deterministic() {
        let rc1 = round_constants();
        let rc2 = round_constants();
        assert_eq!(rc1, rc2);
    }

    #[test]
    fn row_classification() {
        // First row of perm 0: round 0 (full)
        assert!(matches!(row_kind(0), RowKind::FullRound { round: 0 }));
        // Row 4 of perm 0: round 4 (partial)
        assert!(matches!(row_kind(4), RowKind::PartialRound { round: 4 }));
        // Row 30 of perm 0: output
        assert!(matches!(row_kind(30), RowKind::PermOutput { perm: 0 }));
        // Row 31: perm 1, round 0 (full)
        assert!(matches!(row_kind(31), RowKind::FullRound { round: 0 }));
        // Padding
        assert!(matches!(row_kind(403), RowKind::Padding));
        assert!(matches!(row_kind(511), RowKind::Padding));
    }
}
