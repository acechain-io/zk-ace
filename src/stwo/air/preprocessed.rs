//! Preprocessed trace generation for the ZK-ACE Poseidon2 circuit.
//!
//! Generates the preprocessed (public) columns that encode the computation
//! schedule: round constants, round-type selectors, perm-init selectors,
//! and output selectors.

use stwo::core::fields::m31::M31;

use super::schedule::*;

/// Names for the preprocessed columns, in the order they are read by the AIR.
pub fn preprocessed_column_names() -> Vec<String> {
    let mut names = Vec::with_capacity(NUM_PREPROCESSED_COLUMNS);
    for i in 0..STATE_WIDTH {
        names.push(format!("rc_{i}"));
    }
    names.push("is_full".into());
    names.push("is_partial".into());
    names.push("is_padding".into());
    for i in 0..NUM_PERMS {
        names.push(format!("is_init_perm_{i}"));
    }
    names.push("is_output_idcom".into());
    names.push("is_output_target".into());
    names.push("is_output_rpcom".into());
    names.push("is_padding_start".into());
    assert_eq!(names.len(), NUM_PREPROCESSED_COLUMNS);
    names
}

/// Generate all preprocessed trace columns.
///
/// Each returned `Vec<M31>` has length `TRACE_LEN` (512).
/// Column order matches `preprocessed_column_names()`.
pub fn generate_preprocessed_trace() -> Vec<Vec<M31>> {
    let rc_all = round_constants();
    let mut columns: Vec<Vec<M31>> = (0..NUM_PREPROCESSED_COLUMNS)
        .map(|_| vec![M31(0); TRACE_LEN])
        .collect();

    // Column index helpers
    let rc_col = |i: usize| i; // 0..15
    let is_full_col = 16;
    let is_partial_col = 17;
    let is_padding_col = 18;
    let is_init_perm_col = |p: usize| 19 + p; // 19..31
    let is_output_idcom_col = 32;
    let is_output_target_col = 33;
    let is_output_rpcom_col = 34;
    let is_padding_start_col = 35;

    for row in 0..TRACE_LEN {
        match row_kind(row) {
            RowKind::FullRound { round } => {
                columns[is_full_col][row] = M31(1);
                for k in 0..STATE_WIDTH {
                    columns[rc_col(k)][row] = rc_all[round][k];
                }
            }
            RowKind::PartialRound { round } => {
                columns[is_partial_col][row] = M31(1);
                for k in 0..STATE_WIDTH {
                    columns[rc_col(k)][row] = rc_all[round][k];
                }
            }
            RowKind::PermOutput { perm } => {
                // Output rows are special: they define the transition to the next perm's
                // initial state. Set the is_init_perm_N selector for the NEXT perm.
                let next_perm = perm + 1;
                if next_perm < NUM_PERMS {
                    columns[is_init_perm_col(next_perm)][row] = M31(1);
                }

                // Output selectors for hash outputs
                match perm {
                    2 => columns[is_output_idcom_col][row] = M31(1),
                    6 => columns[is_output_target_col][row] = M31(1),
                    12 => {
                        columns[is_output_rpcom_col][row] = M31(1);
                        columns[is_padding_start_col][row] = M31(1);
                    }
                    _ => {}
                }
            }
            RowKind::Padding => {
                if row == TRACE_LEN - 1 {
                    // Row 511 wraps to row 0: defines perm 0's initial state
                    columns[is_init_perm_col(0)][row] = M31(1);
                } else {
                    columns[is_padding_col][row] = M31(1);
                }
            }
        }
    }

    columns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocessed_column_count() {
        let cols = generate_preprocessed_trace();
        assert_eq!(cols.len(), NUM_PREPROCESSED_COLUMNS);
        for col in &cols {
            assert_eq!(col.len(), TRACE_LEN);
        }
    }

    #[test]
    fn init_perm_selectors_are_at_correct_rows() {
        let cols = generate_preprocessed_trace();
        // is_init_perm_0 at row 511
        assert_eq!(cols[19][511], M31(1));
        // is_init_perm_1 at row 30 (perm 0 output)
        assert_eq!(cols[20][30], M31(1));
        // is_init_perm_3 at row 92 (perm 2 output)
        assert_eq!(cols[22][92], M31(1));
    }

    #[test]
    fn output_selectors_at_correct_rows() {
        let cols = generate_preprocessed_trace();
        // id_com output at row 92 (perm 2 output)
        assert_eq!(cols[32][92], M31(1));
        // target output at row 216 (perm 6 output)
        assert_eq!(cols[33][216], M31(1));
        // rp_com output at row 402 (perm 12 output)
        assert_eq!(cols[34][402], M31(1));
    }

    #[test]
    fn names_match_count() {
        let names = preprocessed_column_names();
        assert_eq!(names.len(), NUM_PREPROCESSED_COLUMNS);
    }
}
