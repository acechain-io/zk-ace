//! ZK-ACE AIR definition using Stwo's constraint framework.
//!
//! Implements a full Poseidon2 constraint circuit that proves knowledge of
//! the witness (REV, salt, nonce, derivation context) used to compute the
//! identity commitment, target, and replay-prevention commitment.
//!
//! The trace encodes 13 Poseidon2 permutations step-by-step over 512 rows.
//! Constraints verify:
//! 1. S-box decomposition (x^5) at every row
//! 2. Full and partial round transitions via the MDS matrix
//! 3. Boundary/init constraints at each permutation start
//! 4. Output constraints binding hash outputs to public inputs
//! 5. Witness column constancy across all rows

use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use super::schedule::*;
use crate::stwo::types::{
    ReplayMode, ZkAcePublicInputs, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN, ELEMENTS_PER_HASH,
};

pub use super::schedule::LOG_TRACE_SIZE;
pub use super::schedule::NUM_MAIN_COLUMNS as NUM_TRACE_COLUMNS;

/// ZK-ACE constraint evaluator for Stwo.
pub struct ZkAceEval {
    pub log_size: u32,
    pub public_inputs: ZkAcePublicInputs,
    pub replay_mode: ReplayMode,
}

impl ZkAceEval {
    pub fn new(public_inputs: ZkAcePublicInputs, replay_mode: ReplayMode) -> Self {
        Self {
            log_size: LOG_TRACE_SIZE,
            public_inputs,
            replay_mode,
        }
    }
}

impl FrameworkEval for ZkAceEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        use stwo::core::fields::m31::M31;

        // =====================================================================
        // Read preprocessed columns (must match order in preprocessed_column_names)
        // =====================================================================
        let rc: Vec<E::F> = (0..STATE_WIDTH)
            .map(|k| {
                eval.get_preprocessed_column(PreProcessedColumnId {
                    id: format!("rc_{k}").into(),
                })
            })
            .collect();
        let is_full = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_full".into(),
        });
        let is_partial = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_partial".into(),
        });
        let is_padding = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_padding".into(),
        });
        let is_init_perm: Vec<E::F> = (0..NUM_PERMS)
            .map(|p| {
                eval.get_preprocessed_column(PreProcessedColumnId {
                    id: format!("is_init_perm_{p}").into(),
                })
            })
            .collect();
        let is_output_idcom = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_output_idcom".into(),
        });
        let is_output_target = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_output_target".into(),
        });
        let is_output_rpcom = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_output_rpcom".into(),
        });
        let is_padding_start = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "is_padding_start".into(),
        });

        // =====================================================================
        // Read main trace columns
        // =====================================================================

        // State columns: read at offsets [0, 1] for current and next row
        let mut state_curr: Vec<E::F> = Vec::with_capacity(STATE_WIDTH);
        let mut state_next: Vec<E::F> = Vec::with_capacity(STATE_WIDTH);
        for _k in 0..STATE_WIDTH {
            let [curr, next] =
                eval.next_interaction_mask(stwo_constraint_framework::ORIGINAL_TRACE_IDX, [0, 1]);
            state_curr.push(curr);
            state_next.push(next);
        }

        // S-box intermediate columns: read at offset [0]
        let x2: Vec<E::F> = (0..STATE_WIDTH).map(|_| eval.next_trace_mask()).collect();
        let x4: Vec<E::F> = (0..STATE_WIDTH).map(|_| eval.next_trace_mask()).collect();
        let x5: Vec<E::F> = (0..STATE_WIDTH).map(|_| eval.next_trace_mask()).collect();

        // Witness columns: read at offsets [0, 1] for constancy check
        let (w_rev_curr, w_rev_next) = read_witness_pair::<E>(&mut eval, ELEMENTS_PER_BYTES32);
        let (w_salt_curr, w_salt_next) = read_witness_pair::<E>(&mut eval, ELEMENTS_PER_BYTES32);
        let (w_nonce_curr, w_nonce_next) = read_witness_pair::<E>(&mut eval, ELEMENTS_PER_DOMAIN);
        let (w_ctx_curr, w_ctx_next) = read_witness_pair::<E>(&mut eval, 3);
        let (w_tx_hash_curr, w_tx_hash_next) =
            read_witness_pair::<E>(&mut eval, ELEMENTS_PER_BYTES32);
        let (w_domain_curr, w_domain_next) = read_witness_pair::<E>(&mut eval, ELEMENTS_PER_DOMAIN);

        // =====================================================================
        // Constraint 1: S-box decomposition (48 constraints)
        // =====================================================================
        for k in 0..STATE_WIDTH {
            eval.add_constraint(x2[k].clone() - state_curr[k].clone() * state_curr[k].clone());
            eval.add_constraint(x4[k].clone() - x2[k].clone() * x2[k].clone());
            eval.add_constraint(x5[k].clone() - x4[k].clone() * state_curr[k].clone());
        }

        // =====================================================================
        // Constraint 2: Full round transition (16 constraints)
        // =====================================================================
        let mds = MDS_CIRC;
        for j in 0..STATE_WIDTH {
            let mut mds_result = x5[0].clone() * M31(mds[(STATE_WIDTH + j) % STATE_WIDTH]);
            for k in 1..STATE_WIDTH {
                mds_result =
                    mds_result + x5[k].clone() * M31(mds[(STATE_WIDTH + j - k) % STATE_WIDTH]);
            }
            eval.add_constraint(
                is_full.clone() * (state_next[j].clone() - mds_result - rc[j].clone()),
            );
        }

        // =====================================================================
        // Constraint 3: Partial round transition (16 constraints)
        // =====================================================================
        for j in 0..STATE_WIDTH {
            let mut mds_result = x5[0].clone() * M31(mds[(STATE_WIDTH + j) % STATE_WIDTH]);
            for k in 1..STATE_WIDTH {
                mds_result = mds_result
                    + state_curr[k].clone() * M31(mds[(STATE_WIDTH + j - k) % STATE_WIDTH]);
            }
            eval.add_constraint(
                is_partial.clone() * (state_next[j].clone() - mds_result - rc[j].clone()),
            );
        }

        // =====================================================================
        // Constraint 4: Padding identity (16 constraints)
        // =====================================================================
        for j in 0..STATE_WIDTH {
            eval.add_constraint(
                is_padding.clone() * (state_next[j].clone() - state_curr[j].clone()),
            );
        }

        // =====================================================================
        // Constraint 5: Padding start transition (16 constraints)
        // =====================================================================
        for j in 0..STATE_WIDTH {
            eval.add_constraint(
                is_padding_start.clone() * (state_next[j].clone() - state_curr[j].clone()),
            );
        }

        // =====================================================================
        // Constraint 6: Witness constancy (36 constraints)
        // =====================================================================
        for k in 0..ELEMENTS_PER_BYTES32 {
            eval.add_constraint(w_rev_next[k].clone() - w_rev_curr[k].clone());
        }
        for k in 0..ELEMENTS_PER_BYTES32 {
            eval.add_constraint(w_salt_next[k].clone() - w_salt_curr[k].clone());
        }
        for k in 0..ELEMENTS_PER_DOMAIN {
            eval.add_constraint(w_nonce_next[k].clone() - w_nonce_curr[k].clone());
        }
        for k in 0..3 {
            eval.add_constraint(w_ctx_next[k].clone() - w_ctx_curr[k].clone());
        }
        for k in 0..ELEMENTS_PER_BYTES32 {
            eval.add_constraint(w_tx_hash_next[k].clone() - w_tx_hash_curr[k].clone());
        }
        for k in 0..ELEMENTS_PER_DOMAIN {
            eval.add_constraint(w_domain_next[k].clone() - w_domain_curr[k].clone());
        }

        // =====================================================================
        // Constraint 7: PI binding for tx_hash and domain witness columns
        // =====================================================================
        let pi = &self.public_inputs;
        for k in 0..ELEMENTS_PER_BYTES32 {
            eval.add_constraint(
                is_init_perm[0].clone() * (w_tx_hash_curr[k].clone() - E::F::from(pi.tx_hash[k])),
            );
        }
        for k in 0..ELEMENTS_PER_DOMAIN {
            eval.add_constraint(
                is_init_perm[0].clone() * (w_domain_curr[k].clone() - E::F::from(pi.domain[k])),
            );
        }

        // =====================================================================
        // Constraint 8: Fresh init and continue boundary constraints
        // =====================================================================

        // --- Perm 0 (is_init_perm[0]): id_com hash, domain_sep=21 ---
        {
            let sel = &is_init_perm[0];
            eval.add_constraint(sel.clone() * (state_next[0].clone() - E::F::from(M31(21))));
            for k in 1..CAPACITY {
                eval.add_constraint(sel.clone() * state_next[k].clone());
            }
            for k in 0..RATE {
                eval.add_constraint(
                    sel.clone() * (state_next[CAPACITY + k].clone() - w_rev_curr[k].clone()),
                );
            }
        }

        // --- Perm 1 (is_init_perm[1]): continue id_com, absorb [rev[8], salt[0..7]] ---
        {
            let sel = &is_init_perm[1];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_rev_curr[8].clone()),
            );
            for i in 0..7 {
                eval.add_constraint(
                    sel.clone()
                        * (state_next[9 + i].clone()
                            - state_curr[9 + i].clone()
                            - w_salt_curr[i].clone()),
                );
            }
        }

        // --- Perm 2 (is_init_perm[2]): continue id_com, absorb [salt[7], salt[8], domain[0..3]] ---
        {
            let sel = &is_init_perm[2];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_salt_curr[7].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[9].clone() - state_curr[9].clone() - w_salt_curr[8].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[10].clone() - state_curr[10].clone() - w_domain_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[11].clone() - state_curr[11].clone() - w_domain_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[12].clone() - state_curr[12].clone() - w_domain_curr[2].clone()),
            );
            for k in 13..STATE_WIDTH {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
        }

        // --- Perm 3 (is_init_perm[3]): fresh derive hash, domain_sep=12 ---
        {
            let sel = &is_init_perm[3];
            eval.add_constraint(sel.clone() * (state_next[0].clone() - E::F::from(M31(12))));
            for k in 1..CAPACITY {
                eval.add_constraint(sel.clone() * state_next[k].clone());
            }
            for k in 0..RATE {
                eval.add_constraint(
                    sel.clone() * (state_next[CAPACITY + k].clone() - w_rev_curr[k].clone()),
                );
            }
        }

        // --- Perm 4 (is_init_perm[4]): continue derive, absorb [rev[8], ctx...] ---
        {
            let sel = &is_init_perm[4];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_rev_curr[8].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[9].clone() - state_curr[9].clone() - w_ctx_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[10].clone() - state_curr[10].clone() - w_ctx_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[11].clone() - state_curr[11].clone() - w_ctx_curr[2].clone()),
            );
            for k in 12..STATE_WIDTH {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
        }

        // --- Perm 5 (is_init_perm[5]): fresh target hash, domain_sep=8 ---
        {
            let sel = &is_init_perm[5];
            eval.add_constraint(sel.clone() * (state_next[0].clone() - E::F::from(M31(8))));
            for k in 1..CAPACITY {
                eval.add_constraint(sel.clone() * state_next[k].clone());
            }
            for k in 0..RATE {
                eval.add_constraint(
                    sel.clone()
                        * (state_next[CAPACITY + k].clone() - state_curr[CAPACITY + k].clone()),
                );
            }
        }

        // --- Perm 6 (is_init_perm[6]): no-absorb continue ---
        {
            let sel = &is_init_perm[6];
            for k in 0..STATE_WIDTH {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
        }

        // --- Perm 7 (is_init_perm[7]): fresh auth hash, domain_sep=28 ---
        {
            let sel = &is_init_perm[7];
            eval.add_constraint(sel.clone() * (state_next[0].clone() - E::F::from(M31(27))));
            for k in 1..CAPACITY {
                eval.add_constraint(sel.clone() * state_next[k].clone());
            }
            for k in 0..RATE {
                eval.add_constraint(
                    sel.clone() * (state_next[CAPACITY + k].clone() - w_rev_curr[k].clone()),
                );
            }
        }

        // --- Perm 8 (is_init_perm[8]): continue auth, absorb block 1 ---
        {
            let sel = &is_init_perm[8];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_rev_curr[8].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[9].clone() - state_curr[9].clone() - w_ctx_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[10].clone() - state_curr[10].clone() - w_ctx_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[11].clone() - state_curr[11].clone() - w_ctx_curr[2].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[12].clone() - state_curr[12].clone() - w_tx_hash_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[13].clone() - state_curr[13].clone() - w_tx_hash_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[14].clone() - state_curr[14].clone() - w_tx_hash_curr[2].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[15].clone() - state_curr[15].clone() - w_tx_hash_curr[3].clone()),
            );
        }

        // --- Perm 9 (is_init_perm[9]): continue auth, absorb block 2 ---
        {
            let sel = &is_init_perm[9];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_tx_hash_curr[4].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[9].clone() - state_curr[9].clone() - w_tx_hash_curr[5].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[10].clone() - state_curr[10].clone() - w_tx_hash_curr[6].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[11].clone() - state_curr[11].clone() - w_tx_hash_curr[7].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[12].clone() - state_curr[12].clone() - w_tx_hash_curr[8].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[13].clone() - state_curr[13].clone() - w_domain_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[14].clone() - state_curr[14].clone() - w_domain_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[15].clone() - state_curr[15].clone() - w_domain_curr[2].clone()),
            );
        }

        // --- Perm 10 (is_init_perm[10]): continue auth, absorb nonce ---
        {
            let sel = &is_init_perm[10];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            eval.add_constraint(
                sel.clone()
                    * (state_next[8].clone() - state_curr[8].clone() - w_nonce_curr[0].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[9].clone() - state_curr[9].clone() - w_nonce_curr[1].clone()),
            );
            eval.add_constraint(
                sel.clone()
                    * (state_next[10].clone() - state_curr[10].clone() - w_nonce_curr[2].clone()),
            );
            for k in 11..STATE_WIDTH {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
        }

        // --- Perm 11 (is_init_perm[11]): fresh rp_com hash, domain_sep=11 ---
        {
            let sel = &is_init_perm[11];
            eval.add_constraint(sel.clone() * (state_next[0].clone() - E::F::from(M31(11))));
            for k in 1..CAPACITY {
                eval.add_constraint(sel.clone() * state_next[k].clone());
            }
            match self.replay_mode {
                ReplayMode::NonceRegistry => {
                    for k in 0..RATE {
                        eval.add_constraint(
                            sel.clone()
                                * (state_next[CAPACITY + k].clone() - E::F::from(pi.id_com[k])),
                        );
                    }
                }
                ReplayMode::NullifierSet => {
                    for k in 0..RATE {
                        eval.add_constraint(
                            sel.clone()
                                * (state_next[CAPACITY + k].clone()
                                    - state_curr[CAPACITY + k].clone()),
                        );
                    }
                }
            }
        }

        // --- Perm 12 (is_init_perm[12]): continue rp_com, absorb partial ---
        {
            let sel = &is_init_perm[12];
            for k in 0..CAPACITY {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
            match self.replay_mode {
                ReplayMode::NonceRegistry => {
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[8].clone()
                                - state_curr[8].clone()
                                - w_nonce_curr[0].clone()),
                    );
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[9].clone()
                                - state_curr[9].clone()
                                - w_nonce_curr[1].clone()),
                    );
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[10].clone()
                                - state_curr[10].clone()
                                - w_nonce_curr[2].clone()),
                    );
                }
                ReplayMode::NullifierSet => {
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[8].clone()
                                - state_curr[8].clone()
                                - w_domain_curr[0].clone()),
                    );
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[9].clone()
                                - state_curr[9].clone()
                                - w_domain_curr[1].clone()),
                    );
                    eval.add_constraint(
                        sel.clone()
                            * (state_next[10].clone()
                                - state_curr[10].clone()
                                - w_domain_curr[2].clone()),
                    );
                }
            }
            for k in 11..STATE_WIDTH {
                eval.add_constraint(sel.clone() * (state_next[k].clone() - state_curr[k].clone()));
            }
        }

        // =====================================================================
        // Constraint 9: Output constraints (24 constraints)
        // =====================================================================
        for k in 0..ELEMENTS_PER_HASH {
            eval.add_constraint(
                is_output_idcom.clone()
                    * (state_curr[CAPACITY + k].clone() - E::F::from(pi.id_com[k])),
            );
        }
        for k in 0..ELEMENTS_PER_HASH {
            eval.add_constraint(
                is_output_target.clone()
                    * (state_curr[CAPACITY + k].clone() - E::F::from(pi.target[k])),
            );
        }
        for k in 0..ELEMENTS_PER_HASH {
            eval.add_constraint(
                is_output_rpcom.clone()
                    * (state_curr[CAPACITY + k].clone() - E::F::from(pi.rp_com[k])),
            );
        }

        eval
    }
}

/// Helper: read `n` witness columns at offsets [0, 1], returning (curr, next) vectors.
fn read_witness_pair<E: EvalAtRow>(eval: &mut E, n: usize) -> (Vec<E::F>, Vec<E::F>) {
    let mut curr = Vec::with_capacity(n);
    let mut next = Vec::with_capacity(n);
    for _ in 0..n {
        let [c, nx] =
            eval.next_interaction_mask(stwo_constraint_framework::ORIGINAL_TRACE_IDX, [0, 1]);
        curr.push(c);
        next.push(nx);
    }
    (curr, next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;

    fn sample_public_inputs() -> ZkAcePublicInputs {
        ZkAcePublicInputs {
            id_com: [
                M31(1),
                M31(2),
                M31(3),
                M31(4),
                M31(5),
                M31(6),
                M31(7),
                M31(8),
            ],
            tx_hash: [
                M31(10),
                M31(20),
                M31(30),
                M31(40),
                M31(50),
                M31(60),
                M31(70),
                M31(80),
                M31(0),
            ],
            domain: [M31(99), M31(0), M31(0)],
            target: [
                M31(5),
                M31(6),
                M31(7),
                M31(8),
                M31(9),
                M31(10),
                M31(11),
                M31(12),
            ],
            rp_com: [
                M31(50),
                M31(60),
                M31(70),
                M31(80),
                M31(90),
                M31(100),
                M31(110),
                M31(120),
            ],
        }
    }

    #[test]
    fn eval_has_correct_log_size() {
        let pi = sample_public_inputs();
        let eval = ZkAceEval::new(pi, ReplayMode::NonceRegistry);
        assert_eq!(eval.log_size(), LOG_TRACE_SIZE);
    }

    #[test]
    fn constraint_degree_bound() {
        let pi = sample_public_inputs();
        let eval = ZkAceEval::new(pi, ReplayMode::NonceRegistry);
        assert_eq!(eval.max_constraint_log_degree_bound(), LOG_TRACE_SIZE + 1);
    }
}
