use stwo::core::fields::m31::M31;

use super::hash::poseidon2_hash;
use crate::stwo::types::{DerivationContext, ELEMENTS_PER_BYTES32, ELEMENTS_PER_HASH};

/// Derive function: Poseidon2(REV[0..9], AlgID, Domain, Index).
pub fn derive_native(
    rev: &[M31; ELEMENTS_PER_BYTES32],
    ctx: &DerivationContext,
) -> [M31; ELEMENTS_PER_HASH] {
    let mut inputs = Vec::with_capacity(ELEMENTS_PER_BYTES32 + 3);
    inputs.extend_from_slice(rev);
    inputs.push(ctx.alg_id);
    inputs.push(ctx.domain);
    inputs.push(ctx.index);
    poseidon2_hash(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rev() -> [M31; ELEMENTS_PER_BYTES32] {
        [
            M31(12345),
            M31(67890),
            M31(11111),
            M31(22222),
            M31(33333),
            M31(44444),
            M31(55555),
            M31(66666),
            M31(0),
        ]
    }

    #[test]
    fn derive_is_deterministic() {
        let rev = test_rev();
        let ctx = DerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let d1 = derive_native(&rev, &ctx);
        let d2 = derive_native(&rev, &ctx);
        assert_eq!(d1, d2);
    }

    #[test]
    fn context_isolation() {
        let rev = test_rev();
        let ctx_a = DerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let ctx_b = DerivationContext {
            alg_id: M31(1),
            domain: M31(1),
            index: M31(0),
        };
        assert_ne!(derive_native(&rev, &ctx_a), derive_native(&rev, &ctx_b));
    }

    #[test]
    fn different_rev_different_output() {
        let ctx = DerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let rev_a = [M31(111); ELEMENTS_PER_BYTES32];
        let rev_b = [M31(222); ELEMENTS_PER_BYTES32];
        assert_ne!(derive_native(&rev_a, &ctx), derive_native(&rev_b, &ctx));
    }
}
