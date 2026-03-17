//! Key derivation for Groth16 backend.

use ark_bn254::Fr;

use super::hash::poseidon_hash;
use super::types::DerivationContext;

/// Derive: Poseidon(rev, alg_id, domain, index) -> Fr
pub fn derive_native(rev: &Fr, ctx: &DerivationContext) -> Fr {
    poseidon_hash(&[*rev, ctx.alg_id, ctx.domain, ctx.index])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rev() -> Fr {
        Fr::from(12345u64)
    }

    #[test]
    fn derive_is_deterministic() {
        let rev = test_rev();
        let ctx = DerivationContext {
            alg_id: Fr::from(0u64),
            domain: Fr::from(1u64),
            index: Fr::from(0u64),
        };
        assert_eq!(derive_native(&rev, &ctx), derive_native(&rev, &ctx));
    }

    #[test]
    fn context_isolation() {
        let rev = test_rev();
        let ctx_a = DerivationContext {
            alg_id: Fr::from(0u64),
            domain: Fr::from(1u64),
            index: Fr::from(0u64),
        };
        let ctx_b = DerivationContext {
            alg_id: Fr::from(1u64),
            domain: Fr::from(1u64),
            index: Fr::from(0u64),
        };
        assert_ne!(derive_native(&rev, &ctx_a), derive_native(&rev, &ctx_b));
    }

    #[test]
    fn different_rev_different_output() {
        let ctx = DerivationContext {
            alg_id: Fr::from(0u64),
            domain: Fr::from(1u64),
            index: Fr::from(0u64),
        };
        assert_ne!(
            derive_native(&Fr::from(111u64), &ctx),
            derive_native(&Fr::from(222u64), &ctx),
        );
    }
}
