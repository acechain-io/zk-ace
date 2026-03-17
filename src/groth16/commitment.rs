//! Native C1-C5 constraint computations for Groth16 backend.

use ark_bn254::Fr;

use super::derive::derive_native;
use super::hash::poseidon_hash;
use super::types::DerivationContext;
use crate::types::ReplayMode;

/// C1: id_com = Poseidon(rev, salt, domain)
pub fn compute_id_com(rev: &Fr, salt: &Fr, domain: &Fr) -> Fr {
    poseidon_hash(&[*rev, *salt, *domain])
}

/// C2: target = Poseidon(Derive(rev, ctx))
pub fn compute_target(rev: &Fr, ctx: &DerivationContext) -> Fr {
    let derived = derive_native(rev, ctx);
    poseidon_hash(&[derived])
}

/// C3: auth = Poseidon(rev, alg_id, domain_ctx, index, tx_hash, domain, nonce)
pub fn compute_auth(
    rev: &Fr,
    ctx: &DerivationContext,
    tx_hash: &Fr,
    domain: &Fr,
    nonce: &Fr,
) -> Fr {
    poseidon_hash(&[
        *rev, ctx.alg_id, ctx.domain, ctx.index, *tx_hash, *domain, *nonce,
    ])
}

/// C4A: rp_com = Poseidon(id_com, nonce) (NonceRegistry mode)
pub fn compute_rp_com_nonce(id_com: &Fr, nonce: &Fr) -> Fr {
    poseidon_hash(&[*id_com, *nonce])
}

/// C4B: rp_com = Poseidon(auth, domain) (NullifierSet mode)
pub fn compute_rp_com_nullifier(auth: &Fr, domain: &Fr) -> Fr {
    poseidon_hash(&[*auth, *domain])
}

/// Compute all public inputs from witness, tx_hash, and domain.
pub fn compute_public_inputs(
    rev: &Fr,
    salt: &Fr,
    ctx: &DerivationContext,
    nonce: &Fr,
    tx_hash: &Fr,
    domain: &Fr,
    mode: ReplayMode,
) -> Groth16PublicInputs {
    let id_com = compute_id_com(rev, salt, domain);
    let target = compute_target(rev, ctx);
    let auth = compute_auth(rev, ctx, tx_hash, domain, nonce);

    let rp_com = match mode {
        ReplayMode::NonceRegistry => compute_rp_com_nonce(&id_com, nonce),
        ReplayMode::NullifierSet => compute_rp_com_nullifier(&auth, domain),
    };

    Groth16PublicInputs {
        id_com,
        tx_hash: *tx_hash,
        domain: *domain,
        target,
        rp_com,
    }
}

/// Internal public inputs (BN254 Fr-based).
#[derive(Clone, Debug, PartialEq)]
pub struct Groth16PublicInputs {
    pub id_com: Fr,
    pub tx_hash: Fr,
    pub domain: Fr,
    pub target: Fr,
    pub rp_com: Fr,
}

impl Groth16PublicInputs {
    /// Flatten to a vector of field elements (order matches circuit allocation).
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![
            self.id_com,
            self.tx_hash,
            self.domain,
            self.target,
            self.rp_com,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> (Fr, Fr, DerivationContext, Fr, Fr, Fr) {
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
        (rev, salt, ctx, nonce, tx_hash, domain)
    }

    #[test]
    fn public_inputs_are_deterministic() {
        let (rev, salt, ctx, nonce, tx, domain) = test_params();
        let pi1 = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NonceRegistry,
        );
        let pi2 = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NonceRegistry,
        );
        assert_eq!(pi1, pi2);
    }

    #[test]
    fn different_replay_modes_produce_different_rp_com() {
        let (rev, salt, ctx, nonce, tx, domain) = test_params();
        let pi_nonce = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NonceRegistry,
        );
        let pi_null = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NullifierSet,
        );
        assert_eq!(pi_nonce.id_com, pi_null.id_com);
        assert_eq!(pi_nonce.target, pi_null.target);
        assert_ne!(pi_nonce.rp_com, pi_null.rp_com);
    }

    #[test]
    fn all_public_inputs_are_nonzero() {
        let (rev, salt, ctx, nonce, tx, domain) = test_params();
        let pi = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NonceRegistry,
        );
        assert_ne!(pi.id_com, Fr::from(0u64));
        assert_ne!(pi.target, Fr::from(0u64));
        assert_ne!(pi.rp_com, Fr::from(0u64));
    }

    #[test]
    fn public_inputs_to_vec_length() {
        let (rev, salt, ctx, nonce, tx, domain) = test_params();
        let pi = compute_public_inputs(
            &rev,
            &salt,
            &ctx,
            &nonce,
            &tx,
            &domain,
            ReplayMode::NonceRegistry,
        );
        assert_eq!(pi.to_vec().len(), 5);
    }
}
