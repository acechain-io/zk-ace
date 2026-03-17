use stwo::core::fields::m31::M31;

use super::derive::derive_native;
use super::hash::poseidon2_hash;
use crate::stwo::types::{
    DerivationContext, ReplayMode, ZkAcePublicInputs, ZkAceWitness, ELEMENTS_PER_BYTES32,
    ELEMENTS_PER_DOMAIN, ELEMENTS_PER_HASH,
};

/// C1: id_com = Poseidon2(REV || salt || domain)
pub fn compute_id_com(
    rev: &[M31; ELEMENTS_PER_BYTES32],
    salt: &[M31; ELEMENTS_PER_BYTES32],
    domain: &[M31; ELEMENTS_PER_DOMAIN],
) -> [M31; ELEMENTS_PER_HASH] {
    let mut inputs = Vec::with_capacity(ELEMENTS_PER_BYTES32 * 2 + ELEMENTS_PER_DOMAIN);
    inputs.extend_from_slice(rev);
    inputs.extend_from_slice(salt);
    inputs.extend_from_slice(domain);
    poseidon2_hash(&inputs)
}

/// C2: target = Poseidon2(Derive(REV, Ctx))
pub fn compute_target(
    rev: &[M31; ELEMENTS_PER_BYTES32],
    ctx: &DerivationContext,
) -> [M31; ELEMENTS_PER_HASH] {
    let derived = derive_native(rev, ctx);
    poseidon2_hash(&derived)
}

/// C3: Auth = Poseidon2(REV || AlgID || Domain || Index || TxHash || domain || nonce)
pub fn compute_auth(
    rev: &[M31; ELEMENTS_PER_BYTES32],
    ctx: &DerivationContext,
    tx_hash: &[M31; ELEMENTS_PER_BYTES32],
    domain: &[M31; ELEMENTS_PER_DOMAIN],
    nonce: &[M31; ELEMENTS_PER_DOMAIN],
) -> [M31; ELEMENTS_PER_HASH] {
    let mut inputs = Vec::with_capacity(
        ELEMENTS_PER_BYTES32 * 2 + 3 + ELEMENTS_PER_DOMAIN + ELEMENTS_PER_DOMAIN,
    );
    inputs.extend_from_slice(rev);
    inputs.push(ctx.alg_id);
    inputs.push(ctx.domain);
    inputs.push(ctx.index);
    inputs.extend_from_slice(tx_hash);
    inputs.extend_from_slice(domain);
    inputs.extend_from_slice(nonce);
    poseidon2_hash(&inputs)
}

/// C4A: rp_com = Poseidon2(id_com || nonce)
pub fn compute_rp_com_nonce(
    id_com: &[M31; ELEMENTS_PER_HASH],
    nonce: &[M31; ELEMENTS_PER_DOMAIN],
) -> [M31; ELEMENTS_PER_HASH] {
    let mut inputs = Vec::with_capacity(ELEMENTS_PER_HASH + ELEMENTS_PER_DOMAIN);
    inputs.extend_from_slice(id_com);
    inputs.extend_from_slice(nonce);
    poseidon2_hash(&inputs)
}

/// C4B: rp_com = Poseidon2(Auth || domain)
pub fn compute_rp_com_nullifier(
    auth: &[M31; ELEMENTS_PER_HASH],
    domain: &[M31; ELEMENTS_PER_DOMAIN],
) -> [M31; ELEMENTS_PER_HASH] {
    let mut inputs = Vec::with_capacity(ELEMENTS_PER_HASH + ELEMENTS_PER_DOMAIN);
    inputs.extend_from_slice(auth);
    inputs.extend_from_slice(domain);
    poseidon2_hash(&inputs)
}

/// Compute all public inputs from witness, tx_hash, and domain.
pub fn compute_public_inputs(
    witness: &ZkAceWitness,
    tx_hash: &[M31; ELEMENTS_PER_BYTES32],
    domain: &[M31; ELEMENTS_PER_DOMAIN],
    replay_mode: ReplayMode,
) -> ZkAcePublicInputs {
    let id_com = compute_id_com(&witness.rev, &witness.salt, domain);
    let target = compute_target(&witness.rev, &witness.ctx);
    let auth = compute_auth(&witness.rev, &witness.ctx, tx_hash, domain, &witness.nonce);

    let rp_com = match replay_mode {
        ReplayMode::NonceRegistry => compute_rp_com_nonce(&id_com, &witness.nonce),
        ReplayMode::NullifierSet => compute_rp_com_nullifier(&auth, domain),
    };

    ZkAcePublicInputs {
        id_com,
        tx_hash: *tx_hash,
        domain: *domain,
        target,
        rp_com,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn public_inputs_are_deterministic() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi1 = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let pi2 = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        assert_eq!(pi1, pi2);
    }

    #[test]
    fn different_replay_modes_produce_different_rp_com() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi_nonce = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let pi_null = compute_public_inputs(&w, &tx, &domain, ReplayMode::NullifierSet);
        assert_eq!(pi_nonce.id_com, pi_null.id_com);
        assert_eq!(pi_nonce.target, pi_null.target);
        assert_ne!(pi_nonce.rp_com, pi_null.rp_com);
    }

    #[test]
    fn all_public_inputs_are_nonzero() {
        let w = test_witness();
        let tx = test_tx_hash();
        let domain = test_domain();
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let zero = [M31(0); ELEMENTS_PER_HASH];
        assert_ne!(pi.id_com, zero);
        assert_ne!(pi.target, zero);
        assert_ne!(pi.rp_com, zero);
    }
}
