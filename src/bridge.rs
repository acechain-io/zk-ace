//! Bridge between ACE-GF wallet and ZK-ACE.
//!
//! Converts wallet-level byte representations into M31 field elements
//! and constructs ZK-ACE witnesses ready for proving.

use stwo::core::fields::m31::M31;

use crate::errors::ZkAceError;
use crate::stwo::types::{
    bytes_to_elements, DerivationContext, ZkAceWitness, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN,
};

/// Bridge for converting ACE-GF wallet data into ZK-ACE types.
pub struct AceGfBridge;

impl AceGfBridge {
    /// Convert a 32-byte REV (or any 32-byte value) into 9 M31 field elements (lossless).
    ///
    /// Validates that the input is exactly 32 bytes, then delegates to
    /// `bytes_to_elements`.
    pub fn rev_bytes_to_elements(
        rev_bytes: &[u8],
    ) -> Result<[M31; ELEMENTS_PER_BYTES32], ZkAceError> {
        if rev_bytes.len() != 32 {
            return Err(ZkAceError::InvalidRevLength {
                expected: 32,
                actual: rev_bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(rev_bytes);
        Ok(bytes_to_elements(&arr))
    }

    /// Build a complete `ZkAceWitness` from wallet-level components.
    pub fn build_witness(
        rev: &[M31; ELEMENTS_PER_BYTES32],
        salt: [M31; ELEMENTS_PER_BYTES32],
        ctx: DerivationContext,
        nonce: [M31; ELEMENTS_PER_DOMAIN],
    ) -> ZkAceWitness {
        ZkAceWitness {
            rev: *rev,
            salt,
            ctx,
            nonce,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rev_bytes_to_elements_roundtrip() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let elems = AceGfBridge::rev_bytes_to_elements(&bytes).unwrap();
        let back = crate::stwo::types::bytes32_from_elements(&elems);
        assert_eq!(bytes, back, "roundtrip must be lossless");
    }

    #[test]
    fn rev_bytes_rejects_wrong_length() {
        assert!(AceGfBridge::rev_bytes_to_elements(&[0u8; 16]).is_err());
        assert!(AceGfBridge::rev_bytes_to_elements(&[0u8; 33]).is_err());
        assert!(AceGfBridge::rev_bytes_to_elements(&[]).is_err());
    }

    #[test]
    fn build_witness_populates_fields() {
        let rev = [
            M31(1),
            M31(2),
            M31(3),
            M31(4),
            M31(5),
            M31(6),
            M31(7),
            M31(8),
            M31(0),
        ];
        let salt = [
            M31(10),
            M31(20),
            M31(30),
            M31(40),
            M31(50),
            M31(60),
            M31(70),
            M31(80),
            M31(0),
        ];
        let ctx = DerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let nonce = [M31(7), M31(0), M31(0)];

        let w = AceGfBridge::build_witness(&rev, salt, ctx, nonce);
        assert_eq!(w.rev, rev);
        assert_eq!(w.salt, salt);
        assert_eq!(w.nonce[0].0, 7);
    }

    #[test]
    fn build_witness_and_compute_public_inputs() {
        use crate::stwo::types::ELEMENTS_PER_HASH;
        let rev = [
            M31(42),
            M31(43),
            M31(44),
            M31(45),
            M31(46),
            M31(47),
            M31(48),
            M31(49),
            M31(0),
        ];
        let salt = [
            M31(100),
            M31(101),
            M31(102),
            M31(103),
            M31(104),
            M31(105),
            M31(106),
            M31(107),
            M31(0),
        ];
        let ctx = DerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let nonce = [M31(7), M31(0), M31(0)];

        let w = AceGfBridge::build_witness(&rev, salt, ctx, nonce);
        let tx_hash = [
            M31(999),
            M31(998),
            M31(997),
            M31(996),
            M31(995),
            M31(994),
            M31(993),
            M31(992),
            M31(0),
        ];
        let domain = [M31(1), M31(0), M31(0)];
        let pi = crate::stwo::native::commitment::compute_public_inputs(
            &w,
            &tx_hash,
            &domain,
            crate::stwo::types::ReplayMode::NonceRegistry,
        );
        // Public inputs should be deterministic and non-zero.
        let zero = [M31(0); ELEMENTS_PER_HASH];
        assert_ne!(pi.id_com, zero);
        assert_ne!(pi.target, zero);
        assert_ne!(pi.rp_com, zero);
    }
}
