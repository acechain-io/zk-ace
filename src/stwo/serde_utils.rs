//! Serialization utilities for STARK proofs and public inputs.

use stwo::core::fields::m31::M31;

use super::prover::ZkAceProof;
use super::types::{
    is_valid_m31_value, ZkAcePublicInputs, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN,
    ELEMENTS_PER_HASH,
};
use crate::errors::ZkAceError;

// ---------------------------------------------------------------------------
// Proof serialization (identity -- already bytes)
// ---------------------------------------------------------------------------

/// Serialize a STARK proof. The proof is already a `Vec<u8>`, so this is a no-op copy.
pub fn serialize_proof(proof_bytes: &ZkAceProof) -> Vec<u8> {
    proof_bytes.clone()
}

/// Deserialize a STARK proof from raw bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Result<ZkAceProof, ZkAceError> {
    if bytes.is_empty() {
        return Err(ZkAceError::SerializationError(
            "proof bytes are empty".to_string(),
        ));
    }
    Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Public inputs serialization (36 elements x 4 bytes LE)
// ---------------------------------------------------------------------------

/// Expected byte length of serialized public inputs: 36 elements x 4 bytes.
const PI_BYTE_LEN: usize = ZkAcePublicInputs::NUM_ELEMENTS * 4;

/// Serialize public inputs to bytes: 36 M31 elements as little-endian u32s.
pub fn serialize_public_inputs(pi: &ZkAcePublicInputs) -> Vec<u8> {
    let elems = pi.to_elements();
    let mut out = Vec::with_capacity(PI_BYTE_LEN);
    for e in &elems {
        out.extend_from_slice(&e.0.to_le_bytes());
    }
    out
}

/// Deserialize public inputs from bytes (36 x 4 bytes LE).
pub fn deserialize_public_inputs(bytes: &[u8]) -> Result<ZkAcePublicInputs, ZkAceError> {
    if bytes.len() != PI_BYTE_LEN {
        return Err(ZkAceError::SerializationError(format!(
            "expected {PI_BYTE_LEN} bytes for public inputs, got {}",
            bytes.len()
        )));
    }

    let mut elems = Vec::with_capacity(ZkAcePublicInputs::NUM_ELEMENTS);
    for i in 0..ZkAcePublicInputs::NUM_ELEMENTS {
        let start = i * 4;
        let mut chunk = [0u8; 4];
        chunk.copy_from_slice(&bytes[start..start + 4]);
        let raw = u32::from_le_bytes(chunk);
        if !is_valid_m31_value(raw) {
            return Err(ZkAceError::SerializationError(format!(
                "public input element {i} is not a canonical M31 value: {raw}"
            )));
        }
        elems.push(M31(raw));
    }

    let mut id_com = [M31(0); ELEMENTS_PER_HASH];
    let mut tx_hash = [M31(0); ELEMENTS_PER_BYTES32];
    let mut domain = [M31(0); ELEMENTS_PER_DOMAIN];
    let mut target = [M31(0); ELEMENTS_PER_HASH];
    let mut rp_com = [M31(0); ELEMENTS_PER_HASH];

    id_com.copy_from_slice(&elems[0..8]);
    tx_hash.copy_from_slice(&elems[8..17]);
    domain.copy_from_slice(&elems[17..20]);
    target.copy_from_slice(&elems[20..28]);
    rp_com.copy_from_slice(&elems[28..36]);

    Ok(ZkAcePublicInputs {
        id_com,
        tx_hash,
        domain,
        target,
        rp_com,
    })
}

// ---------------------------------------------------------------------------
// Hex representation
// ---------------------------------------------------------------------------

/// Convert each public-input element to a hex string prefixed with "0x".
pub fn public_inputs_to_hex(pi: &ZkAcePublicInputs) -> Vec<String> {
    pi.to_elements()
        .iter()
        .map(|e| format!("0x{:08x}", e.0))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pi() -> ZkAcePublicInputs {
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
                M31(100),
                M31(200),
                M31(300),
                M31(400),
                M31(500),
                M31(600),
                M31(700),
                M31(800),
            ],
            rp_com: [
                M31(1000),
                M31(2000),
                M31(3000),
                M31(4000),
                M31(5000),
                M31(6000),
                M31(7000),
                M31(8000),
            ],
        }
    }

    #[test]
    fn proof_roundtrip() {
        let proof: ZkAceProof = vec![1, 2, 3, 4, 5];
        let ser = serialize_proof(&proof);
        let de = deserialize_proof(&ser).unwrap();
        assert_eq!(proof, de);
    }

    #[test]
    fn deserialize_proof_rejects_empty() {
        assert!(deserialize_proof(&[]).is_err());
    }

    #[test]
    fn public_inputs_roundtrip() {
        let pi = sample_pi();
        let bytes = serialize_public_inputs(&pi);
        assert_eq!(bytes.len(), PI_BYTE_LEN);
        let pi2 = deserialize_public_inputs(&bytes).unwrap();
        assert_eq!(pi, pi2);
    }

    #[test]
    fn deserialize_pi_rejects_wrong_length() {
        assert!(deserialize_public_inputs(&[0u8; 10]).is_err());
    }

    #[test]
    fn deserialize_proof_rejects_truncated() {
        use crate::stwo::native::commitment::compute_public_inputs;
        use crate::stwo::prover::prove;
        use crate::stwo::types::{DerivationContext, ReplayMode, ZkAceWitness};
        use stwo::core::fields::m31::M31;

        let w = ZkAceWitness {
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
        };
        let tx = [
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
        let pi = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&w, &pi, ReplayMode::NonceRegistry).unwrap();

        // Serialize and truncate last 10 bytes
        let mut bytes = serialize_proof(&proof);
        assert!(bytes.len() > 10);
        bytes.truncate(bytes.len() - 10);

        // Truncated proof should fail verification (bincode deserialization inside verify)
        let result = crate::stwo::verifier::verify(&bytes, &pi, ReplayMode::NonceRegistry);
        assert!(
            result.is_err(),
            "truncated proof must be rejected by verifier"
        );
    }

    #[test]
    fn deserialize_pi_rejects_m31_overflow() {
        // PI_BYTE_LEN = 36 * 4 = 144 bytes
        // Each element is a LE u32 representing an M31 field element
        // M31 prime modulus = 2^31 - 1 = 2147483647
        // A value >= 2^31 - 1 is out of range for M31

        let mut bytes = [0u8; 36 * 4]; // correct length

        // Set the first element to the M31 prime itself (2^31 - 1 = 0x7FFF_FFFF)
        let overflow_val: u32 = 0x7FFF_FFFF; // P itself, which is NOT a valid M31 element
        bytes[0..4].copy_from_slice(&overflow_val.to_le_bytes());

        assert!(deserialize_public_inputs(&bytes).is_err());
    }

    #[test]
    fn hex_output_format() {
        let pi = sample_pi();
        let hex = public_inputs_to_hex(&pi);
        assert_eq!(hex.len(), ZkAcePublicInputs::NUM_ELEMENTS);
        assert!(hex[0].starts_with("0x"));
        assert_eq!(hex[0], "0x00000001");
    }
}
