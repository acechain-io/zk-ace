//! BN254 Fr field conversion utilities for Groth16 backend.

use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Convert 32 bytes to a BN254 scalar field element (little-endian, mod order).
///
/// Note: BN254 Fr is ~254 bits, so values >= field order are reduced.
/// This is lossless for field-computed values and loses at most 2 bits
/// for arbitrary 256-bit inputs.
pub fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Convert 32 bytes to a BN254 scalar only if they are already canonical.
pub fn try_bytes32_to_fr(bytes: &[u8; 32]) -> Option<Fr> {
    let fr = bytes32_to_fr(bytes);
    if fr_to_bytes32(&fr) == *bytes {
        Some(fr)
    } else {
        None
    }
}

/// Convert a BN254 scalar field element to 32 bytes (little-endian).
pub fn fr_to_bytes32(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref(); // [u64; 4]
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = i * 8;
        out[start..start + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Convert a u64 to a field element.
pub fn u64_to_fr(v: u64) -> Fr {
    Fr::from(v)
}

/// Convert a field element to u64 (takes lowest 64 bits).
/// Only valid for values that originally fit in u64.
pub fn fr_to_u64(fr: &Fr) -> u64 {
    fr.into_bigint().as_ref()[0]
}

/// Derivation context parameters (BN254 Fr-based).
#[derive(Clone, Debug)]
pub struct DerivationContext {
    pub alg_id: Fr,
    pub domain: Fr,
    pub index: Fr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn bytes32_roundtrip() {
        // Value within field range
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        bytes[7] = 0xFF;
        let fr = bytes32_to_fr(&bytes);
        let recovered = fr_to_bytes32(&fr);
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn u64_roundtrip() {
        let val = 123456789u64;
        let fr = u64_to_fr(val);
        assert_eq!(fr_to_u64(&fr), val);
    }

    #[test]
    fn zero_roundtrip() {
        let fr = Fr::zero();
        let bytes = fr_to_bytes32(&fr);
        assert_eq!(bytes, [0u8; 32]);
        assert_eq!(bytes32_to_fr(&bytes), fr);
    }

    #[test]
    fn u64_max_roundtrip() {
        let val = u64::MAX;
        let fr = u64_to_fr(val);
        assert_eq!(fr_to_u64(&fr), val);
    }

    #[test]
    fn try_bytes32_to_fr_rejects_noncanonical_encoding() {
        assert!(try_bytes32_to_fr(&[0xFF; 32]).is_none());
    }
}
