use stwo::core::fields::m31::M31;

pub const M31_MODULUS: u32 = 0x7FFF_FFFF;
pub const REV_BYTES_LEN: usize = 32;
/// Number of M31 field elements needed to represent a 32-byte hash digest.
/// Each M31 element holds ~31 bits, so 8 elements = 248 bits (covers 32 bytes with 4 bytes each).
pub const ELEMENTS_PER_HASH: usize = 8;
/// Lossless encoding of 32 bytes into M31 elements: 8 × 31-bit + 1 overflow element.
pub const ELEMENTS_PER_BYTES32: usize = 9;
/// Lossless encoding of a u64 domain value: 2 × 31-bit + 1 overflow element.
pub const ELEMENTS_PER_DOMAIN: usize = 3;

/// Derivation Context: (AlgID, Domain, Index).
#[derive(Clone, Debug)]
pub struct DerivationContext {
    pub alg_id: M31,
    pub domain: M31,
    pub index: M31,
}

/// Private witness for the ZK-ACE circuit.
/// REV and salt are 32-byte values represented as 9 M31 elements each (lossless).
/// Scalar values (alg_id, domain, index) fit in single elements.
/// Nonce is a u64 encoded as [M31; 3] (lossless, same as domain encoding).
#[derive(Clone)]
pub struct ZkAceWitness {
    pub rev: [M31; ELEMENTS_PER_BYTES32],
    pub salt: [M31; ELEMENTS_PER_BYTES32],
    pub ctx: DerivationContext,
    pub nonce: [M31; ELEMENTS_PER_DOMAIN],
}

/// Public inputs for the ZK-ACE circuit.
/// Hash outputs are [M31; 8]. Byte-encoded values use [M31; 9] (lossless).
/// Domain is [M31; 3] (lossless u64 encoding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAcePublicInputs {
    pub id_com: [M31; ELEMENTS_PER_HASH],
    pub tx_hash: [M31; ELEMENTS_PER_BYTES32],
    pub domain: [M31; ELEMENTS_PER_DOMAIN],
    pub target: [M31; ELEMENTS_PER_HASH],
    pub rp_com: [M31; ELEMENTS_PER_HASH],
}

impl ZkAcePublicInputs {
    /// Total number of field elements in the public inputs.
    /// 3 * 8 (hashes) + 9 (tx_hash) + 3 (domain) = 36
    pub const NUM_ELEMENTS: usize =
        3 * ELEMENTS_PER_HASH + ELEMENTS_PER_BYTES32 + ELEMENTS_PER_DOMAIN; // 36

    /// Flatten all public inputs into a single Vec for boundary constraints.
    pub fn to_elements(&self) -> Vec<M31> {
        let mut v = Vec::with_capacity(Self::NUM_ELEMENTS);
        v.extend_from_slice(&self.id_com);
        v.extend_from_slice(&self.tx_hash);
        v.extend_from_slice(&self.domain);
        v.extend_from_slice(&self.target);
        v.extend_from_slice(&self.rp_com);
        v
    }
}

/// Replay prevention mode selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayMode {
    NonceRegistry,
    NullifierSet,
}

/// Convert a 32-byte value to 9 M31 field elements (lossless).
///
/// Each of the first 8 elements holds the lower 31 bits of a 4-byte chunk.
/// The 9th element collects the high bits (bit 31) from each chunk.
pub fn bytes_to_elements(bytes: &[u8; 32]) -> [M31; ELEMENTS_PER_BYTES32] {
    let mut elements = [M31(0); ELEMENTS_PER_BYTES32];
    let mut overflow: u32 = 0;
    for i in 0..8 {
        let start = i * 4;
        let mut chunk = [0u8; 4];
        chunk.copy_from_slice(&bytes[start..start + 4]);
        let val = u32::from_le_bytes(chunk);
        elements[i] = M31(val & 0x7FFF_FFFF);
        overflow |= (val >> 31) << i;
    }
    elements[8] = M31(overflow);
    elements
}

/// Convert 8 M31 field elements back to 32 bytes (little-endian).
pub fn elements_to_bytes(elements: &[M31; ELEMENTS_PER_HASH]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..ELEMENTS_PER_HASH {
        let val: u32 = elements[i].0;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Whether a raw `u32` is a canonical M31 encoding.
pub fn is_valid_m31_value(val: u32) -> bool {
    val < M31_MODULUS
}

/// Convert 32 canonical hash bytes to [M31; 8].
///
/// Each 4-byte chunk must encode a canonical M31 value (< 2^31 - 1). This
/// rejects aliased encodings that would otherwise be silently truncated.
pub fn try_bytes32_to_hash_elements(bytes: &[u8; 32]) -> Option<[M31; ELEMENTS_PER_HASH]> {
    let mut elems = [M31(0); ELEMENTS_PER_HASH];
    for i in 0..ELEMENTS_PER_HASH {
        let start = i * 4;
        let mut chunk = [0u8; 4];
        chunk.copy_from_slice(&bytes[start..start + 4]);
        let value = u32::from_le_bytes(chunk);
        if !is_valid_m31_value(value) {
            return None;
        }
        elems[i] = M31(value);
    }
    Some(elems)
}

/// Inverse of `bytes_to_elements`: 9 M31 elements → 32 bytes (lossless).
pub fn bytes32_from_elements(elems: &[M31; ELEMENTS_PER_BYTES32]) -> [u8; 32] {
    let overflow = elems[8].0;
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let val = elems[i].0 | (((overflow >> i) & 1) << 31);
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Convert a single u64 to a field element.
///
/// Panics if the value does not fit in a single M31 element.
pub fn u64_to_element(val: u64) -> M31 {
    match try_u64_to_element(val) {
        Some(m) => m,
        None => panic!("scalar value {val} does not fit in a single M31 element"),
    }
}

/// Try to convert a single u64 to a field element.
///
/// Returns `None` if the value does not fit in a single M31 element (>= 2^31 - 1).
pub fn try_u64_to_element(val: u64) -> Option<M31> {
    let v = val as u32;
    if (v as u64) != val || !is_valid_m31_value(v) {
        return None;
    }
    Some(M31(v))
}

/// Convert a field element to u64.
pub fn element_to_u64(elem: M31) -> u64 {
    elem.0 as u64
}

/// Convert a u64 domain value (8 bytes) to [M31; 3] (lossless).
pub fn u64_to_domain_elements(val: u64) -> [M31; ELEMENTS_PER_DOMAIN] {
    let bytes = val.to_le_bytes();
    let lo = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let hi = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let overflow = ((lo >> 31) & 1) | (((hi >> 31) & 1) << 1);
    [M31(lo & 0x7FFF_FFFF), M31(hi & 0x7FFF_FFFF), M31(overflow)]
}

/// Convert [M31; 3] domain elements back to u64 (lossless).
pub fn domain_elements_to_u64(elems: &[M31; ELEMENTS_PER_DOMAIN]) -> u64 {
    let overflow = elems[2].0;
    let lo = elems[0].0 | ((overflow & 1) << 31);
    let hi = elems[1].0 | (((overflow >> 1) & 1) << 31);
    (lo as u64) | ((hi as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_bytes32_to_hash_elements_accepts_canonical_chunks() {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&123u32.to_le_bytes());
        let elems = try_bytes32_to_hash_elements(&bytes).unwrap();
        assert_eq!(elems[0], M31(123));
    }

    #[test]
    fn try_bytes32_to_hash_elements_rejects_modulus_chunk() {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&M31_MODULUS.to_le_bytes());
        assert!(try_bytes32_to_hash_elements(&bytes).is_none());
    }

    #[test]
    fn domain_elements_roundtrip() {
        let value = u64::MAX;
        let elems = u64_to_domain_elements(value);
        assert_eq!(domain_elements_to_u64(&elems), value);
    }
}
