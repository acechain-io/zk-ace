//! Core byte-based types for ZK-ACE.
//!
//! These types are backend-agnostic: they use raw bytes and u64 scalars,
//! not field-specific representations. Each backend converts these into
//! its native field element format internally.

use serde::{Deserialize, Serialize};

/// Replay prevention mode selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayMode {
    /// rp_com = H(ID_com || nonce) — nonce registry model (account-style)
    NonceRegistry,
    /// rp_com = H(Auth || domain) — nullifier set model (privacy-style)
    NullifierSet,
}

/// Backend-agnostic witness (private inputs).
///
/// All 32-byte values are raw bytes; scalar values fit in u64.
/// The backend converts these into its native field representation.
#[derive(Clone, Debug)]
pub struct Witness {
    /// REV: 256-bit Root Entropy Value.
    pub rev: [u8; 32],
    /// Identity-specific commitment salt.
    pub salt: [u8; 32],
    /// Target cryptographic algorithm ID.
    pub alg_id: u64,
    /// Chain/application domain tag.
    pub domain: u64,
    /// Derivation index.
    pub index: u64,
    /// Replay-prevention nonce.
    pub nonce: u64,
}

/// Backend-agnostic public inputs.
///
/// Hash outputs are 32 bytes (backend truncates or pads as needed).
/// Domain is a u64 scalar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Identity commitment: H(REV || salt || domain)
    pub id_com: [u8; 32],
    /// Transaction hash to be authorized.
    pub tx_hash: [u8; 32],
    /// Chain/application domain tag.
    pub domain: u64,
    /// Target-binding hash: H(Derive(REV, Ctx))
    pub target: [u8; 32],
    /// Replay-prevention commitment.
    pub rp_com: [u8; 32],
}
