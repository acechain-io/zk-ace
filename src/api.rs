//! High-level API for ZK-ACE STARK operations.
//!
//! Provides an `AuthorizationHandler` that verifies STARK proofs, enforces
//! replay prevention, and supports request idempotency.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use stwo::core::fields::m31::M31;

use crate::replay::{NonceRegistryStore, NullifierSetStore, ReplayGuard};
use crate::stwo::native::commitment::compute_rp_com_nonce;
use crate::stwo::prover::ZkAceProof;
use crate::stwo::types::{
    bytes_to_elements, u64_to_domain_elements, ZkAcePublicInputs, ELEMENTS_PER_BYTES32,
};
use crate::stwo::verifier;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// An authorization request submitted to the handler.
#[derive(Clone, Debug)]
pub struct AuthorizeRequest {
    /// The raw transaction payload bytes.
    pub tx_payload: Vec<u8>,
    /// Which replay prevention mode was used when generating the proof.
    pub replay_mode: crate::stwo::types::ReplayMode,
    /// Serialized STARK proof.
    pub proof: ZkAceProof,
    /// Public inputs matching the proof.
    pub public_inputs: ZkAcePublicInputs,
    /// Revealed nonce (required for NonceRegistry mode).
    pub revealed_nonce: Option<u64>,
    /// Caller-supplied idempotency key.
    pub request_id: String,
}

/// The outcome of an authorization attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizeResponse {
    pub decision: Decision,
    pub error_code: Option<ErrorCode>,
    pub message: String,
    pub request_id: String,
}

/// Authorization decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Approved,
    Denied,
}

/// Machine-readable error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidProof,
    ReplayDetected,
    MissingNonce,
    NonceMismatch,
    PayloadMismatch,
    InternalError,
}

// ---------------------------------------------------------------------------
// Idempotency store
// ---------------------------------------------------------------------------

/// Trait for request idempotency storage.
pub trait IdempotencyStore {
    fn get(&self, fingerprint: &str) -> Option<AuthorizeResponse>;
    fn put(&mut self, fingerprint: String, response: AuthorizeResponse);
}

/// In-memory idempotency store.
#[derive(Debug, Default)]
pub struct InMemoryIdempotencyStore {
    map: HashMap<String, AuthorizeResponse>,
}

impl InMemoryIdempotencyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdempotencyStore for InMemoryIdempotencyStore {
    fn get(&self, fingerprint: &str) -> Option<AuthorizeResponse> {
        self.map.get(fingerprint).cloned()
    }

    fn put(&mut self, fingerprint: String, response: AuthorizeResponse) {
        self.map.insert(fingerprint, response);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a SHA-256 fingerprint over the request content.
pub fn build_request_fingerprint(
    payload: &[u8],
    replay_mode: crate::stwo::types::ReplayMode,
    public_inputs: &ZkAcePublicInputs,
    nonce: Option<u64>,
    proof: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.update(match replay_mode {
        crate::stwo::types::ReplayMode::NonceRegistry => [0u8],
        crate::stwo::types::ReplayMode::NullifierSet => [1u8],
    });
    for element in public_inputs.to_elements() {
        hasher.update(element.0.to_le_bytes());
    }
    if let Some(n) = nonce {
        hasher.update(n.to_le_bytes());
    }
    hasher.update(proof);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Compute tx_hash = SHA-256(payload) converted to [M31; 9] (lossless).
pub fn tx_hash_from_payload(payload: &[u8]) -> [M31; ELEMENTS_PER_BYTES32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    bytes_to_elements(&arr)
}

// ---------------------------------------------------------------------------
// hex encoding helper (vendored to avoid extra dep on hex crate)
// ---------------------------------------------------------------------------

mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

// ---------------------------------------------------------------------------
// AuthorizationHandler
// ---------------------------------------------------------------------------

pub struct AuthorizationHandler<N: NonceRegistryStore, U: NullifierSetStore, I: IdempotencyStore> {
    replay_guard: ReplayGuard<N, U>,
    idempotency: I,
}

impl<N: NonceRegistryStore, U: NullifierSetStore, I: IdempotencyStore>
    AuthorizationHandler<N, U, I>
{
    pub fn new(nonce_registry: N, nullifier_set: U, idempotency: I) -> Self {
        Self {
            replay_guard: ReplayGuard::new(nonce_registry, nullifier_set),
            idempotency,
        }
    }

    pub fn handle_authorize(&mut self, req: &AuthorizeRequest) -> AuthorizeResponse {
        // 1. Idempotency check.
        let fingerprint = build_request_fingerprint(
            &req.tx_payload,
            req.replay_mode,
            &req.public_inputs,
            req.revealed_nonce,
            &req.proof,
        );
        if let Some(cached) = self.idempotency.get(&fingerprint) {
            return cached;
        }

        // 2. Verify that tx_payload matches the public input tx_hash.
        let computed_tx_hash = tx_hash_from_payload(&req.tx_payload);
        if computed_tx_hash != req.public_inputs.tx_hash {
            let resp = AuthorizeResponse {
                decision: Decision::Denied,
                error_code: Some(ErrorCode::PayloadMismatch),
                message: "tx_hash does not match payload".to_string(),
                request_id: req.request_id.clone(),
            };
            self.idempotency.put(fingerprint, resp.clone());
            return resp;
        }

        // 3. Verify the STARK proof.
        match verifier::verify(&req.proof, &req.public_inputs, req.replay_mode) {
            Ok(true) => {}
            Ok(false) => {
                let resp = AuthorizeResponse {
                    decision: Decision::Denied,
                    error_code: Some(ErrorCode::InvalidProof),
                    message: "proof verification returned false".to_string(),
                    request_id: req.request_id.clone(),
                };
                self.idempotency.put(fingerprint, resp.clone());
                return resp;
            }
            Err(e) => {
                let resp = AuthorizeResponse {
                    decision: Decision::Denied,
                    error_code: Some(ErrorCode::InvalidProof),
                    message: format!("proof verification failed: {e}"),
                    request_id: req.request_id.clone(),
                };
                self.idempotency.put(fingerprint, resp.clone());
                return resp;
            }
        }

        // 4. Replay prevention.
        let replay_result = match req.replay_mode {
            crate::stwo::types::ReplayMode::NonceRegistry => {
                let nonce = match req.revealed_nonce {
                    Some(n) => n,
                    None => {
                        let resp = AuthorizeResponse {
                            decision: Decision::Denied,
                            error_code: Some(ErrorCode::MissingNonce),
                            message: "nonce required for NonceRegistry mode".to_string(),
                            request_id: req.request_id.clone(),
                        };
                        self.idempotency.put(fingerprint, resp.clone());
                        return resp;
                    }
                };
                let expected_rp_com =
                    compute_rp_com_nonce(&req.public_inputs.id_com, &u64_to_domain_elements(nonce));
                if expected_rp_com != req.public_inputs.rp_com {
                    let resp = AuthorizeResponse {
                        decision: Decision::Denied,
                        error_code: Some(ErrorCode::NonceMismatch),
                        message: "revealed_nonce does not match the proof-bound rp_com".to_string(),
                        request_id: req.request_id.clone(),
                    };
                    self.idempotency.put(fingerprint, resp.clone());
                    return resp;
                }
                self.replay_guard
                    .check_and_record_nonce(&req.public_inputs.id_com, nonce)
            }
            crate::stwo::types::ReplayMode::NullifierSet => self
                .replay_guard
                .check_and_record_nullifier(&req.public_inputs.rp_com),
        };

        if let Err(e) = replay_result {
            let resp = AuthorizeResponse {
                decision: Decision::Denied,
                error_code: Some(ErrorCode::ReplayDetected),
                message: format!("replay check failed: {e}"),
                request_id: req.request_id.clone(),
            };
            self.idempotency.put(fingerprint, resp.clone());
            return resp;
        }

        // 5. All checks passed.
        let resp = AuthorizeResponse {
            decision: Decision::Approved,
            error_code: None,
            message: "authorized".to_string(),
            request_id: req.request_id.clone(),
        };
        self.idempotency.put(fingerprint, resp.clone());
        resp
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;

    #[test]
    fn tx_hash_from_payload_deterministic() {
        let payload = b"hello world";
        let h1 = tx_hash_from_payload(payload);
        let h2 = tx_hash_from_payload(payload);
        assert_eq!(h1, h2);
    }

    #[test]
    fn tx_hash_differs_for_different_payloads() {
        let h1 = tx_hash_from_payload(b"payload1");
        let h2 = tx_hash_from_payload(b"payload2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn fingerprint_deterministic() {
        let pi = tx_hash_from_payload(b"pay");
        let public_inputs = ZkAcePublicInputs {
            id_com: [pi[0]; 8],
            tx_hash: pi,
            domain: [pi[0]; 3],
            target: [pi[1]; 8],
            rp_com: [pi[2]; 8],
        };
        let f1 = build_request_fingerprint(
            b"pay",
            crate::stwo::types::ReplayMode::NonceRegistry,
            &public_inputs,
            Some(42),
            b"proof",
        );
        let f2 = build_request_fingerprint(
            b"pay",
            crate::stwo::types::ReplayMode::NonceRegistry,
            &public_inputs,
            Some(42),
            b"proof",
        );
        assert_eq!(f1, f2);
    }

    #[test]
    fn fingerprint_differs_with_nonce() {
        let pi = tx_hash_from_payload(b"pay");
        let public_inputs = ZkAcePublicInputs {
            id_com: [pi[0]; 8],
            tx_hash: pi,
            domain: [pi[0]; 3],
            target: [pi[1]; 8],
            rp_com: [pi[2]; 8],
        };
        let f1 = build_request_fingerprint(
            b"pay",
            crate::stwo::types::ReplayMode::NonceRegistry,
            &public_inputs,
            Some(1),
            b"proof",
        );
        let f2 = build_request_fingerprint(
            b"pay",
            crate::stwo::types::ReplayMode::NonceRegistry,
            &public_inputs,
            Some(2),
            b"proof",
        );
        assert_ne!(f1, f2);
    }

    #[test]
    fn idempotency_store_basic() {
        let mut store = InMemoryIdempotencyStore::new();
        assert!(store.get("key1").is_none());
        let resp = AuthorizeResponse {
            decision: Decision::Approved,
            error_code: None,
            message: "ok".to_string(),
            request_id: "r1".to_string(),
        };
        store.put("key1".to_string(), resp.clone());
        assert_eq!(store.get("key1"), Some(resp));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex::encode([0x00, 0xff]), "00ff");
    }

    fn make_request(payload: &[u8], nonce: u64, request_id: &str) -> AuthorizeRequest {
        use crate::stwo::native::commitment::compute_public_inputs;
        use crate::stwo::prover::prove;
        use crate::stwo::types::{DerivationContext, ReplayMode, ZkAceWitness};

        let witness = ZkAceWitness {
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
            nonce: u64_to_domain_elements(nonce),
        };
        let tx_hash = tx_hash_from_payload(payload);
        let domain = [M31(1), M31(0), M31(0)];
        let public_inputs =
            compute_public_inputs(&witness, &tx_hash, &domain, ReplayMode::NonceRegistry);
        let proof = prove(&witness, &public_inputs, ReplayMode::NonceRegistry).unwrap();

        AuthorizeRequest {
            tx_payload: payload.to_vec(),
            replay_mode: ReplayMode::NonceRegistry,
            proof,
            public_inputs,
            revealed_nonce: Some(nonce),
            request_id: request_id.to_string(),
        }
    }

    #[test]
    fn handle_authorize_approves_valid_request() {
        let mut handler = AuthorizationHandler::new(
            crate::replay::InMemoryNonceRegistry::new(),
            crate::replay::InMemoryNullifierSet::new(),
            InMemoryIdempotencyStore::new(),
        );
        let req = make_request(b"payload-1", 7, "req-1");
        let resp = handler.handle_authorize(&req);
        assert_eq!(resp.decision, Decision::Approved);
        assert_eq!(resp.error_code, None);
    }

    #[test]
    fn handle_authorize_rejects_nonce_mismatch() {
        let mut handler = AuthorizationHandler::new(
            crate::replay::InMemoryNonceRegistry::new(),
            crate::replay::InMemoryNullifierSet::new(),
            InMemoryIdempotencyStore::new(),
        );
        let mut req = make_request(b"payload-1", 7, "req-1");
        req.revealed_nonce = Some(8);
        let resp = handler.handle_authorize(&req);
        assert_eq!(resp.decision, Decision::Denied);
        assert_eq!(resp.error_code, Some(ErrorCode::NonceMismatch));
    }

    #[test]
    fn handle_authorize_rejects_replayed_nonce_on_new_payload() {
        let mut handler = AuthorizationHandler::new(
            crate::replay::InMemoryNonceRegistry::new(),
            crate::replay::InMemoryNullifierSet::new(),
            InMemoryIdempotencyStore::new(),
        );

        let req1 = make_request(b"payload-1", 7, "req-1");
        let req2 = make_request(b"payload-2", 7, "req-2");

        let resp1 = handler.handle_authorize(&req1);
        assert_eq!(resp1.decision, Decision::Approved);

        let resp2 = handler.handle_authorize(&req2);
        assert_eq!(resp2.decision, Decision::Denied);
        assert_eq!(resp2.error_code, Some(ErrorCode::ReplayDetected));
    }
}
