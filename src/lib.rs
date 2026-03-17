#![feature(array_chunks, iter_array_chunks, portable_simd, slice_ptr_get)]

// Core modules (backend-agnostic)
pub mod aggregation;
pub mod errors;
pub mod traits;
pub mod types;

// Stwo Circle STARK backend (post-quantum secure)
#[cfg(feature = "stwo")]
pub mod stwo;

// Groth16/BN254 backend (compact proofs, not post-quantum)
#[cfg(feature = "groth16")]
pub mod groth16;

// Higher-level modules (feature-gated to active backend)
#[cfg(feature = "stwo")]
pub mod api;
#[cfg(feature = "stwo")]
pub mod bridge;
#[cfg(feature = "stwo")]
pub mod replay;

// Re-exports
pub use errors::ZkAceError;
pub use traits::ZkAceEngine;
pub use types::{PublicInputs, ReplayMode, Witness};

#[cfg(feature = "stwo")]
pub use stwo::StwoEngine;

#[cfg(feature = "groth16")]
pub use groth16::Groth16Engine;
