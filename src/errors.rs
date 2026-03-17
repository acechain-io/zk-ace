use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkAceError {
    #[error("Invalid REV length: expected {expected} bytes, got {actual} bytes")]
    InvalidRevLength { expected: usize, actual: usize },

    #[error("Proof generation failed: {0}")]
    ProvingFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Witness construction error: {0}")]
    WitnessError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),

    #[error("Aggregated proof verification failed: {0}")]
    AggregatedVerificationFailed(String),
}
