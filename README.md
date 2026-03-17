# ZK-ACE: Zero-Knowledge Authorization for Atomic Cryptographic Entities

ZK-ACE replaces on-chain digital signature objects with succinct zero-knowledge proofs of identity-bound authorization. It is designed to solve the **signature bloat problem** introduced by post-quantum cryptography (PQC) migration in blockchain systems.

## The Problem

NIST post-quantum signature standards (ML-DSA, SLH-DSA) produce signatures 10-100x larger than classical ECDSA. Placing these directly on-chain degrades throughput, inflates gas costs, and strains storage.

| Scheme | Signature | Public Key | On-Chain Total |
|--------|-----------|------------|----------------|
| ECDSA (secp256k1) | 64 B | 33 B | **~97 B** |
| Schnorr (BIP-340) | 64 B | 32 B | **~96 B** |
| Ed25519 | 64 B | 32 B | **~96 B** |
| ML-DSA-65 (Dilithium) | 3,309 B | 1,952 B | **~5,261 B** |
| SLH-DSA-128s (SPHINCS+) | 7,856 B | 32 B | **~7,888 B** |
| Falcon-512 | 666 B | 897 B | **~1,563 B** |

## The Solution

ZK-ACE proves authorization knowledge inside a minimal ZK circuit and submits only a constant-size proof on-chain. Two pluggable backends are provided:

| Backend | Proof Size | PQ-Secure | On-Chain per tx | Setup |
|---------|-----------|-----------|-----------------|-------|
| **Stwo Circle STARK** (default) | ~105 KB | Yes | ~160 B (aggregated) | Transparent |
| **Groth16/BN254** | 128 B | No | ~288 B | Trusted |

### Compression Ratios vs. PQC Signatures (with STARK aggregation)

| PQC Scheme | On-Chain (Direct) | ZK-ACE (aggregated) | Compression |
|------------|-------------------|---------------------|-------------|
| ML-DSA-65 | 5,261 B | ~160 B | **32.9x** |
| SLH-DSA-128s | 7,888 B | ~160 B | **49.3x** |
| Falcon-512 | 1,563 B | ~160 B | **9.8x** |

> **Note:** With STARK backend, individual proofs (~105 KB) are aggregated per-block into a single batch proof. Per-transaction on-chain data is only the public inputs (~160 B).

## Architecture

ZK-ACE defines a 5-constraint circuit (C1-C5) using Poseidon hash:

| Constraint | Purpose | Formula |
|------------|---------|---------|
| C1 | Identity commitment | `id_com = H(REV \|\| salt \|\| domain)` |
| C2 | Deterministic derivation | `target = H(Derive(REV, Ctx))` |
| C3 | Authorization binding | `auth = H(REV \|\| Ctx \|\| tx_hash \|\| domain \|\| nonce)` |
| C4 | Replay prevention | `rp_com = H(id_com \|\| nonce)` or `H(auth \|\| domain)` |
| C5 | Domain separation | `Ctx.domain == domain` |

**Private witness:** `(REV, salt, alg_id, domain, index, nonce)` — never leaves the prover.

**Public inputs:** `[id_com, tx_hash, domain, target, rp_com]` — verified on-chain.

### Backend Comparison

| Aspect | Stwo Circle STARK | Groth16/BN254 |
|--------|-------------------|---------------|
| Field | Mersenne-31 (M31) | BN254 Fr (~254-bit) |
| Hash | Poseidon2 (width=16, x^5) | Poseidon (width=3, x^5) |
| Proof system | FRI + AIR | R1CS + pairing |
| Constraints | ~240 AIR | ~1,200 R1CS |
| Proof size | ~105-112 KB | 128 B |
| Prove time | ~21 ms | ~44 ms |
| Verify time | ~1.1 ms | ~1.5 ms |
| PQ-secure | Yes (hash-based) | No (elliptic curve) |
| Setup | Transparent | Trusted (MPC ceremony) |

> Benchmarked on Apple Silicon (M-series). Times include circuit witness generation.

### Replay Prevention Modes

| Mode | Model | Formula | Use Case |
|------|-------|---------|----------|
| NonceRegistry | Account-style | `H(id_com \|\| nonce)` | Ethereum, Solana |
| NullifierSet | Privacy-style | `H(auth \|\| domain)` | Zcash, Aztec |

Each mode compiles into a separate circuit with its own proving/verifying key pair.

## Project Structure

```
zk-ace/
├── src/
│   ├── lib.rs              # Module declarations, feature gates, re-exports
│   ├── traits.rs           # ZkAceEngine trait (backend abstraction)
│   ├── types.rs            # Core byte-based types (Witness, PublicInputs, ReplayMode)
│   ├── errors.rs           # Error types
│   ├── aggregation.rs      # Backend-agnostic proof aggregation
│   ├── api.rs              # High-level prove/verify API
│   ├── bridge.rs           # ACE-GF wallet integration
│   ├── replay.rs           # Replay prevention (NonceRegistry, NullifierSet)
│   ├── stwo/               # Stwo Circle STARK backend (feature: stwo)
│   │   ├── native/         # Off-circuit Poseidon2, derive, commitment
│   │   ├── air/            # AIR constraints (schedule, preprocessed)
│   │   ├── trace.rs        # Execution trace generation
│   │   ├── prover.rs       # STARK prover
│   │   └── verifier.rs     # STARK verifier
│   └── groth16/            # Groth16/BN254 backend (feature: groth16)
│       ├── hash.rs         # Poseidon over BN254 Fr
│       ├── derive.rs       # Key derivation
│       ├── commitment.rs   # C1-C5 native computation
│       ├── circuit.rs      # R1CS ConstraintSynthesizer
│       ├── prover.rs       # Groth16 setup + prove
│       └── verifier.rs     # Groth16 verify
├── benches/
│   └── prove_verify_bench.rs
└── contracts/
    └── ZkAceVerifier.sol   # On-chain Solidity verifier
```

## Building and Testing

```bash
# Default backend (Stwo STARK, post-quantum secure)
cargo test

# Groth16 backend only
cargo test --features groth16 --no-default-features

# Both backends
cargo test --all-features

# Benchmarks
cargo bench
```

Requires Rust nightly (see `rust-toolchain.toml`).

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `stwo` | Yes | Circle STARK backend (post-quantum) |
| `groth16` | No | Groth16/BN254 backend (compact proofs) |

### REV Input Boundary

- This crate accepts REV only as 32-byte raw bytes.
- Mnemonic parsing (e.g., BIP39) is intentionally out of scope and must happen outside this crate.

## Dependencies

| Backend | Key Dependencies |
|---------|-----------------|
| Stwo | [stwo](https://github.com/starkware-libs/stwo) 2.2.0, stwo-constraint-framework |
| Groth16 | [arkworks](https://github.com/arkworks-rs) 0.4 (ark-bn254, ark-groth16, ark-r1cs-std) |
| Core | serde, sha2, bincode, thiserror |

## Limitations

- **Groth16/BN254 is not post-quantum.** Use the Stwo STARK backend for PQ security.
- **STARK proofs are large individually.** The ~105 KB proof size requires mandatory per-block aggregation; individual proofs never go on-chain.
- **Trusted setup (Groth16 only).** Groth16 requires a per-circuit trusted setup. The reference implementation uses a deterministic seed; production deployments must use MPC ceremonies.

## License

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE).
