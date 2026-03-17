use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ace::groth16::circuit::ZkAceCircuit;
use zk_ace::groth16::commitment::compute_public_inputs;
use zk_ace::groth16::prover;
use zk_ace::groth16::types::DerivationContext;
use zk_ace::types::ReplayMode;

use ark_bn254::Fr;

fn test_params() -> (Fr, Fr, DerivationContext, Fr, Fr, Fr) {
    let rev = Fr::from(42u64);
    let salt = Fr::from(100u64);
    let ctx = DerivationContext {
        alg_id: Fr::from(0u64),
        domain: Fr::from(1u64),
        index: Fr::from(0u64),
    };
    let nonce = Fr::from(7u64);
    let tx_hash = Fr::from(999u64);
    let domain = Fr::from(1u64);
    (rev, salt, ctx, nonce, tx_hash, domain)
}

fn make_circuit_and_pi(
    mode: ReplayMode,
) -> (ZkAceCircuit, zk_ace::groth16::commitment::Groth16PublicInputs) {
    let (rev, salt, ctx, nonce, tx_hash, domain) = test_params();
    let pi = compute_public_inputs(&rev, &salt, &ctx, &nonce, &tx_hash, &domain, mode);
    let circuit = ZkAceCircuit {
        rev: Some(rev),
        salt: Some(salt),
        alg_id: Some(ctx.alg_id),
        domain_ctx: Some(ctx.domain),
        index: Some(ctx.index),
        nonce: Some(nonce),
        id_com: Some(pi.id_com),
        tx_hash: Some(pi.tx_hash),
        domain: Some(pi.domain),
        target: Some(pi.target),
        rp_com: Some(pi.rp_com),
        mode,
    };
    (circuit, pi)
}

fn bench_groth16_setup(c: &mut Criterion) {
    // Warm up the cached keys first
    let _ = prover::get_keys(ReplayMode::NonceRegistry);
    let _ = prover::get_keys(ReplayMode::NullifierSet);

    // Setup is cached via OnceLock, so this measures the cache hit path.
    // To measure cold setup, we'd need to bypass the cache.
    // Instead, report the initial setup time via a one-shot measurement.
    println!("\n=== Groth16 Setup (one-shot, cached via OnceLock) ===");
    println!("  Keys are generated once and cached for the process lifetime.");

    c.bench_function("groth16_setup_cache_hit", |b| {
        b.iter(|| {
            let _ = prover::get_keys(ReplayMode::NonceRegistry);
        });
    });
}

fn bench_groth16_prove(c: &mut Criterion) {
    // Ensure keys are cached before benchmarking prove
    let _ = prover::get_keys(ReplayMode::NonceRegistry);
    let _ = prover::get_keys(ReplayMode::NullifierSet);

    let mut group = c.benchmark_group("groth16_prove");
    for mode in [ReplayMode::NonceRegistry, ReplayMode::NullifierSet] {
        let label = match mode {
            ReplayMode::NonceRegistry => "nonce_registry",
            ReplayMode::NullifierSet => "nullifier_set",
        };
        group.bench_with_input(BenchmarkId::new("prove", label), &(), |b, _| {
            b.iter(|| {
                let (circuit, _pi) = make_circuit_and_pi(mode);
                prover::prove(circuit, mode).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_groth16_verify(c: &mut Criterion) {
    let _ = prover::get_keys(ReplayMode::NonceRegistry);
    let _ = prover::get_keys(ReplayMode::NullifierSet);

    let mut group = c.benchmark_group("groth16_verify");
    for mode in [ReplayMode::NonceRegistry, ReplayMode::NullifierSet] {
        let label = match mode {
            ReplayMode::NonceRegistry => "nonce_registry",
            ReplayMode::NullifierSet => "nullifier_set",
        };
        let (circuit, pi) = make_circuit_and_pi(mode);
        let proof_bytes = prover::prove(circuit, mode).unwrap();
        group.bench_with_input(BenchmarkId::new("verify", label), &(), |b, _| {
            b.iter(|| prover::verify(&proof_bytes, &pi, mode).unwrap());
        });
    }
    group.finish();
}

fn bench_groth16_proof_size(c: &mut Criterion) {
    let (circuit_nonce, _) = make_circuit_and_pi(ReplayMode::NonceRegistry);
    let proof_nonce = prover::prove(circuit_nonce, ReplayMode::NonceRegistry).unwrap();

    let (circuit_null, _) = make_circuit_and_pi(ReplayMode::NullifierSet);
    let proof_null = prover::prove(circuit_null, ReplayMode::NullifierSet).unwrap();

    println!("\n=== Groth16 Proof Size ===");
    println!("  NonceRegistry: {} bytes", proof_nonce.len());
    println!("  NullifierSet:  {} bytes", proof_null.len());

    c.bench_function("groth16_proof_size_report", |b| {
        b.iter(|| proof_nonce.len() + proof_null.len());
    });
}

criterion_group!(
    benches,
    bench_groth16_setup,
    bench_groth16_prove,
    bench_groth16_verify,
    bench_groth16_proof_size
);
criterion_main!(benches);
