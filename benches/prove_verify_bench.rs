use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stwo::core::fields::m31::M31;
use zk_ace::stwo::native::commitment::compute_public_inputs;
use zk_ace::stwo::prover::prove;
use zk_ace::stwo::types::{
    DerivationContext, ReplayMode, ZkAceWitness, ELEMENTS_PER_BYTES32, ELEMENTS_PER_DOMAIN,
};
use zk_ace::stwo::verifier::verify;

fn test_witness() -> ZkAceWitness {
    ZkAceWitness {
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
    }
}

fn test_tx_hash() -> [M31; ELEMENTS_PER_BYTES32] {
    [
        M31(999),
        M31(998),
        M31(997),
        M31(996),
        M31(995),
        M31(994),
        M31(993),
        M31(992),
        M31(0),
    ]
}

fn test_domain() -> [M31; ELEMENTS_PER_DOMAIN] {
    [M31(1), M31(0), M31(0)]
}

fn bench_prove(c: &mut Criterion) {
    let w = test_witness();
    let tx = test_tx_hash();
    let domain = test_domain();

    let mut group = c.benchmark_group("stark_prove");
    for mode in [ReplayMode::NonceRegistry, ReplayMode::NullifierSet] {
        let label = match mode {
            ReplayMode::NonceRegistry => "nonce_registry",
            ReplayMode::NullifierSet => "nullifier_set",
        };
        let pi = compute_public_inputs(&w, &tx, &domain, mode);
        group.bench_with_input(BenchmarkId::new("prove", label), &(), |b, _| {
            b.iter(|| prove(&w, &pi, mode).unwrap());
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let w = test_witness();
    let tx = test_tx_hash();
    let domain = test_domain();

    let mut group = c.benchmark_group("stark_verify");
    for mode in [ReplayMode::NonceRegistry, ReplayMode::NullifierSet] {
        let label = match mode {
            ReplayMode::NonceRegistry => "nonce_registry",
            ReplayMode::NullifierSet => "nullifier_set",
        };
        let pi = compute_public_inputs(&w, &tx, &domain, mode);
        let proof = prove(&w, &pi, mode).unwrap();
        group.bench_with_input(BenchmarkId::new("verify", label), &(), |b, _| {
            b.iter(|| verify(&proof, &pi, mode).unwrap());
        });
    }
    group.finish();
}

fn bench_proof_size(c: &mut Criterion) {
    let w = test_witness();
    let tx = test_tx_hash();
    let domain = test_domain();

    let pi_nonce = compute_public_inputs(&w, &tx, &domain, ReplayMode::NonceRegistry);
    let proof_nonce = prove(&w, &pi_nonce, ReplayMode::NonceRegistry).unwrap();

    let pi_null = compute_public_inputs(&w, &tx, &domain, ReplayMode::NullifierSet);
    let proof_null = prove(&w, &pi_null, ReplayMode::NullifierSet).unwrap();

    println!("\n=== Proof Size ===");
    println!(
        "  NonceRegistry: {} bytes ({:.1} KB)",
        proof_nonce.len(),
        proof_nonce.len() as f64 / 1024.0
    );
    println!(
        "  NullifierSet:  {} bytes ({:.1} KB)",
        proof_null.len(),
        proof_null.len() as f64 / 1024.0
    );

    // Dummy bench so criterion doesn't complain
    c.bench_function("proof_size_report", |b| {
        b.iter(|| proof_nonce.len() + proof_null.len());
    });
}

criterion_group!(benches, bench_prove, bench_verify, bench_proof_size);
criterion_main!(benches);
