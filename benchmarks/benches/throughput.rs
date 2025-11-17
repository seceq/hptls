//! Throughput benchmarks.

use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_throughput(_c: &mut Criterion) {
    // Note: Throughput benchmarks are pending implementation.
    // Planned measurements:
    // - Record encryption/decryption throughput
    // - Data transfer throughput
    // - Effect of kTLS on throughput
}

criterion_group!(benches, benchmark_throughput);
criterion_main!(benches);
