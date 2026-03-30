use criterion::{criterion_group, criterion_main, Criterion};
use pow_solver::hash_pow::{self, BitPosition, HashAlgo};

// ---------------------------------------------------------------------------
// Throughput benchmarks: fixed work, deterministic, low variance.
// These are the primary benchmarks for measuring the effect of optimizations
// (e.g. AVX512, intrinsics) on the hot path.
// ---------------------------------------------------------------------------

fn bench_throughput(c: &mut Criterion) {
    let prefix = b"ThroughputBench!";
    let n = 100_000u64;

    let mut group = c.benchmark_group("throughput");
    group.sample_size(50);

    group.bench_function("sha256/leading/100k", |b| {
        b.iter(|| {
            hash_pow::hash_throughput::<sha2::Sha256>(prefix, n, 20, true)
        })
    });

    group.bench_function("sha256/trailing/100k", |b| {
        b.iter(|| {
            hash_pow::hash_throughput::<sha2::Sha256>(prefix, n, 20, false)
        })
    });

    group.bench_function("sha1/leading/100k", |b| {
        b.iter(|| {
            hash_pow::hash_throughput::<sha1::Sha1>(prefix, n, 20, true)
        })
    });

    group.finish();
}

fn bench_zero_check(c: &mut Criterion) {
    let hash_16_leading = [0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
                           0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
                           0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
                           0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45];

    let mut group = c.benchmark_group("zero_check");
    group.sample_size(1000);

    group.bench_function("leading/pass", |b| {
        b.iter(|| hash_pow::count_leading_zero_bits(&hash_16_leading))
    });

    group.bench_function("leading/fail_first_byte", |b| {
        let hash = [0x01u8; 32];
        b.iter(|| hash_pow::count_leading_zero_bits(&hash))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Brute-force benchmarks: realistic end-to-end, higher variance.
// Useful for overall system-level comparison but not for isolating
// micro-optimizations. Use throughput benchmarks for that.
// ---------------------------------------------------------------------------

fn bench_bruteforce(c: &mut Criterion) {
    let prefix = b"BenchPrefix12345";

    let mut group = c.benchmark_group("bruteforce");
    group.sample_size(20);

    let charset_printable = hash_pow::parse_charset("printable").unwrap();
    group.bench_function("sha256/leading/printable/20bits/1t", |b| {
        b.iter(|| {
            hash_pow::bruteforce(prefix, HashAlgo::Sha256, 20, BitPosition::Leading, &charset_printable, Some(1))
                .expect("should find solution")
        })
    });

    let charset_bytes = hash_pow::parse_charset("bytes").unwrap();
    group.bench_function("sha256/trailing/bytes/20bits/1t", |b| {
        b.iter(|| {
            hash_pow::bruteforce(prefix, HashAlgo::Sha256, 20, BitPosition::Trailing, &charset_bytes, Some(1))
                .expect("should find solution")
        })
    });

    let charset_hex = hash_pow::parse_charset("hex").unwrap();
    group.bench_function("sha1/leading/hex/20bits/1t", |b| {
        b.iter(|| {
            hash_pow::bruteforce(b"1:20:260330:bench@example.com::salt123:", HashAlgo::Sha1, 20, BitPosition::Leading, &charset_hex, Some(1))
                .expect("should find solution")
        })
    });

    group.bench_function("sha256/leading/printable/20bits/all_threads", |b| {
        b.iter(|| {
            hash_pow::bruteforce(prefix, HashAlgo::Sha256, 20, BitPosition::Leading, &charset_printable, None)
                .expect("should find solution")
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_throughput,
    bench_zero_check,
    bench_bruteforce,
);
criterion_main!(benches);
