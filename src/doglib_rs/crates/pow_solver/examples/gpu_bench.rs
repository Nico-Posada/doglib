/// GPU throughput benchmark.
///
/// Runs N bruteforces with randomly-generated prefixes, then reports the
/// mean time and estimated hash rate averaged across all runs.
///
/// Usage (from the pow_solver crate root):
///   LD_LIBRARY_PATH=/usr/lib/wsl/lib \
///   cargo run --release --features cuda --example gpu_bench
///
/// Optional env vars:
///   GPU_BENCH_BITS=<n>         difficulty in leading zero bits (default 24)
///   GPU_BENCH_ALGO=sha256      algorithm: sha256 or sha1 (default sha256)
///   GPU_BENCH_CHARSET=printable  charset name (default printable)
///   GPU_BENCH_RUNS=<n>         number of samples (default 10)

#[cfg(feature = "cuda")]
fn main() {
    let bits: u32 = std::env::var("GPU_BENCH_BITS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(24);
    let algo = std::env::var("GPU_BENCH_ALGO")
        .unwrap_or_else(|_| "sha256".into());
    let charset_name = std::env::var("GPU_BENCH_CHARSET")
        .unwrap_or_else(|_| "printable".into());
    let runs: usize = std::env::var("GPU_BENCH_RUNS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(10);

    let charset = pow_solver::hash_pow::parse_charset(&charset_name)
        .expect("unknown charset");

    // Warm up: force device init and module load before any timing.
    pow_solver::gpu::bruteforce(b"warmup", &algo, 0, "leading", &charset);

    println!("GPU benchmark: algo={algo} bits={bits} charset={charset_name} runs={runs}");
    println!("Expected attempts per run: ~{:.0}", 2f64.powi(bits as i32));
    println!();

    // Simple xorshift64 for prefix generation — no extra deps needed.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xdeadbeefcafe1234);
    let mut rng = seed | 1; // ensure non-zero
    let mut xorshift = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    let mut times = Vec::with_capacity(runs);

    for i in 0..runs {
        // 16-byte random prefix
        let prefix: Vec<u8> = (0..2).flat_map(|_| xorshift().to_le_bytes()).collect();

        let t0 = std::time::Instant::now();
        let result = pow_solver::gpu::bruteforce(&prefix, &algo, bits, "leading", &charset);
        let elapsed = t0.elapsed().as_secs_f64();

        match result {
            Some(suf) => {
                // Verify correctness
                let full: Vec<u8> = prefix.iter().chain(suf.iter()).copied().collect();
                let hash = if algo == "sha1" {
                    use sha1::Digest;
                    sha1::Sha1::digest(&full).to_vec()
                } else {
                    use sha2::Digest;
                    sha2::Sha256::digest(&full).to_vec()
                };
                let zeros = pow_solver::hash_pow::count_leading_zero_bits(&hash);
                let mhs = 2f64.powi(bits as i32) / elapsed / 1e6;
                println!("  run {:>2}: {:.3}s  ~{:.0} MH/s  [verified: {} bits]",
                    i + 1, elapsed, mhs, zeros);
                times.push(elapsed);
            }
            None => {
                eprintln!("  run {:>2}: GPU unavailable or no solution", i + 1);
                std::process::exit(1);
            }
        }
    }

    let mean = times.iter().sum::<f64>() / times.len() as f64;
    let min  = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max  = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let mean_mhs = 2f64.powi(bits as i32) / mean / 1e6;

    println!();
    println!("  mean: {:.3}s   min: {:.3}s   max: {:.3}s", mean, min, max);
    println!("  avg est. rate: {:.0} MH/s  ({:.3} GH/s)", mean_mhs, mean_mhs / 1000.0);
    println!("  (rates are estimated from expected 2^bits attempts; actual attempts are random)");
}

#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("Build with --features cuda to run the GPU benchmark.");
    std::process::exit(1);
}
