/// GPU throughput benchmark — deterministic, low-variance.
///
/// Instead of timing random solve attempts, fires a fixed number of kernel
/// launches with an impossible difficulty (bits=255) so every thread always
/// processes the full BATCH.  Total candidates / wall-time = true throughput
/// with no search randomness.
///
/// Usage (from the pow_solver crate root):
///   LD_LIBRARY_PATH=/usr/lib/wsl/lib \
///   cargo run --release --features cuda --example gpu_bench
///
/// Optional env vars:
///   GPU_BENCH_ALGO=sha256        algorithm: sha256 or sha1 (default sha256)
///   GPU_BENCH_CHARSET=printable  charset name (default printable)
///   GPU_BENCH_SUFFIX_LEN=4       suffix length to test (default 4)
///   GPU_BENCH_DURATION=10        target seconds to run (default 10)

#[cfg(feature = "cuda")]
fn main() {
    let algo = std::env::var("GPU_BENCH_ALGO")
        .unwrap_or_else(|_| "sha256".into());
    let charset_name = std::env::var("GPU_BENCH_CHARSET")
        .unwrap_or_else(|_| "printable".into());
    let suffix_len: usize = std::env::var("GPU_BENCH_SUFFIX_LEN")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(4);
    let target_secs: f64 = std::env::var("GPU_BENCH_DURATION")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(10.0);

    let charset = pow_solver::hash_pow::parse_charset(&charset_name)
        .expect("unknown charset");

    println!("GPU throughput benchmark");
    println!("  algo={algo}  charset={charset_name}  suffix_len={suffix_len}");
    println!("  target duration: {target_secs:.0}s");
    println!();

    // Warmup: triggers lazy GPU init (PTX load + function handle setup) and
    // lets the driver reach steady-state clocks before we start timing.
    // warmup=true fires one extra launch internally before the timed section.
    print!("  Warming up... ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let (_, warmup_time) = pow_solver::gpu::bench_throughput(
        &algo, &charset, suffix_len, 3, true,
    ).expect("GPU unavailable — check LD_LIBRARY_PATH on WSL2");
    println!("done ({:.2}s)", warmup_time.as_secs_f64());

    // Calibration: 5 launches to estimate per-launch time, then scale to
    // hit the target duration.
    let (cal_hashes, cal_time) = pow_solver::gpu::bench_throughput(
        &algo, &charset, suffix_len, 5, false,
    ).expect("GPU unavailable");
    let secs_per_launch = cal_time.as_secs_f64() / 5.0;
    let n_launches = ((target_secs / secs_per_launch) as u32).max(10);
    let cal_ghs = cal_hashes as f64 / cal_time.as_secs_f64() / 1e9;
    println!("  Calibration: {cal_ghs:.3} GH/s → running {n_launches} launches (~{target_secs:.0}s)");
    println!();

    // Timed run.
    let (total_hashes, elapsed) = pow_solver::gpu::bench_throughput(
        &algo, &charset, suffix_len, n_launches, false,
    ).expect("GPU unavailable");

    let elapsed_s = elapsed.as_secs_f64();
    let ghs       = total_hashes as f64 / elapsed_s / 1e9;
    let mhs       = ghs * 1000.0;

    println!("  Results");
    println!("  -------");
    println!("  launches : {n_launches}");
    println!("  hashes   : {:.3}B", total_hashes as f64 / 1e9);
    println!("  time     : {elapsed_s:.3}s");
    println!("  rate     : {ghs:.3} GH/s  ({mhs:.0} MH/s)");
}

#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("Build with --features cuda to run the GPU benchmark.");
    std::process::exit(1);
}
