fn main() {
    // Only compile CUDA kernels when the `cuda` feature is enabled.
    if std::env::var("CARGO_FEATURE_CUDA").is_err() {
        return;
    }

    let out = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("OUT_DIR not set"),
    );
    let cuda_dir = std::path::PathBuf::from("cuda");

    for algo in ["sha256", "sha1"] {
        let src = cuda_dir.join(format!("{algo}_pow.cu"));
        let ptx = out.join(format!("{algo}_pow.ptx"));

        let status = std::process::Command::new("nvcc")
            .args([
                "-ptx",
                "-O3",
                "-arch=native",          // target the GPU present at build time
                "--use_fast_math",
                "-o",
                ptx.to_str().unwrap(),
                src.to_str().unwrap(),
            ])
            .status()
            .expect(
                "nvcc not found — install the CUDA Toolkit and ensure nvcc is on PATH"
            );

        assert!(
            status.success(),
            "nvcc failed to compile cuda/{algo}_pow.cu"
        );

        println!("cargo:rerun-if-changed=cuda/{algo}_pow.cu");
    }

    println!("cargo:rerun-if-changed=build.rs");
}
