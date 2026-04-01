include!("src/constants.rs");

fn main() {
    let out = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("OUT_DIR not set"),
    );

    // Generate a C header with the INST instantiation list so the .cu files
    // don't need to be touched when MAX_SUFFIX_LEN changes.
    let inst_calls: String = (1..=MAX_SUFFIX_LEN)
        .map(|n| format!("INST({n})"))
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(out.join("pow_inst.h"), inst_calls)
        .expect("failed to write pow_inst.h");

    // Only compile CUDA kernels when the `cuda` feature is enabled.
    if std::env::var("CARGO_FEATURE_CUDA").is_err() {
        return;
    }

    let cuda_dir = std::path::PathBuf::from("cuda");

    for algo in ["sha256", "sha1"] {
        let src = cuda_dir.join(format!("{algo}_pow.cu"));
        let ptx = out.join(format!("{algo}_pow.ptx"));

        let status = std::process::Command::new("nvcc")
            .args([
                "-ptx",
                "-O3",
                "-arch=native",
                "--use_fast_math",
                &format!("-I{}", out.display()),
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
    println!("cargo:rerun-if-changed=src/constants.rs");
}
