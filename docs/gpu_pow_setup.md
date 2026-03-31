# GPU Proof-of-Work Solver — Build Setup

The GPU backend compiles SHA-256 and SHA-1 CUDA kernels to PTX at `cargo build` time and embeds them in the extension module. At runtime there is zero JIT penalty — the PTX is loaded directly into the driver.

## Prerequisites

| Requirement | Notes |
|---|---|
| NVIDIA GPU (Ampere / Ada or newer recommended) | Must be present at build time (nvcc `-arch=native`) |
| CUDA Toolkit ≥ 12 | Provides `nvcc`; [download](https://developer.nvidia.com/cuda-downloads) |
| NVIDIA driver ≥ 525 | Shipped with the OS or downloaded from NVIDIA |
| Rust toolchain (stable) | `rustup update stable` |
| `maturin` | `pip install maturin` |

Verify nvcc is on PATH:
```sh
nvcc --version
```

## Build

From the repository root:
```sh
cd src/doglib_rs
maturin develop --features cuda
```

This will:
1. Run `build.rs`, which invokes `nvcc -ptx -O3 -arch=native --use_fast_math` on each `.cu` kernel.
2. Compile the Rust crate with cudarc and embed the PTX binaries.
3. Install the Python extension into the current virtualenv.

For a release build (recommended for benchmarking):
```sh
maturin develop --release --features cuda
```

## Verify

```python
import hashlib
from doglib_rs import pow_solver

# SHA-256, 20 leading zero bits
suf = pow_solver.hash_bruteforce(b"TestPrefix", "sha256", 20, "leading", "printable")
assert int.from_bytes(hashlib.sha256(b"TestPrefix" + suf).digest()[:3], "big") >> 4 == 0
print("SHA-256 OK:", suf)

# SHA-1 (hashcash style), 20 leading zero bits
suf1 = pow_solver.hash_bruteforce(b"1:20:250101::salt:", "sha1", 20, "leading", "hex")
assert int.from_bytes(hashlib.sha1(b"1:20:250101::salt:" + suf1).digest()[:3], "big") >> 4 == 0
print("SHA-1 OK:", suf1)
```

## Fallback behaviour

If the `cuda` feature is not enabled (default), the crate is built without cudarc and GPU code is not compiled. `hash_bruteforce` falls back to the multi-threaded CPU implementation automatically — no code changes required.

```sh
# CPU-only build (default):
maturin develop
```

## WSL2: `CUDA_ERROR_NO_DEVICE` at runtime

On WSL2, Ubuntu ships a stub `libcuda.so` in `/usr/lib/x86_64-linux-gnu/` that always reports no devices. The real driver library lives in `/usr/lib/wsl/lib/`. Because the stub comes first in the standard library search path for unversioned `.so` lookups, cudarc loads the wrong one.

Fix — add the WSL lib path to `LD_LIBRARY_PATH`:

```sh
echo 'export LD_LIBRARY_PATH=/usr/lib/wsl/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

Verify it's fixed:
```sh
python3 -c "from doglib_rs import pow_solver; print(pow_solver.backend_info())"
# should print: cuda
```

## Notes

- `-arch=native` targets the GPU present at build time. To cross-compile for a specific architecture, replace with e.g. `-arch=sm_89` (Ada Lovelace).
- The `.ptx` files are written to Cargo's `OUT_DIR` (inside `target/`) and are not committed to the repository.
- `nvcc` must be on `PATH` when building with `--features cuda`; if it is not found, the build fails immediately with a clear error message.
