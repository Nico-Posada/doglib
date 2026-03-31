//! GPU-accelerated hash POW solver (cudarc backend).
//!
//! Compiled only when the `cuda` feature is enabled.  The PTX binaries are
//! compiled by `build.rs` at cargo-build time and embedded via `include_str!`.
//!
//! Entry point: [`bruteforce`].

#[cfg(feature = "cuda")]
mod inner {
    use std::sync::OnceLock;

    use cudarc::driver::safe::{CudaContext, CudaFunction, CudaSlice, LaunchConfig, PushKernelArg};
    use cudarc::nvrtc::Ptx;

    // ── PTX binaries (compiled by build.rs) ──────────────────────────────────
    const SHA256_PTX: &str = include_str!(concat!(env!("OUT_DIR"), "/sha256_pow.ptx"));
    const SHA1_PTX:   &str = include_str!(concat!(env!("OUT_DIR"), "/sha1_pow.ptx"));

    // ── launch geometry ───────────────────────────────────────────────────────
    const THREADS: u32 = 256;
    const BLOCKS:  u32 = 4096;
    const BATCH:   u64 = 64;
    const CHUNK:   u64 = (THREADS as u64) * (BLOCKS as u64) * BATCH; // 64M/launch

    // ── SHA IVs ───────────────────────────────────────────────────────────────
    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const SHA1_IV: [u32; 5] = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    ];

    // ── lazily-initialised GPU state ─────────────────────────────────────────
    struct GpuState {
        ctx:      std::sync::Arc<CudaContext>,
        sha256_f: CudaFunction,
        sha1_f:   CudaFunction,
    }

    static GPU: OnceLock<Option<GpuState>> = OnceLock::new();

    fn get_gpu() -> Option<&'static GpuState> {
        GPU.get_or_init(|| {
            match init_gpu() {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("[doglib.pow] GPU init failed, falling back to CPU: {e}");
                    None
                }
            }
        }).as_ref()
    }

    fn init_gpu() -> Result<GpuState, Box<dyn std::error::Error>> {
        let ctx = CudaContext::new(0)?;

        // Load SHA-256 module
        let sha256_mod = ctx.load_module(Ptx::from_src(SHA256_PTX))?;
        let sha256_f   = sha256_mod.load_function("sha256_pow")?;

        // Load SHA-1 module
        let sha1_mod = ctx.load_module(Ptx::from_src(SHA1_PTX))?;
        let sha1_f   = sha1_mod.load_function("sha1_pow")?;

        Ok(GpuState { ctx, sha256_f, sha1_f })
    }

    // ── SHA-256 CPU compression (for long-prefix mid-state) ──────────────────
    fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
            0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
            0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
            0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
            0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
            0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
            0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
            0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        let rotr = |x: u32, n: u32| x.rotate_right(n);
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            let s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2]>>10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h] = *state;
        for i in 0..64 {
            let s1  = rotr(e,6)^rotr(e,11)^rotr(e,25);
            let ch  = (e&f)^(!e&g);
            let t1  = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0  = rotr(a,2)^rotr(a,13)^rotr(a,22);
            let maj = (a&b)^(a&c)^(b&c);
            let t2  = s0.wrapping_add(maj);
            h=g; g=f; f=e; e=d.wrapping_add(t1);
            d=c; c=b; b=a; a=t1.wrapping_add(t2);
        }
        let s = [a,b,c,d,e,f,g,h];
        for i in 0..8 { state[i] = state[i].wrapping_add(s[i]); }
    }

    fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let rotl = |x: u32, n: u32| x.rotate_left(n);
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
        }
        let [mut a,mut b,mut c,mut d,mut e] = *state;
        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b&c)|(!b&d), 0x5a827999u32)
            } else if i < 40 {
                (b^c^d, 0x6ed9eba1u32)
            } else if i < 60 {
                ((b&c)|(b&d)|(c&d), 0x8f1bbcdcu32)
            } else {
                (b^c^d, 0xca62c1d6u32)
            };
            let t = rotl(a,5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e=d; d=c; c=rotl(b,30); b=a; a=t;
        }
        let s = [a,b,c,d,e];
        for i in 0..5 { state[i] = state[i].wrapping_add(s[i]); }
    }

    // ── build init state + remaining prefix for the GPU ───────────────────────
    // Returns (init_state_words, remaining_prefix_slice_start).
    fn build_init_state_sha256(prefix: &[u8]) -> ([u32; 8], usize) {
        if prefix.len() < 56 {
            return (SHA256_IV, 0);
        }
        let mut state = SHA256_IV;
        let mut pos = 0usize;
        while pos + 64 <= prefix.len() {
            sha256_compress(&mut state, prefix[pos..pos+64].try_into().unwrap());
            pos += 64;
        }
        (state, pos)
    }

    fn build_init_state_sha1(prefix: &[u8]) -> ([u32; 5], usize) {
        if prefix.len() < 56 {
            return (SHA1_IV, 0);
        }
        let mut state = SHA1_IV;
        let mut pos = 0usize;
        while pos + 64 <= prefix.len() {
            sha1_compress(&mut state, prefix[pos..pos+64].try_into().unwrap());
            pos += 64;
        }
        (state, pos)
    }

    // ── build 64-byte SHA block template ─────────────────────────────────────
    // Returns (template_as_16_be_u32_words, suffix_byte_offset_within_block)
    // or None if the combination does not fit in a single block.
    fn make_template(remaining_prefix: &[u8], suffix_len: usize, total_message_len: usize)
        -> Option<([u32; 16], usize)>
    {
        let rp_len = remaining_prefix.len();
        if rp_len + suffix_len > 55 {
            return None; // does not fit
        }
        let mut block = [0u8; 64];
        block[..rp_len].copy_from_slice(remaining_prefix);
        // suffix bytes inserted by kernel; leave as zero in template
        let pad_pos = rp_len + suffix_len;
        block[pad_pos] = 0x80;
        let bit_len = (total_message_len as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());

        // Convert to 16 big-endian u32 words
        let mut words = [0u32; 16];
        for i in 0..16 {
            words[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        Some((words, rp_len))
    }

    // ── decode counter → suffix bytes ─────────────────────────────────────────
    fn decode_counter(mut counter: u64, suffix_len: usize, charset: &[u8]) -> Vec<u8> {
        let cs = charset.len() as u64;
        let mut result = vec![0u8; suffix_len];
        for i in 0..suffix_len {
            result[i] = charset[(counter % cs) as usize];
            counter /= cs;
        }
        result
    }

    // ── public entry point ────────────────────────────────────────────────────
    pub fn bruteforce(
        prefix:   &[u8],
        algo:     &str,
        bits:     u32,
        position: &str,
        charset:  &[u8],
    ) -> Option<Vec<u8>> {
        let gpu = get_gpu()?;
        let stream = gpu.ctx.default_stream();

        let leading: i32 = if position == "leading" { 1 } else { 0 };
        let bits_i = bits as i32;

        // Upload charset once
        let cs_gpu: CudaSlice<u8> = stream.clone_htod(charset).ok()?;
        let cs_len = charset.len() as i32;

        // Select function and init-state builder
        let (func, init_words_vec, remaining_start) = match algo {
            "sha256" => {
                let (iw, rs) = build_init_state_sha256(prefix);
                (&gpu.sha256_f, iw.to_vec(), rs)
            }
            "sha1" => {
                let (iw, rs) = build_init_state_sha1(prefix);
                let mut v = iw.to_vec();
                v.resize(8, 0); // pad to 8 words so upload is uniform
                (&gpu.sha1_f, v, rs)
            }
            _ => return None,
        };
        let remaining_prefix = &prefix[remaining_start..];

        let init_gpu: CudaSlice<u32> = stream.clone_htod(&init_words_vec).ok()?;

        for suffix_len in 1usize..=8 {
            let total_len = prefix.len() + suffix_len;
            let tmpl_result = make_template(remaining_prefix, suffix_len, total_len);
            let (tmpl_words, suffix_byte_off) = match tmpl_result {
                Some(t) => t,
                None => continue,
            };

            let tmpl_gpu: CudaSlice<u32> = stream.clone_htod(&tmpl_words).ok()?;

            let mut found_gpu: CudaSlice<u32> = stream.alloc_zeros(1).ok()?;
            let mut result_gpu: CudaSlice<u64> = stream.alloc_zeros(1).ok()?;

            let suf_off = suffix_byte_off as i32;
            let suf_len = suffix_len as i32;

            let total_candidates: u64 = (charset.len() as u64).pow(suffix_len as u32);
            let mut base: u64 = 0;

            while base < total_candidates {
                let cfg = LaunchConfig {
                    block_dim: (THREADS, 1, 1),
                    grid_dim:  (BLOCKS, 1, 1),
                    shared_mem_bytes: 0, // s_found is statically allocated
                };

                unsafe {
                    stream.launch_builder(func)
                        .arg(&base)
                        .arg(&init_gpu)
                        .arg(&tmpl_gpu)
                        .arg(&cs_gpu)
                        .arg(&cs_len)
                        .arg(&suf_off)
                        .arg(&suf_len)
                        .arg(&bits_i)
                        .arg(&leading)
                        .arg(&mut found_gpu)
                        .arg(&mut result_gpu)
                        .launch(cfg)
                        .ok()?;
                }

                stream.synchronize().ok()?;

                let found_host = stream.clone_dtoh(&found_gpu).ok()?;
                if found_host[0] != 0 {
                    let rc = stream.clone_dtoh(&result_gpu).ok()?;
                    return Some(decode_counter(rc[0], suffix_len, charset));
                }

                base = base.saturating_add(CHUNK);
            }
        }

        None
    }
}

#[cfg(feature = "cuda")]
pub use inner::bruteforce;
