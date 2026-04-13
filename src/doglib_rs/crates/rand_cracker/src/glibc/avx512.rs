//! AVX-512 accelerated glibc rand() seed brute-force.
//!
//! Processes 16 seeds simultaneously using 512-bit SIMD registers (16 × i32 lanes).
//! The LCG initialization and AFSR warmup are fully vectorized.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::{DEG, SEP, MAX_FLAT};

/// Pre-allocated buffer for SIMD computation. One per thread.
#[repr(C, align(64))]
pub struct SimdBuf {
    flat: [__m512i; MAX_FLAT],
}

impl SimdBuf {
    pub fn new() -> Self {
        SimdBuf {
            flat: [unsafe { _mm512_setzero_si512() }; MAX_FLAT],
        }
    }
}

/// Check 16 seeds in parallel using a pre-allocated buffer.
/// Returns the matching seed, or u32::MAX if none match.
///
/// # Safety
/// Caller must ensure AVX-512F is supported.
#[target_feature(enable = "avx512f")]
pub unsafe fn check_16_seeds(
    buf: &mut SimdBuf,
    seeds: &[u32; 16],
    constraints: &[(u32, u32, u32)],
    total: usize,
) -> u32 {
    debug_assert!(total <= MAX_FLAT);
    let flat = &mut buf.flat;

    // ---- LCG initialization (16 seeds in parallel) ----

    let mut seed_vec = _mm512_loadu_si512(seeds.as_ptr() as *const _);

    // Replace seed==0 with seed==1
    let zero = _mm512_setzero_si512();
    let ones = _mm512_set1_epi32(1);
    let zero_mask = _mm512_cmpeq_epi32_mask(seed_vec, zero);
    seed_vec = _mm512_mask_mov_epi32(seed_vec, zero_mask, ones);

    // LCG: state[i] = (16807 * state[i-1]) % (2^31 - 1)
    // Process in two halves (lo/hi 8 lanes) for 64-bit precision.
    let mut lcg = [zero; DEG];
    lcg[0] = seed_vec;

    let multiplier = _mm512_set1_epi64(16807);
    let mersenne = _mm512_set1_epi64(0x7fffffff);
    let neg_mersenne = _mm512_set1_epi64(-0x7fffffff_i64);
    // 16809 * (2^31-1): adding this to any negative LCG product makes it positive
    // while preserving the value mod (2^31-1). Only needed for the first iteration
    // when seeds >= 2^31 produce negative i32 words.
    let fixup = _mm512_set1_epi64(16809_i64 * 0x7fffffff_i64);

    // sign-extend each half from i32 to i64
    let mut lo8 = _mm512_cvtepi32_epi64(_mm512_castsi512_si256(seed_vec));
    let mut hi8 = _mm512_cvtepi32_epi64(_mm512_extracti32x8_epi32(seed_vec, 1));

    for i in 1..DEG {
        lo8 = _mm512_mullo_epi64(lo8, multiplier);
        hi8 = _mm512_mullo_epi64(hi8, multiplier);

        // Fix negative products (first iteration only, when seed >= 2^31).
        // Add 16809 * M to negative lanes — this is ≡ 0 (mod M) so it
        // doesn't change the result, just makes it positive for the
        // unsigned Mersenne reduction below.
        if i == 1 {
            let lo_neg = _mm512_cmpgt_epi64_mask(zero, lo8);
            lo8 = _mm512_mask_add_epi64(lo8, lo_neg, lo8, fixup);
            let hi_neg = _mm512_cmpgt_epi64_mask(zero, hi8);
            hi8 = _mm512_mask_add_epi64(hi8, hi_neg, hi8, fixup);
        }

        // Mersenne reduction: r = (x & 0x7fffffff) + (x >> 31)
        // x is guaranteed positive here, so srli (logical shift) is correct.
        let lo_r = _mm512_add_epi64(_mm512_and_si512(lo8, mersenne), _mm512_srli_epi64(lo8, 31));
        let hi_r = _mm512_add_epi64(_mm512_and_si512(hi8, mersenne), _mm512_srli_epi64(hi8, 31));
        // if r >= mersenne: r -= mersenne
        let lo_cmp = _mm512_cmpge_epi64_mask(lo_r, mersenne);
        lo8 = _mm512_mask_add_epi64(lo_r, lo_cmp, lo_r, neg_mersenne);
        let hi_cmp = _mm512_cmpge_epi64_mask(hi_r, mersenne);
        hi8 = _mm512_mask_add_epi64(hi_r, hi_cmp, hi_r, neg_mersenne);

        // Pack back to 16 x i32
        let lo_trunc = _mm512_cvtepi64_epi32(lo8);
        let hi_trunc = _mm512_cvtepi64_epi32(hi8);
        lcg[i] = _mm512_inserti32x8(_mm512_castsi256_si512(lo_trunc), hi_trunc, 1);
    }

    // ---- Reorder into flat layout ----
    // flat[k] = lcg[(k + SEP) % DEG]
    for k in 0..DEG {
        *flat.get_unchecked_mut(k) = lcg[(k + SEP) % DEG];
    }

    // ---- AFSR recurrence (vectorized) ----
    for i in DEG..total {
        let a = *flat.get_unchecked(i - DEG);
        let b = *flat.get_unchecked(i - SEP);
        *flat.get_unchecked_mut(i) = _mm512_add_epi32(a, b);
    }

    // ---- Check constraints ----
    let base = DEG + 310;
    let mut alive: u16 = 0xFFFF;

    for &(idx, value, mask) in constraints {
        let raw = *flat.get_unchecked(base + idx as usize);
        let output = _mm512_srli_epi32(raw, 1);

        let val_vec = _mm512_set1_epi32(value as i32);
        let mask_vec = _mm512_set1_epi32(mask as i32);

        let got = _mm512_and_si512(output, mask_vec);
        let want = _mm512_and_si512(val_vec, mask_vec);
        alive &= _mm512_cmpeq_epi32_mask(got, want);

        if alive == 0 {
            return u32::MAX;
        }
    }

    // return the first surviving seed
    let lane = alive.trailing_zeros() as usize;
    *seeds.get_unchecked(lane)
}

/// Same as check_16_seeds but returns the alive bitmask instead of a single seed.
/// Bit i is set if seeds[i] matches all constraints.
///
/// # Safety
/// Caller must ensure AVX-512F is supported.
#[target_feature(enable = "avx512f")]
pub unsafe fn check_16_seeds_mask(
    buf: &mut SimdBuf,
    seeds: &[u32; 16],
    constraints: &[(u32, u32, u32)],
    total: usize,
) -> u16 {
    debug_assert!(total <= MAX_FLAT);
    let flat = &mut buf.flat;

    // ---- LCG initialization (16 seeds in parallel) ----

    let mut seed_vec = _mm512_loadu_si512(seeds.as_ptr() as *const _);

    let zero = _mm512_setzero_si512();
    let ones = _mm512_set1_epi32(1);
    let zero_mask = _mm512_cmpeq_epi32_mask(seed_vec, zero);
    seed_vec = _mm512_mask_mov_epi32(seed_vec, zero_mask, ones);

    let mut lcg = [zero; DEG];
    lcg[0] = seed_vec;

    let multiplier = _mm512_set1_epi64(16807);
    let mersenne = _mm512_set1_epi64(0x7fffffff);
    let neg_mersenne = _mm512_set1_epi64(-0x7fffffff_i64);
    let fixup = _mm512_set1_epi64(16809_i64 * 0x7fffffff_i64);

    let mut lo8 = _mm512_cvtepi32_epi64(_mm512_castsi512_si256(seed_vec));
    let mut hi8 = _mm512_cvtepi32_epi64(_mm512_extracti32x8_epi32(seed_vec, 1));

    for i in 1..DEG {
        lo8 = _mm512_mullo_epi64(lo8, multiplier);
        hi8 = _mm512_mullo_epi64(hi8, multiplier);

        if i == 1 {
            let lo_neg = _mm512_cmpgt_epi64_mask(zero, lo8);
            lo8 = _mm512_mask_add_epi64(lo8, lo_neg, lo8, fixup);
            let hi_neg = _mm512_cmpgt_epi64_mask(zero, hi8);
            hi8 = _mm512_mask_add_epi64(hi8, hi_neg, hi8, fixup);
        }

        let lo_r = _mm512_add_epi64(_mm512_and_si512(lo8, mersenne), _mm512_srli_epi64(lo8, 31));
        let hi_r = _mm512_add_epi64(_mm512_and_si512(hi8, mersenne), _mm512_srli_epi64(hi8, 31));
        let lo_cmp = _mm512_cmpge_epi64_mask(lo_r, mersenne);
        lo8 = _mm512_mask_add_epi64(lo_r, lo_cmp, lo_r, neg_mersenne);
        let hi_cmp = _mm512_cmpge_epi64_mask(hi_r, mersenne);
        hi8 = _mm512_mask_add_epi64(hi_r, hi_cmp, hi_r, neg_mersenne);

        let lo_trunc = _mm512_cvtepi64_epi32(lo8);
        let hi_trunc = _mm512_cvtepi64_epi32(hi8);
        lcg[i] = _mm512_inserti32x8(_mm512_castsi256_si512(lo_trunc), hi_trunc, 1);
    }

    for k in 0..DEG {
        *flat.get_unchecked_mut(k) = lcg[(k + SEP) % DEG];
    }

    for i in DEG..total {
        let a = *flat.get_unchecked(i - DEG);
        let b = *flat.get_unchecked(i - SEP);
        *flat.get_unchecked_mut(i) = _mm512_add_epi32(a, b);
    }

    let base = DEG + 310;
    let mut alive: u16 = 0xFFFF;

    for &(idx, value, mask) in constraints {
        let raw = *flat.get_unchecked(base + idx as usize);
        let output = _mm512_srli_epi32(raw, 1);

        let val_vec = _mm512_set1_epi32(value as i32);
        let mask_vec = _mm512_set1_epi32(mask as i32);

        let got = _mm512_and_si512(output, mask_vec);
        let want = _mm512_and_si512(val_vec, mask_vec);
        alive &= _mm512_cmpeq_epi32_mask(got, want);

        if alive == 0 {
            return 0;
        }
    }

    alive
}
