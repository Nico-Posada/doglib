use pyo3::prelude::*;
use rayon::prelude::*;

const DEG: usize = 31;
const SEP: usize = 3;

#[cfg(target_arch = "x86_64")]
mod avx512;

#[cfg(test)]
#[derive(Clone)]
struct GlibcRand {
    state: [i32; DEG],
    fptr: usize,
    rptr: usize,
}

#[cfg(test)]
impl GlibcRand {
    fn new(seed: u32) -> Self {
        let mut rng = GlibcRand {
            state: [0i32; DEG],
            fptr: SEP,
            rptr: 0,
        };
        rng.srand(seed);
        rng
    }

    fn srand(&mut self, mut seed: u32) {
        if seed == 0 {
            seed = 1;
        }

        self.state[0] = seed as i32;
        let mut word = (seed as i32) as i64;
        for i in 1..DEG {
            word = mersenne_mod(16807 * word);
            self.state[i] = word as i32;
        }

        self.fptr = SEP;
        self.rptr = 0;

        // flush 310 warmup cycles
        for _ in 0..(DEG * 10) {
            self.step();
        }
    }

    #[inline(always)]
    fn step(&mut self) -> u32 {
        let val = (self.state[self.fptr] as u32).wrapping_add(self.state[self.rptr] as u32);
        self.state[self.fptr] = val as i32;

        self.fptr += 1;
        if self.fptr >= DEG {
            self.fptr = 0;
            self.rptr += 1;
        } else {
            self.rptr += 1;
            if self.rptr >= DEG {
                self.rptr = 0;
            }
        }
        val
    }

    #[inline(always)]
    fn rand(&mut self) -> u32 {
        self.step() >> 1
    }
}

/// Mersenne prime modular reduction: x mod (2^31 - 1), always non-negative.
/// Handles both positive and negative x (needed because seeds >= 2^31
/// produce negative i32 words, and 16807 * negative = negative).
#[inline(always)]
fn mersenne_mod(x: i64) -> i64 {
    const M: i64 = 0x7fffffff;
    // rem_euclid gives always-positive result, matching Python's % behavior
    // and glibc's Schrage method (which adds M when result < 0).
    // LLVM optimizes constant-modulus division, so this is fast.
    x.rem_euclid(M)
}

struct Constraint {
    index: u32,
    value: u32,
    mask: u32,
}

// ---- Flat-array scalar brute force ----

/// LCG init + reorder into flat array layout.
/// s[0..31] = LCG state reordered by fptr traversal order (starting at SEP).
#[inline(always)]
fn lcg_init_flat(seed: u32, s: &mut [i32]) {
    let mut seed = seed;
    if seed == 0 {
        seed = 1;
    }

    let mut lcg = [0i32; DEG];
    lcg[0] = seed as i32;
    let mut word = (seed as i32) as i64;
    for i in 1..DEG {
        word = mersenne_mod(16807 * word);
        lcg[i] = word as i32;
    }

    // reorder: fptr starts at SEP, so s[k] = lcg[(k + SEP) % DEG]
    for k in 0..DEG {
        s[k] = lcg[(k + SEP) % DEG];
    }
}

/// Run the AFSR recurrence on a flat array: s[i] = s[i-31] + s[i-3] (wrapping u32)
#[inline(always)]
fn afsr_flat(s: &mut [i32], start: usize, end: usize) {
    for i in start..end {
        let val = (s[i - DEG] as u32).wrapping_add(s[i - SEP] as u32);
        s[i] = val as i32;
    }
}

/// Maximum constraint index we support (covers up to 512 outputs)
const MAX_FLAT: usize = DEG + 310 + 512;

#[inline(always)]
fn check_single_seed_flat(seed: u32, constraints: &[(u32, u32, u32)], total: usize) -> bool {
    let mut buf = [0i32; MAX_FLAT];
    lcg_init_flat(seed, &mut buf);
    afsr_flat(&mut buf, DEG, total);
    let base = DEG + 310;
    for &(idx, val, mask) in constraints {
        let output = (buf[base + idx as usize] as u32) >> 1;
        if (output & mask) != (val & mask) {
            return false;
        }
    }
    true
}

/// Identify free (unknown) bit positions and build a seed expansion helper.
struct SeedExpander {
    free_bits: [u8; 32],
    num_free: u32,
    template: u32,
}

impl SeedExpander {
    fn new(seed_value: u32, seed_mask: u32) -> Self {
        let mut free_bits = [0u8; 32];
        let mut num_free = 0u32;
        for bit in 0..32u8 {
            if seed_mask & (1u32 << bit) == 0 {
                free_bits[num_free as usize] = bit;
                num_free += 1;
            }
        }
        SeedExpander {
            free_bits,
            num_free,
            template: seed_value & seed_mask,
        }
    }

    /// Expand combo index into a full 32-bit seed by scattering free bits.
    #[inline(always)]
    fn expand(&self, combo: u64) -> u32 {
        let mut seed = self.template;
        for i in 0..self.num_free {
            if combo & (1u64 << i) != 0 {
                seed |= 1u32 << self.free_bits[i as usize];
            }
        }
        seed
    }
}

fn crack_scalar(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Option<u32> {
    if constraints.is_empty() {
        return None;
    }

    let max_idx = constraints.iter().map(|c| c.index).max().unwrap() as usize;
    let total = DEG + 310 + max_idx + 1;
    assert!(total <= MAX_FLAT, "too many outputs for flat array");

    let mut sorted: Vec<&Constraint> = constraints.iter().collect();
    sorted.sort_by_key(|c| c.index);

    let expander = SeedExpander::new(seed_value, seed_mask);
    let num_combos = 1u64 << expander.num_free;

    let con_packed: Vec<(u32, u32, u32)> = sorted
        .iter()
        .map(|c| (c.index, c.value, c.mask))
        .collect();

    (0u64..num_combos)
        .into_par_iter()
        .find_any(|&combo| {
            let seed = expander.expand(combo);
            check_single_seed_flat(seed, &con_packed, total)
        })
        .map(|combo| expander.expand(combo))
}

// ---- AVX-512 brute force (16 seeds per iteration) ----

#[cfg(target_arch = "x86_64")]
fn crack_avx512(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Option<u32> {
    if constraints.is_empty() {
        return None;
    }

    let max_idx = constraints.iter().map(|c| c.index).max().unwrap() as usize;
    assert!(DEG + 310 + max_idx + 1 <= MAX_FLAT);

    let mut sorted: Vec<&Constraint> = constraints.iter().collect();
    sorted.sort_by_key(|c| c.index);

    let con_packed: Vec<(u32, u32, u32)> = sorted
        .iter()
        .map(|c| (c.index, c.value, c.mask))
        .collect();
    let total = DEG + 310 + max_idx + 1;

    let expander = SeedExpander::new(seed_value, seed_mask);
    let num_combos = 1u64 << expander.num_free;

    const CHUNK: u64 = 16 * 4096;
    let num_chunks = (num_combos + CHUNK - 1) / CHUNK;

    (0..num_chunks)
        .into_par_iter()
        .find_any(|&chunk_idx| {
            let mut buf = avx512::SimdBuf::new();
            let base_combo = chunk_idx * CHUNK;
            let end_combo = (base_combo + CHUNK).min(num_combos);

            let mut combo = base_combo;
            while combo + 16 <= end_combo {
                let seeds: [u32; 16] = std::array::from_fn(|i| expander.expand(combo + i as u64));
                let hit = unsafe {
                    avx512::check_16_seeds(&mut buf, &seeds, &con_packed, total)
                };
                if hit != u32::MAX {
                    return true;
                }
                combo += 16;
            }
            while combo < end_combo {
                if check_single_seed_flat(expander.expand(combo), &con_packed, total) {
                    return true;
                }
                combo += 1;
            }
            false
        })
        .map(|chunk_idx| {
            // re-scan the winning chunk to find the exact seed
            let mut buf = avx512::SimdBuf::new();
            let base_combo = chunk_idx * CHUNK;
            let end_combo = (base_combo + CHUNK).min(num_combos);

            let mut combo = base_combo;
            while combo + 16 <= end_combo {
                let seeds: [u32; 16] = std::array::from_fn(|i| expander.expand(combo + i as u64));
                let hit = unsafe {
                    avx512::check_16_seeds(&mut buf, &seeds, &con_packed, total)
                };
                if hit != u32::MAX {
                    return hit;
                }
                combo += 16;
            }
            while combo < end_combo {
                if check_single_seed_flat(expander.expand(combo), &con_packed, total) {
                    return expander.expand(combo);
                }
                combo += 1;
            }
            unreachable!()
        })
}

fn crack(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return crack_avx512(constraints, seed_value, seed_mask);
        }
    }
    crack_scalar(constraints, seed_value, seed_mask)
}

// ---- Find ALL matching seeds ----

fn crack_all_scalar(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Vec<u32> {
    if constraints.is_empty() {
        return vec![];
    }

    let max_idx = constraints.iter().map(|c| c.index).max().unwrap() as usize;
    let total = DEG + 310 + max_idx + 1;
    assert!(total <= MAX_FLAT, "too many outputs for flat array");

    let mut sorted: Vec<&Constraint> = constraints.iter().collect();
    sorted.sort_by_key(|c| c.index);

    let expander = SeedExpander::new(seed_value, seed_mask);
    let num_combos = 1u64 << expander.num_free;

    let con_packed: Vec<(u32, u32, u32)> = sorted
        .iter()
        .map(|c| (c.index, c.value, c.mask))
        .collect();

    (0u64..num_combos)
        .into_par_iter()
        .filter_map(|combo| {
            let seed = expander.expand(combo);
            if check_single_seed_flat(seed, &con_packed, total) {
                Some(seed)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(target_arch = "x86_64")]
fn crack_all_avx512(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Vec<u32> {
    if constraints.is_empty() {
        return vec![];
    }

    let max_idx = constraints.iter().map(|c| c.index).max().unwrap() as usize;
    assert!(DEG + 310 + max_idx + 1 <= MAX_FLAT);

    let mut sorted: Vec<&Constraint> = constraints.iter().collect();
    sorted.sort_by_key(|c| c.index);

    let con_packed: Vec<(u32, u32, u32)> = sorted
        .iter()
        .map(|c| (c.index, c.value, c.mask))
        .collect();
    let total = DEG + 310 + max_idx + 1;

    let expander = SeedExpander::new(seed_value, seed_mask);
    let num_combos = 1u64 << expander.num_free;

    const CHUNK: u64 = 16 * 4096;
    let num_chunks = (num_combos + CHUNK - 1) / CHUNK;

    (0..num_chunks)
        .into_par_iter()
        .flat_map(|chunk_idx| {
            let mut buf = avx512::SimdBuf::new();
            let base_combo = chunk_idx * CHUNK;
            let end_combo = (base_combo + CHUNK).min(num_combos);
            let mut hits = Vec::new();

            let mut combo = base_combo;
            while combo + 16 <= end_combo {
                let seeds: [u32; 16] = std::array::from_fn(|i| expander.expand(combo + i as u64));
                let alive = unsafe {
                    avx512::check_16_seeds_mask(&mut buf, &seeds, &con_packed, total)
                };
                let mut mask = alive;
                while mask != 0 {
                    let lane = mask.trailing_zeros() as usize;
                    hits.push(seeds[lane]);
                    mask &= mask - 1;
                }
                combo += 16;
            }
            while combo < end_combo {
                let seed = expander.expand(combo);
                if check_single_seed_flat(seed, &con_packed, total) {
                    hits.push(seed);
                }
                combo += 1;
            }
            hits
        })
        .collect()
}

fn crack_all(constraints: &[Constraint], seed_value: u32, seed_mask: u32) -> Vec<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return crack_all_avx512(constraints, seed_value, seed_mask);
        }
    }
    crack_all_scalar(constraints, seed_value, seed_mask)
}

#[pyfunction]
#[pyo3(signature = (constraints, seed_value=0, seed_mask=0))]
fn bruteforce_seed(
    py: Python<'_>,
    constraints: Vec<(u32, u32, u32)>,
    seed_value: u32,
    seed_mask: u32,
) -> PyResult<Option<u32>> {
    let constraints: Vec<Constraint> = constraints
        .into_iter()
        .map(|(index, value, mask)| Constraint { index, value, mask })
        .collect();

    let result = py.detach(|| crack(&constraints, seed_value, seed_mask));
    Ok(result)
}

#[pyfunction]
#[pyo3(signature = (constraints, seed_value=0, seed_mask=0))]
fn bruteforce_seed_all(
    py: Python<'_>,
    constraints: Vec<(u32, u32, u32)>,
    seed_value: u32,
    seed_mask: u32,
) -> PyResult<Vec<u32>> {
    let constraints: Vec<Constraint> = constraints
        .into_iter()
        .map(|(index, value, mask)| Constraint { index, value, mask })
        .collect();

    let result = py.detach(|| crack_all(&constraints, seed_value, seed_mask));
    Ok(result)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bruteforce_seed, m)?)?;
    m.add_function(wrap_pyfunction!(bruteforce_seed_all, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_sequence_seed1() {
        let mut rng = GlibcRand::new(1);
        assert_eq!(rng.rand(), 1804289383);
        assert_eq!(rng.rand(), 846930886);
        assert_eq!(rng.rand(), 1681692777);
    }

    #[test]
    fn test_flat_matches_ring_buffer() {
        for seed in [1u32, 42, 1337, 0xdeadbeef, 0xffffffff] {
            let mut rng = GlibcRand::new(seed);
            let mut s = [0i32; MAX_FLAT];
            lcg_init_flat(seed, &mut s);
            afsr_flat(&mut s, DEG, DEG + 310 + 20);

            for i in 0..20 {
                let expected = rng.rand();
                let got = (s[DEG + 310 + i] as u32) >> 1;
                assert_eq!(got, expected, "seed={seed} i={i}");
            }
        }
    }

    #[test]
    fn test_crack_finds_seed() {
        let seed = 42u32;
        let mut rng = GlibcRand::new(seed);
        let outputs: Vec<u32> = (0..3).map(|_| rng.rand()).collect();

        let constraints: Vec<Constraint> = outputs
            .iter()
            .enumerate()
            .map(|(i, &v)| Constraint {
                index: i as u32,
                value: v,
                mask: 0x7fffffff,
            })
            .collect();

        assert_eq!(crack(&constraints, 0, 0), Some(42));
    }

    #[test]
    fn test_large_seed_sign_extension() {
        let mut rng = GlibcRand::new(0xdeadbeef);
        let first = rng.rand();
        let mut rng2 = GlibcRand::new(0xdeadbeef);
        assert_eq!(rng2.rand(), first);

        let mut a = GlibcRand::new(0xffffffff);
        let seq: Vec<u32> = (0..10).map(|_| a.rand()).collect();
        let mut b = GlibcRand::new(0xffffffff);
        for &v in &seq {
            assert_eq!(b.rand(), v);
        }
    }

    #[test]
    fn test_mersenne_mod() {
        for &x in &[0i64, 1, 16806, 16807, 2147483646, 2147483647, 36028795946492927] {
            assert_eq!(mersenne_mod(x), x % 0x7fffffff, "x={x}");
        }
    }

    #[test]
    fn test_crack_with_known_bits() {
        let seed = 0xdeadbeef_u32;
        let mut rng = GlibcRand::new(seed);
        let outputs: Vec<u32> = (0..3).map(|_| rng.rand()).collect();

        let constraints: Vec<Constraint> = outputs
            .iter()
            .enumerate()
            .map(|(i, &v)| Constraint {
                index: i as u32,
                value: v,
                mask: 0x7fffffff,
            })
            .collect();

        let seed_mask = 0x0000ffff_u32;
        let seed_value = seed & seed_mask;
        assert_eq!(crack(&constraints, seed_value, seed_mask), Some(seed));
    }

    #[test]
    fn test_seed_expander() {
        let exp = SeedExpander::new(0xAB, 0xFF);
        assert_eq!(exp.num_free, 24);
        assert_eq!(exp.template, 0xAB);
        assert_eq!(exp.expand(0), 0xAB);
        assert_eq!(exp.expand(1), 0xAB | (1 << 8));

        let exp2 = SeedExpander::new(42, 0xFFFFFFFF);
        assert_eq!(exp2.num_free, 0);
        assert_eq!(exp2.expand(0), 42);

        let exp3 = SeedExpander::new(0, 0);
        assert_eq!(exp3.num_free, 32);
        assert_eq!(exp3.expand(42), 42);
    }
}
