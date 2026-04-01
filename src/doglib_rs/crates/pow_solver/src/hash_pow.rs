use digest::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

#[derive(Clone, Copy)]
pub enum HashAlgo {
    Sha256,
    Sha1,
}

#[derive(Clone, Copy)]
pub enum BitPosition {
    Leading,
    Trailing,
}

pub fn parse_algo(s: &str) -> Result<HashAlgo, &'static str> {
    match s {
        "sha256" => Ok(HashAlgo::Sha256),
        "sha1" => Ok(HashAlgo::Sha1),
        _ => Err("unknown algorithm: expected \"sha256\" or \"sha1\""),
    }
}

pub fn parse_position(s: &str) -> Result<BitPosition, &'static str> {
    match s {
        "leading" => Ok(BitPosition::Leading),
        "trailing" => Ok(BitPosition::Trailing),
        _ => Err("unknown position: expected \"leading\" or \"trailing\""),
    }
}

pub fn parse_charset(s: &str) -> Result<Vec<u8>, &'static str> {
    match s {
        "bytes" => Ok((0..=255u8).collect()),
        "printable" => Ok((32..127u8).collect()),
        "alphanumeric" => {
            let mut v: Vec<u8> = (b'0'..=b'9').collect();
            v.extend(b'A'..=b'Z');
            v.extend(b'a'..=b'z');
            Ok(v)
        }
        "hex" => {
            let mut v: Vec<u8> = (b'0'..=b'9').collect();
            v.extend(b'a'..=b'f');
            Ok(v)
        }
        "numeric" => Ok((b'0'..=b'9').collect()),
        _ => Err("unknown charset: expected \"bytes\", \"printable\", \"alphanumeric\", \"hex\", or \"numeric\""),
    }
}

pub fn count_leading_zero_bits(hash: &[u8]) -> u32 {
    let mut total = 0u32;
    for &b in hash {
        if b == 0 {
            total += 8;
        } else {
            total += b.leading_zeros();
            return total;
        }
    }
    total
}

pub fn count_trailing_zero_bits(hash: &[u8]) -> u32 {
    let mut total = 0u32;
    for &b in hash.iter().rev() {
        if b == 0 {
            total += 8;
        } else {
            total += b.trailing_zeros();
            return total;
        }
    }
    total
}

#[inline(always)]
fn check_leading_zeros(hash: &[u8], bits: u32) -> bool {
    count_leading_zero_bits(hash) >= bits
}

#[inline(always)]
fn check_trailing_zeros(hash: &[u8], bits: u32) -> bool {
    count_trailing_zero_bits(hash) >= bits
}

/// Inner brute-force loop, monomorphized over hash algorithm and bit position.
fn bruteforce_inner<H: Digest + Clone, const LEADING: bool>(
    prefix_hasher: &H,
    bits: u32,
    charset: &[u8],
    found: &AtomicBool,
    start_idx: usize,
    step: usize,
) -> Option<Vec<u8>> {
    let cs_len = charset.len();
    if cs_len == 0 {
        return None;
    }

    // Try increasing suffix lengths, starting from 1.
    // For length 1, the thread only tries its assigned slice of the charset.
    // For length > 1, the first byte is partitioned across threads; remaining
    // bytes sweep the full charset.
    for suffix_len in 1..=crate::MAX_SUFFIX_LEN {
        // Odometer indices for the current suffix.
        let mut indices = vec![0usize; suffix_len];
        let mut suffix = vec![charset[0]; suffix_len];

        // Partition: this thread handles first-byte indices
        // start_idx, start_idx+step, start_idx+2*step, ...
        let mut first_idx = start_idx;
        while first_idx < cs_len {
            indices[0] = first_idx;
            suffix[0] = charset[first_idx];

            // Reset remaining positions
            for i in 1..suffix_len {
                indices[i] = 0;
                suffix[i] = charset[0];
            }

            loop {
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                let mut hasher = prefix_hasher.clone();
                hasher.update(&suffix);
                let hash = hasher.finalize();

                let ok = if LEADING {
                    check_leading_zeros(&hash, bits)
                } else {
                    check_trailing_zeros(&hash, bits)
                };

                if ok {
                    found.store(true, Ordering::Relaxed);
                    return Some(suffix.clone());
                }

                // Odometer increment: advance from the last position, carry leftward,
                // but never roll over position 0 (that's controlled by the partition).
                let mut carry_pos = suffix_len - 1;
                loop {
                    if carry_pos == 0 {
                        // Exhausted all combinations for this first-byte assignment.
                        // Break to move to the next first_idx.
                        break;
                    }
                    indices[carry_pos] += 1;
                    if indices[carry_pos] < cs_len {
                        suffix[carry_pos] = charset[indices[carry_pos]];
                        break;
                    }
                    indices[carry_pos] = 0;
                    suffix[carry_pos] = charset[0];
                    carry_pos -= 1;
                }
                if carry_pos == 0 && suffix_len > 1 {
                    // We broke out of the carry loop at position 0 -- this
                    // means all positions [1..] rolled over. Move to next first byte.
                    break;
                }
                if suffix_len == 1 {
                    // Single-byte suffix: each first_idx is a single candidate,
                    // already checked above.
                    break;
                }
            }

            first_idx += step;
        }
    }

    None
}

fn default_threads() -> usize {
    let n = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (n / 2).max(1)
}

pub fn bruteforce(
    prefix: &[u8],
    algo: HashAlgo,
    bits: u32,
    position: BitPosition,
    charset: &[u8],
    threads: Option<u32>,
) -> Option<Vec<u8>> {
    let num_threads = threads
        .map(|t| t as usize)
        .unwrap_or_else(default_threads)
        .max(1)
        .min(charset.len());

    let found = AtomicBool::new(false);

    // Dispatch into monomorphized paths, then spawn threads.
    match (algo, position) {
        (HashAlgo::Sha256, BitPosition::Leading) => {
            dispatch::<sha2::Sha256, true>(prefix, bits, charset, num_threads, &found)
        }
        (HashAlgo::Sha256, BitPosition::Trailing) => {
            dispatch::<sha2::Sha256, false>(prefix, bits, charset, num_threads, &found)
        }
        (HashAlgo::Sha1, BitPosition::Leading) => {
            dispatch::<sha1::Sha1, true>(prefix, bits, charset, num_threads, &found)
        }
        (HashAlgo::Sha1, BitPosition::Trailing) => {
            dispatch::<sha1::Sha1, false>(prefix, bits, charset, num_threads, &found)
        }
    }
}

fn dispatch<H: Digest + Clone + Send + Sync, const LEADING: bool>(
    prefix: &[u8],
    bits: u32,
    charset: &[u8],
    num_threads: usize,
    found: &AtomicBool,
) -> Option<Vec<u8>> {
    let mut prefix_hasher = H::new();
    prefix_hasher.update(prefix);

    if num_threads == 1 {
        return bruteforce_inner::<H, LEADING>(&prefix_hasher, bits, charset, found, 0, 1);
    }

    thread::scope(|s| {
        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let hasher = prefix_hasher.clone();
                s.spawn(move || {
                    bruteforce_inner::<H, LEADING>(&hasher, bits, charset, found, i, num_threads)
                })
            })
            .collect();

        let mut result = None;
        for h in handles {
            if let Some(r) = h.join().ok().flatten() {
                result = Some(r);
            }
        }
        result
    })
}

/// Hash N suffixes against the given prefix and count how many meet the
/// bit threshold. Used by benchmarks to measure raw throughput without the
/// variance of a brute-force search.
pub fn hash_throughput<H: Digest + Clone>(
    prefix: &[u8],
    n: u64,
    bits: u32,
    leading: bool,
) -> u64 {
    let mut prefix_hasher = H::new();
    prefix_hasher.update(prefix);

    let mut hits = 0u64;
    for i in 0..n {
        let suffix = i.to_le_bytes();
        let mut h = prefix_hasher.clone();
        h.update(&suffix);
        let hash = h.finalize();
        let ok = if leading {
            check_leading_zeros(&hash, bits)
        } else {
            check_trailing_zeros(&hash, bits)
        };
        if ok {
            hits += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify_hash<H: Digest>(prefix: &[u8], suffix: &[u8], bits: u32, leading: bool) -> bool {
        let mut hasher = H::new();
        hasher.update(prefix);
        hasher.update(suffix);
        let hash = hasher.finalize();
        if leading {
            check_leading_zeros(&hash, bits)
        } else {
            check_trailing_zeros(&hash, bits)
        }
    }

    #[test]
    fn sha256_leading_printable() {
        let prefix = b"TestPrefix123456";
        let charset = parse_charset("printable").unwrap();
        let result = bruteforce(prefix, HashAlgo::Sha256, 16, BitPosition::Leading, &charset, Some(2));
        let suffix = result.expect("should find a solution");
        assert!(verify_hash::<sha2::Sha256>(prefix, &suffix, 16, true));
        assert!(suffix.iter().all(|&b| (32..127).contains(&b)));
    }

    #[test]
    fn sha256_trailing_bytes() {
        let prefix = b"hxpPrefix_";
        let charset = parse_charset("bytes").unwrap();
        let result = bruteforce(prefix, HashAlgo::Sha256, 16, BitPosition::Trailing, &charset, Some(2));
        let suffix = result.expect("should find a solution");
        assert!(verify_hash::<sha2::Sha256>(prefix, &suffix, 16, false));
    }

    #[test]
    fn sha1_leading_hex() {
        let prefix = b"1:20:260330:test@example.com::abc123:";
        let charset = parse_charset("hex").unwrap();
        let result = bruteforce(prefix, HashAlgo::Sha1, 16, BitPosition::Leading, &charset, Some(2));
        let suffix = result.expect("should find a solution");
        assert!(verify_hash::<sha1::Sha1>(prefix, &suffix, 16, true));
        assert!(suffix.iter().all(|&b| b"0123456789abcdef".contains(&b)));
    }

    #[test]
    fn single_threaded_works() {
        let prefix = b"SingleThread";
        let charset = parse_charset("printable").unwrap();
        let result = bruteforce(prefix, HashAlgo::Sha256, 12, BitPosition::Leading, &charset, Some(1));
        let suffix = result.expect("should find a solution");
        assert!(verify_hash::<sha2::Sha256>(prefix, &suffix, 12, true));
    }

    #[test]
    fn check_zeros_basic() {
        // 0x00, 0x08 = 0000_0000 0000_1000 => exactly 12 leading zeros
        let hash = [0x00, 0x08, 0xFF, 0xFF];
        assert!(check_leading_zeros(&hash, 12));
        assert!(!check_leading_zeros(&hash, 13));

        // 0x10, 0x00 = 0001_0000 0000_0000 => exactly 12 trailing zeros
        let hash2 = [0xFF, 0xFF, 0x10, 0x00];
        assert!(check_trailing_zeros(&hash2, 12));
        assert!(!check_trailing_zeros(&hash2, 13));
    }
}
