"""
Hash brute-force proof-of-work solvers.

Supports three common CTF PoW formats:
  - sosette (FCSC): SHA-256, leading zero bits, ASCII printable suffix
  - hxp:           SHA-256, trailing zero bits, raw byte suffix
  - hashcash:      SHA-1, leading zero bits, hex counter suffix
"""

import hashlib
import sys
from itertools import count

_BACKEND = "python"

try:
    from doglib_rs import pow_solver as _rs_pow
    _BACKEND = "rust"
except ImportError:
    _rs_pow = None


def _python_bruteforce(prefix, algo, bits, leading, charset):
    """Pure-Python fallback brute-forcer. Single-threaded and slow."""
    hash_fn = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    for length in range(1, 9):
        indices = [0] * length
        while True:
            suffix = bytes(charset[i] for i in indices)
            h = hash_fn(prefix + suffix).digest()
            if leading:
                if _check_leading(h, bits):
                    return suffix
            else:
                if _check_trailing(h, bits):
                    return suffix

            # Odometer increment
            pos = length - 1
            while pos >= 0:
                indices[pos] += 1
                if indices[pos] < len(charset):
                    break
                indices[pos] = 0
                pos -= 1
            if pos < 0:
                break
    return None


def _check_leading(h, bits):
    full = bits // 8
    rem = bits % 8
    for b in h[:full]:
        if b != 0:
            return False
    if rem > 0 and full < len(h):
        if h[full] & (0xFF << (8 - rem)):
            return False
    return True


def _check_trailing(h, bits):
    full = bits // 8
    rem = bits % 8
    for b in h[len(h) - full:]:
        if b != 0:
            return False
    if rem > 0 and full < len(h):
        if h[len(h) - 1 - full] & ((1 << rem) - 1):
            return False
    return True


def _do_bruteforce(prefix, algo, bits, position, charset_name, threads=None):
    """Dispatch to Rust if available, otherwise fall back to Python."""
    if _rs_pow is not None:
        result = _rs_pow.hash_bruteforce(prefix, algo, bits, position, charset_name, threads)
        return result

    charset_map = {
        "bytes": list(range(256)),
        "printable": list(range(32, 127)),
        "alphanumeric": list(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "hex": list(b"0123456789abcdef"),
        "numeric": list(b"0123456789"),
    }
    charset = charset_map[charset_name]
    leading = position == "leading"

    sys.stderr.write(
        f"[doglib.pow] hash brute-force running in pure-Python mode (very slow).\n"
        f"             cd src/doglib_rs; pip install .  — much faster\n"
    )
    return _python_bruteforce(prefix, algo, bits, leading, charset)


def solve_sosette(prefix, difficulty, threads=None):
    """Solve a sosette/FCSC-style PoW.

    Args:
        prefix: The prefix bytes (alphanumeric).
        difficulty: Number of leading zero bits required.
        threads: Number of threads (None = default).

    Returns:
        The ASCII printable suffix as bytes.
    """
    if isinstance(prefix, str):
        prefix = prefix.encode()
    return _do_bruteforce(prefix, "sha256", difficulty, "leading", "printable", threads)


def solve_hxp(prefix_hex, bits, threads=None):
    """Solve an hxp-style PoW.

    Args:
        prefix_hex: Hex-encoded prefix string.
        bits: Number of trailing zero bits required.
        threads: Number of threads (None = default).

    Returns:
        Hex-encoded suffix string.
    """
    prefix = bytes.fromhex(prefix_hex)
    raw = _do_bruteforce(prefix, "sha256", bits, "trailing", "bytes", threads)
    return raw.hex()


def solve_hashcash(resource, bits=20, threads=None, salt_length=8, stamp_seconds=False):
    """Solve a hashcash v1 PoW.

    Builds the hashcash stamp prefix (version, bits, date, resource, ext, salt)
    then brute-forces the counter suffix.

    Args:
        resource: The hashcash resource string.
        bits: Number of leading zero bits required.
        threads: Number of threads (None = default).

    Returns:
        The complete hashcash stamp string with counter.
    """
    from secrets import token_urlsafe
    from time import strftime, localtime, time

    now = time()
    if stamp_seconds:
        ts = strftime("%y%m%d%H%M%S", localtime(now))
    else:
        ts = strftime("%y%m%d", localtime(now))

    stamp_prefix = f"1:{bits}:{ts}:{resource}::{token_urlsafe(salt_length)}:"

    counter_bytes = _do_bruteforce(
        stamp_prefix.encode(), "sha1", bits, "leading", "hex", threads
    )
    return stamp_prefix + counter_bytes.decode()
