"""Tests for hash brute-force PoW solvers."""

import hashlib
import random
import secrets

import pytest

from doglib.pow import solve_sosette, solve_hxp, solve_hashcash, detect_and_solve
from doglib.pow._hash import _BACKEND, _do_bruteforce, _gpu_available


class TestSosette:
    """sosette/FCSC-style: SHA-256, leading zero bits, printable suffix."""

    def test_solve_basic(self):
        prefix = b"TestPrefix123456"
        difficulty = 16
        suffix = solve_sosette(prefix, difficulty)
        h = hashlib.sha256(prefix + suffix).digest()
        assert _has_leading_zeros(h, difficulty)

    def test_suffix_is_printable(self):
        prefix = b"PrintableCheck!!"
        suffix = solve_sosette(prefix, 12)
        assert all(32 <= b < 127 for b in suffix)

    @pytest.mark.parametrize("difficulty", [8, 12, 16])
    def test_various_difficulties(self, difficulty):
        prefix = b"VaryDifficulty__"
        suffix = solve_sosette(prefix, difficulty)
        h = hashlib.sha256(prefix + suffix).digest()
        assert _has_leading_zeros(h, difficulty)

    def test_string_prefix(self):
        prefix = "StringPrefix1234"
        suffix = solve_sosette(prefix, 12)
        h = hashlib.sha256(prefix.encode() + suffix).digest()
        assert _has_leading_zeros(h, 12)


class TestHxp:
    """hxp-style: SHA-256, trailing zero bits, raw byte suffix."""

    def test_solve_basic(self):
        prefix_hex = "541ca361107f4a2a"
        bits = 16
        suffix_hex = solve_hxp(prefix_hex, bits)
        h = hashlib.sha256(bytes.fromhex(prefix_hex + suffix_hex)).digest()
        assert _has_trailing_zeros(h, bits)

    def test_output_is_hex(self):
        suffix_hex = solve_hxp("deadbeef", 8)
        int(suffix_hex, 16)

    @pytest.mark.parametrize("bits", [8, 12, 16])
    def test_various_difficulties(self, bits):
        prefix_hex = "aabbccdd11223344"
        suffix_hex = solve_hxp(prefix_hex, bits)
        h = hashlib.sha256(bytes.fromhex(prefix_hex + suffix_hex)).digest()
        assert _has_trailing_zeros(h, bits)


class TestHashcash:
    """hashcash v1: SHA-1, leading zero bits, hex counter."""

    def test_solve_basic(self):
        stamp = solve_hashcash("test@example.com", bits=16)
        h = hashlib.sha1(stamp.encode()).digest()
        assert _has_leading_zeros(h, 16)

    def test_stamp_format(self):
        stamp = solve_hashcash("foo.bar", bits=12)
        parts = stamp.split(":")
        assert parts[0] == "1"
        assert parts[1] == "12"
        assert parts[3] == "foo.bar"

    def test_verify_sha1(self):
        stamp = solve_hashcash("ctf@example.org", bits=16)
        h = hashlib.sha1(stamp.encode()).digest()
        assert _has_leading_zeros(h, 16)


class TestAutoDetect:
    """Test the detect_and_solve auto-detection."""

    def test_detect_sosette(self):
        data = (
            b"Please provide an ASCII printable string S such that "
            b"SHA256(AbCdEfGh12345678 || S) starts with 12 bits equal to 0"
        )
        result = detect_and_solve(data)
        assert result is not None
        h = hashlib.sha256(b"AbCdEfGh12345678" + result).digest()
        assert _has_leading_zeros(h, 12)

    def test_detect_hxp(self):
        data = (
            b'please give S such that sha256(unhex("541ca361107f4a2a" + S)) '
            b"ends with 8 zero bits."
        )
        result = detect_and_solve(data)
        assert result is not None
        h = hashlib.sha256(bytes.fromhex("541ca361107f4a2a") + bytes.fromhex(result.decode())).digest()
        assert _has_trailing_zeros(h, 8)

    def test_detect_hashcash(self):
        data = b'solve: `hashcash -mCb16 "test@resource"`'
        result = detect_and_solve(data)
        assert result is not None
        h = hashlib.sha1(result).digest()
        assert _has_leading_zeros(h, 16)

    def test_detect_sloth(self):
        data = b"proof of work: s.AAAAAQ==.H+fPiuL32DPbfN97cpd0nA==\n"
        result = detect_and_solve(data)
        assert result is not None

    def test_unknown_format(self):
        result = detect_and_solve(b"hello world nothing to see here")
        assert result is None


def _has_leading_zeros(h, bits):
    full = bits // 8
    rem = bits % 8
    for b in h[:full]:
        if b != 0:
            return False
    if rem > 0 and full < len(h):
        if h[full] & (0xFF << (8 - rem)):
            return False
    return True


def _has_trailing_zeros(h, bits):
    full = bits // 8
    rem = bits % 8
    for b in h[len(h) - full:]:
        if b != 0:
            return False
    if rem > 0 and full < len(h):
        if h[len(h) - 1 - full] & ((1 << rem) - 1):
            return False
    return True


# ---------------------------------------------------------------------------
# Stress tests — random combination loop over all parameters
# ---------------------------------------------------------------------------

_ALGOS    = ["sha256", "sha1"]
_POSITIONS = ["leading", "trailing"]
_CHARSETS  = ["bytes", "printable", "alphanumeric", "hex", "numeric"]


def _verify_suffix(prefix, algo, bits, position, suffix):
    h = (hashlib.sha256 if algo == "sha256" else hashlib.sha1)(prefix + suffix).digest()
    return _has_leading_zeros(h, bits) if position == "leading" else _has_trailing_zeros(h, bits)


def test_backend_reports():
    assert _BACKEND in ("rust", "python")


def test_random_combinations():
    """50 iterations over random (algo, position, bits 10-28, charset, prefix) combinations.

    Bits ≥ 25 will exercise the CUDA backend when available (GPU_MIN_BITS=25).
    Max bits capped at 19 when running on the pure-Python fallback.
    """
    max_bits = 19 if _BACKEND == "python" else 28
    rng = random.Random()
    for _ in range(50):
        algo     = rng.choice(_ALGOS)
        position = rng.choice(_POSITIONS)
        bits     = rng.randint(10, max_bits)
        charset  = rng.choice(_CHARSETS)
        prefix   = secrets.token_bytes(rng.randint(4, 20))

        result = _do_bruteforce(prefix, algo, bits, position, charset)
        assert result is not None, (
            f"no solution: algo={algo} pos={position} bits={bits} charset={charset}"
        )
        assert _verify_suffix(prefix, algo, bits, position, result), (
            f"wrong answer: algo={algo} pos={position} bits={bits} charset={charset} "
            f"prefix={prefix!r} suffix={result!r}"
        )


def test_random_combinations_gpu():
    """Same loop but with force_gpu=True — skipped when CUDA is not available.

    Forces GPU even below GPU_MIN_BITS so the kernel is exercised across
    the full parameter space without needing high difficulty every run.
    """
    if not _gpu_available():
        pytest.skip("CUDA backend not available")

    rng = random.Random()
    for _ in range(20):
        algo     = rng.choice(_ALGOS)
        position = rng.choice(_POSITIONS)
        bits     = rng.randint(10, 28)
        charset  = rng.choice(_CHARSETS)
        prefix   = secrets.token_bytes(rng.randint(4, 16))

        result = _do_bruteforce(prefix, algo, bits, position, charset, force_gpu=True)
        assert result is not None, (
            f"GPU returned None: algo={algo} pos={position} bits={bits} charset={charset}"
        )
        assert _verify_suffix(prefix, algo, bits, position, result), (
            f"GPU wrong answer: algo={algo} pos={position} bits={bits} charset={charset} "
            f"prefix={prefix!r} suffix={result!r}"
        )
