"""Tests for doglib.flagguesser."""

from __future__ import annotations

from doglib.flagguesser import CTFFREQ, CTFFREQ_ALL, Guesser, NGramModel, guesser

CORPUS = [
    b"flag{aaa}",
    b"flag{aab}",
    b"flag{abc}",
    b"flag{aaz}",
    b"flag{aaq}",
]


def make_guesser(order: int = 5) -> Guesser:
    m = NGramModel(order=order)
    m.fit(CORPUS)
    return Guesser(m)


def test_guess_returns_256_single_byte_objects():
    g = make_guesser()
    for prefix in [b"", b"f", b"flag{", b"flag{xyzzy"]:
        out = g.guess(prefix)
        assert len(out) == 256
        assert all(isinstance(b, bytes) and len(b) == 1 for b in out)
        assert len({bytes(b) for b in out}) == 256


def test_guess_ranks_obvious_continuation_first():
    g = make_guesser()
    assert g.guess(b"flag{")[0] == b"a"
    assert g.guess(b"flag{aa")[0] == b"a"


def test_stats_mode_returns_tuples_summing_to_one():
    g = make_guesser()
    pairs = g.guess(b"flag{th", stats=True)
    assert len(pairs) == 256
    assert all(isinstance(t, tuple) and len(t) == 2 for t in pairs)
    assert all(0 <= b <= 255 and isinstance(p, float) for b, p in pairs)
    total = sum(p for _, p in pairs)
    assert abs(total - 1.0) < 1e-9
    probs = [p for _, p in pairs]
    assert probs == sorted(probs, reverse=True)


def test_determinism():
    g = make_guesser()
    assert g.guess(b"flag{a") == g.guess(b"flag{a")


def test_save_load_roundtrip(tmp_path):
    m = NGramModel(order=4)
    m.fit(CORPUS)
    path = tmp_path / "m.json.gz"
    m.save(str(path))
    m2 = NGramModel.load(str(path))
    g1, g2 = Guesser(m), Guesser(m2)
    assert g1.guess(b"flag{") == g2.guess(b"flag{")
    assert g1.guess(b"flag{", stats=True) == g2.guess(b"flag{", stats=True)


def test_empty_prefix_uses_start_anchor():
    g = make_guesser()
    assert g.guess(b"")[0] == b"f"


def test_unseen_bytes_have_nonzero_probability():
    g = make_guesser()
    pairs = g.guess(b"flag{aa", stats=True)
    assert all(p > 0 for _, p in pairs)


def test_ctffreq_contains_printable_ascii():
    assert b"_" in CTFFREQ
    assert b"{" in CTFFREQ
    assert b"}" in CTFFREQ
    assert len(CTFFREQ) > 0


def test_ctffreq_all_covers_full_byte_range():
    assert len(set(CTFFREQ_ALL)) == 256


def test_bundled_guesser_works():
    # The pre-instantiated bundled guesser should produce sane output.
    out = guesser.guess(b"flag{")
    assert len(out) == 256
    assert all(isinstance(b, bytes) and len(b) == 1 for b in out)


def test_dog_star_import():
    # Verify the three names reach `from dog import *`.
    import dog
    assert hasattr(dog, "CTFFREQ")
    assert hasattr(dog, "CTFFREQ_ALL")
    assert hasattr(dog, "guesser")
