# packing module that's also not named something that would collide with pwntools
# probably not gonna be much here tbh
from pwnlib.util.packing import u64

def b(n: int|str):
    return str(n).encode()

def ua(b: bytes):
    u64(b.ljust(8, b"\0")[:8])

__all__ = ["b", "ua"]