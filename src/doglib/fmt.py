from pwnlib.memleak import MemLeak
from pwnlib.dynelf import DynELF
# Various helper functions for format string exploits.


def write_data(data, *args, **kwargs):
    pass


"""
A class for dumping an ELF with an arbitrary read.
NOTE: this doesn't really work (like at all)
because the loaded segments in virtual memory aren't the entire ELF, so you can't really just dump and run it.
you can probably do some hacky stuff to get it running (ex. parse link map to find all libraries and offsets) but GL with that.
i think IDA can load it tho
"""
class DumpELF:
    def __init__(self, leak, addr):
        self.leak = leak
        self.addr = addr

    # Read 'n' bytes at 'addr' using 'leak'.
    # 'leak' is a user-provided function that takes a single argument, 'addr', and will leak 1 or more bytes at 'addr'
    def grab(self,addr,n):
        # print(f"trying to read {addr:#x}")
        output = b""
        while len(output) <= n:
            # print(f"trying to read {addr:#x}")
            leak = self.leak(addr)
            output += leak
            addr += len(leak)
        return output[:n]

    # Dump an ELF.
    # Similar to DynELF, but we try to dump *everything* instead of just specific things.
    def dump_elf(self):
        addr = self.addr
        addr &= ~0xfff
        base = None
        
        # find base
        while base is None:
            data = self.grab(addr, 4)
            base = addr if data == b'\x7fELF' else None
            addr -= 0x1000
        
        # now begin leaking elf
        data = b""
        try:
            while True:
                data += self.grab(base,0x1000)
                base += 0x1000
        except Exception as e: # probably crashed trying to read invalid addr
            pass
        return data
