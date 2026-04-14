"""
Tests for DWARFAddress and DWARFArray (_address.py).

Covers address arithmetic, VA-space wrapping, pointer indexing,
array iteration and slicing.

Run from the project root:
    pytest tests/orc/test_address.py
"""
import pytest
from pwnlib.util.packing import p64

from doglib.orc import DWARFAddress


# ============================================================
# DWARFAddress repr & sym_obj
# ============================================================

def test_dwarf_address_repr(chal_pwn_elf):
    r = repr(chal_pwn_elf.sym_obj['target_sym'])
    assert 'DWARFAddress' in r
    assert 'type=' in r


def test_sym_obj_contains(chal_pwn_elf):
    assert 'target_sym' in chal_pwn_elf.sym_obj
    assert 'nonexistent_var' not in chal_pwn_elf.sym_obj


# ============================================================
# DWARFAddress arithmetic
# ============================================================

def test_dwarf_address_arithmetic(headers):
    mask = (1 << 64) - 1
    base = headers.cast('Basic', 0x1000)

    # add preserves type and value
    nxt = base + 0x20
    assert isinstance(nxt, DWARFAddress)
    assert int(nxt) == 0x1020
    assert int(nxt.b) == 0x1020 + headers.offsetof('Basic', 'b')

    # sub preserves type
    prv = base - 0x10
    assert isinstance(prv, DWARFAddress)
    assert int(prv) == 0x0FF0

    # sub of two DWARFAddresses returns plain int
    other = headers.cast('Basic', 0x1020)
    diff = other - base
    assert not isinstance(diff, DWARFAddress)
    assert diff == 0x20

    # radd
    radd_result = 0x100 + base
    assert isinstance(radd_result, DWARFAddress)
    assert int(radd_result) == 0x1100

    # VA wrapping
    near_max = headers.cast('Basic', 0xffffffffffffff00)
    wrapped = near_max + 0x200
    assert int(wrapped) == (0xffffffffffffff00 + 0x200) & mask

    # p64 compatibility
    assert p64(nxt) == p64(0x1020)


def test_dwarf_address_field_error(headers):
    int_addr = headers.cast('int', 0x5000)
    with pytest.raises(AttributeError):
        _ = int_addr.somefield


def test_dwarf_address_index_error(headers):
    int_addr = headers.cast('int', 0x5000)
    with pytest.raises(TypeError):
        _ = int_addr[0]


# ============================================================
# Virtual-address space
# ============================================================

def test_va_space_wrapping(headers):
    mask = (1 << 64) - 1
    base = 0xffffffffffffff00
    va_arr = headers.cast('int', base, count=1000)
    assert int(va_arr[100]) == (base + 100 * 4) & mask
    chunk_va = headers.cast('Basic', 0xfffffffffffffff0)
    assert int(chunk_va.b) == (0xfffffffffffffff0 + headers.offsetof('Basic', 'b')) & mask


def test_pointer_cast(headers):
    mask = (1 << 64) - 1
    ptr = headers.cast('int *', 0x1000)
    assert int(ptr[0]) == 0x1000
    assert int(ptr[520292]) == 0x1000 + 520292 * 4
    assert int(ptr[-1]) == (0x1000 - 4) & mask


def test_pointer_indexing_on_dwarf_address(headers):
    af = headers.cast('ArrayFun', 0x5000)
    ptr_field = af.ptr
    assert int(ptr_field[0]) == int(ptr_field)
    assert int(ptr_field[10]) == int(ptr_field) + 10


def test_exact_va_wrap(headers):
    ptr = headers.cast('long long *', 0x1000)
    wrap_idx = (1 << 64) // 8
    assert int(ptr[wrap_idx]) == 0x1000


# ============================================================
# DWARFArray iteration, slice, len
# ============================================================

def test_dwarf_array_iter(headers):
    it = headers.cast('Basic[3]', 0x1000)
    addrs = list(it)
    assert len(addrs) == 3
    sz = headers.sizeof('Basic')
    for i, addr in enumerate(addrs):
        assert int(addr) == 0x1000 + i * sz


def test_dwarf_array_iter_unbounded_raises(headers):
    ptr = headers.cast('Basic *', 0x2000)
    with pytest.raises(TypeError):
        list(ptr)


def test_dwarf_array_slice(headers):
    bounded = headers.cast('Basic[5]', 0x3000)
    sliced = bounded[1:4]
    assert isinstance(sliced, list) and len(sliced) == 3
    bs = headers.sizeof('Basic')
    assert int(sliced[0]) == 0x3000 + 1 * bs
    assert int(sliced[2]) == 0x3000 + 3 * bs


def test_dwarf_array_slice_unbounded_raises(headers):
    with pytest.raises(TypeError):
        _ = headers.cast('int *', 0x4000)[1:3]


def test_dwarf_array_len_unbounded_raises(headers):
    with pytest.raises(TypeError):
        len(headers.cast('int *', 0x4000))
