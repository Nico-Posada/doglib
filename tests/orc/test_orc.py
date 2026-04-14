"""
Tests for ORC core API (_orc.py, _cheader.py, _enum.py, _builtin_types.py,
and hijack patches: ELF.sym_obj / ELF.resolve_field).

Covers: enum, sizeof/offsetof/containerof/field_at/describe/resolve_type,
dot-path type navigation, ORCHeader/ORCInline setup, C64 built-in types,
resolve_field (hijack), bool base type, C++ class type labels, and
forward-declaration / declaration-skipping regressions.

Run from the project root:
    pytest tests/orc/test_orc.py
"""
import os

import pytest
from pwnlib.exception import PwnlibException

from doglib.orc import ORCHeader, ORCInline, C64


# ============================================================
# Enum
# ============================================================

def test_enum_constants(headers):
    state = headers.enum('State')
    assert state.IDLE == 0
    assert state.RUNNING == 1
    assert state.CRASHED == -1
    assert 'IDLE' in state
    assert 'NONEXISTENT' not in state


def test_enum_assignment_in_craft(headers):
    state = headers.enum('State')
    fb = headers.craft('FinalBoss')
    fb.current_state = state.CRASHED
    assert fb.current_state.value == 0xFFFFFFFF


def test_enum_iteration(headers):
    state = headers.enum('State')
    items = dict(state)
    assert items['IDLE'] == 0
    assert items['CRASHED'] == -1


def test_enum_missing_constant_raises(headers):
    state = headers.enum('State')
    with pytest.raises(AttributeError):
        _ = state.NONEXISTENT


def test_enum_repr(headers):
    state = headers.enum('State')
    r = repr(state)
    assert 'IDLE' in r and 'CRASHED' in r


def test_enum_bracket_access(headers):
    """enum['NAME'] returns the same value as enum.NAME."""
    state = headers.enum('State')
    assert state['IDLE']    == state.IDLE    == 0
    assert state['RUNNING'] == state.RUNNING == 1
    assert state['CRASHED'] == state.CRASHED == -1


def test_enum_bracket_missing_raises_key_error(headers):
    """enum['BOGUS'] raises KeyError, not AttributeError."""
    state = headers.enum('State')
    with pytest.raises(KeyError):
        _ = state['BOGUS']


# ============================================================
# sizeof / offsetof / containerof / resolve_type
# ============================================================

def test_sizeof_structs(headers):
    assert headers.sizeof('Basic') == 12
    assert headers.sizeof('ArrayFun') == 32
    assert headers.sizeof('FinalBoss') == 48
    assert headers.sizeof('EdgeCases') == 16


def test_sizeof_primitives(headers):
    assert headers.sizeof('int') == 4
    assert headers.sizeof('char') == 1
    assert headers.sizeof('short') == 2
    assert headers.sizeof('long long') == 8
    assert headers.sizeof('double') == 8
    assert headers.sizeof('unsigned short') == 2
    assert headers.sizeof('unsigned long') == 8


def test_sizeof_arrays(headers):
    assert headers.sizeof('int[100]') == 400
    assert headers.sizeof('char[16]') == 16
    assert headers.sizeof('Basic[3][2]') == 3 * 2 * headers.sizeof('Basic')


def test_sizeof_pointer(headers):
    assert headers.sizeof('int *') == 8


def test_offsetof(headers):
    assert headers.offsetof('Basic', 'a') == 0
    assert headers.offsetof('Basic', 'b') == 4
    assert headers.offsetof('Basic', 'c') == 8
    assert headers.offsetof('FinalBoss', 'matrix') == 8
    assert headers.offsetof('FinalBoss', 'matrix[1][2]') == 28
    assert headers.offsetof('FinalBoss', 'current_hp') == 40
    assert headers.offsetof('BossFight', 'u.data.raw') == 32


def test_offsetof_invalid_raises(headers):
    with pytest.raises(ValueError):
        headers.offsetof('Basic', 'nonexistent')


def test_containerof(headers):
    member_addr = 0x1000 + headers.offsetof('BossFight', 'u')
    base = headers.containerof('BossFight', 'u', member_addr)
    assert base == 0x1000


def test_containerof_va_wrapping(headers):
    mask = (1 << 64) - 1
    result = headers.containerof('Basic', 'b', 0x4)
    assert result == (0x4 - headers.offsetof('Basic', 'b')) & mask


# ============================================================
# field_at
# ============================================================

def test_field_at_basic_fields(headers):
    assert headers.field_at('Basic', 0) == 'a'
    assert headers.field_at('Basic', 4) == 'b'
    assert headers.field_at('Basic', 8) == 'c'


def test_field_at_mid_field(headers):
    assert headers.field_at('Basic', 5) == 'b+1'
    assert headers.field_at('Basic', 7) == 'b+3'
    assert headers.field_at('Basic', 9) == 'c+1'


def test_field_at_struct_padding_hole(headers):
    # Basic has a 3-byte padding hole between 'a' (offset 0..1) and 'b' (offset 4)
    assert headers.field_at('Basic', 1) == '+1'
    # ArrayFun has padding between int[5] (ends at 20) and char* ptr (at 24)
    assert headers.field_at('ArrayFun', 22) == '+22'


def test_field_at_array_indexing(headers):
    assert headers.field_at('ArrayFun', 0) == 'arr[0]'
    assert headers.field_at('ArrayFun', 4) == 'arr[1]'
    assert headers.field_at('ArrayFun', 16) == 'arr[4]'
    assert headers.field_at('ArrayFun', 19) == 'arr[4]+3'
    assert headers.field_at('ArrayFun', 24) == 'ptr'


def test_field_at_multidim_array(headers):
    assert headers.field_at('FinalBoss', 8) == 'matrix[0][0]'
    assert headers.field_at('FinalBoss', 28) == 'matrix[1][2]'
    assert headers.field_at('FinalBoss', 40) == 'current_hp'
    assert headers.field_at('MultiDimTest', 0) == 'grid[0][0]'
    assert headers.field_at('MultiDimTest', 28) == 'grid[1][3]'
    assert headers.field_at('MultiDimTest', 48) == 'cube[0][0][0]'
    assert headers.field_at('MultiDimTest', 62) == 'cube[1][0][2]'


def test_field_at_nested_struct(headers):
    assert headers.field_at('BossFight', 0) == 'b[0].a'
    assert headers.field_at('BossFight', 16) == 'b[1].b'
    # offset 28 is 4 bytes into u (which is UnionMadness), inside u.type (long)
    assert headers.field_at('BossFight', 28) == 'u.type+4'


def test_field_at_union(headers):
    # UnionMadness.data starts at offset 8; the union has overlapping members
    result = headers.field_at('UnionMadness', 8)
    assert isinstance(result, list)
    assert 'data.coords.x' in result
    assert 'data.raw[0]' in result

    result = headers.field_at('UnionMadness', 12)
    assert isinstance(result, list)
    assert 'data.coords.y' in result
    assert 'data.raw[4]' in result


def test_field_at_anonymous_members(headers):
    # AnonMember has a top-level int 'type', then an anonymous union, then an anonymous struct
    assert headers.field_at('AnonMember', 0) == 'type'
    result = headers.field_at('AnonMember', 4)
    assert isinstance(result, list)
    assert 'as_int' in result
    assert 'as_float' in result
    # the anonymous struct's named members are reachable directly
    assert headers.field_at('AnonMember', 8) == 'x'
    assert headers.field_at('AnonMember', 10) == 'y'


def test_field_at_out_of_bounds(headers):
    with pytest.raises(ValueError):
        headers.field_at('Basic', headers.sizeof('Basic'))
    with pytest.raises(ValueError):
        headers.field_at('Basic', 999)
    with pytest.raises(ValueError):
        headers.field_at('Basic', -1)


def test_field_at_inverse_of_offsetof(headers):
    """For each known (type, field), feed offsetof's result into field_at and
    confirm at least one returned path round-trips back to the same offset."""
    cases = [
        ('Basic', 'a'), ('Basic', 'b'), ('Basic', 'c'),
        ('ArrayFun', 'arr[0]'), ('ArrayFun', 'arr[3]'), ('ArrayFun', 'ptr'),
        ('FinalBoss', 'current_state'), ('FinalBoss', 'matrix[0][0]'),
        ('FinalBoss', 'matrix[1][2]'), ('FinalBoss', 'current_hp'),
        ('MultiDimTest', 'grid[2][3]'), ('MultiDimTest', 'cube[1][0][2]'),
        ('BossFight', 'b[0].a'), ('BossFight', 'b[1].c'),
        ('UnionMadness', 'type'),
    ]
    for type_name, path in cases:
        offset = headers.offsetof(type_name, path)
        result = headers.field_at(type_name, offset)
        results = [result] if isinstance(result, str) else result
        # at least one returned path should map back to the same offset
        assert any(headers.offsetof(type_name, r.split('+')[0]) == offset
                   for r in results if not r.startswith('+')), \
            f"field_at({type_name!r}, {offset}) = {result!r} did not round-trip {path!r}"


# ============================================================
# resolve_type / describe
# ============================================================

def test_resolve_type(headers):
    assert headers.resolve_type('State') == 'enum State'


def test_resolve_type_alias_short(headers):
    assert headers.resolve_type('short') == 'short int'


def test_describe_no_crash(headers):
    headers.describe('FinalBoss')
    headers.describe('AnonMember')


def test_describe_primitive_raises(headers):
    with pytest.raises(ValueError):
        headers.describe('int')


# ============================================================
# Dot-path type navigation: sizeof / craft / describe / cast / offsetof
# ============================================================

def test_sizeof_dotpath_struct_field(headers):
    """sizeof('BossFight.u') returns the size of the UnionMadness member."""
    assert headers.sizeof('BossFight.u') == headers.sizeof('UnionMadness')


def test_sizeof_dotpath_primitive_field(headers):
    """sizeof('FinalBoss.negative_val') returns 2 (short)."""
    assert headers.sizeof('FinalBoss.negative_val') == 2


def test_sizeof_dotpath_array_field(headers):
    """sizeof('FinalBoss.matrix') returns total bytes of the array."""
    # int matrix[2][3] -> 2 * 3 * 4 = 24 bytes
    assert headers.sizeof('FinalBoss.matrix') == 24


def test_sizeof_dotpath_deep(headers):
    """sizeof('BossFight.u.data.coords') returns size of coords struct."""
    # coords has two ints: 8 bytes
    assert headers.sizeof('BossFight.u.data.coords') == 8


def test_sizeof_dotpath_invalid_base(headers):
    """sizeof('NoSuchType.field') raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        headers.sizeof('NoSuchType.field')


def test_sizeof_dotpath_invalid_field(headers):
    """sizeof('Basic.nonexistent') raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        headers.sizeof('Basic.nonexistent')


def test_sizeof_through_array_field(headers):
    """sizeof('BossFight.b.a') resolves through Basic[2] to char -> 1 byte."""
    assert headers.sizeof('BossFight.b.a') == 1
    assert headers.sizeof('BossFight.b.b') == 4


def test_craft_dotpath_struct_field(headers):
    """craft('BossFight.u') creates a crafter for UnionMadness."""
    m = headers.craft('BossFight.u')
    assert len(bytes(m)) == headers.sizeof('UnionMadness')


def test_craft_dotpath_assigns_correctly(headers):
    """craft('BossFight.u') crafter supports normal field writes."""
    m = headers.craft('BossFight.u')
    m.type = 0x1234
    assert m.type.value == 0x1234


def test_craft_dotpath_primitive_field(headers):
    """craft('FinalBoss.negative_val') creates a 2-byte crafter."""
    m = headers.craft('FinalBoss.negative_val')
    assert len(bytes(m)) == 2


def test_craft_dotpath_with_array_suffix(headers):
    """craft('Basic.b[3]') creates an array-crafter for 3 ints."""
    import struct as _struct
    arr = headers.craft('Basic.b[3]')
    arr[0] = 10
    arr[1] = 20
    arr[2] = 30
    vals = _struct.unpack('<iii', bytes(arr))
    assert vals == (10, 20, 30)


def test_craft_array_of_struct_field(headers):
    """craft('BossFight.b') returns a crafter for Basic[2], indexable into Basic elements."""
    arr = headers.craft('BossFight.b')
    arr[0].a = ord('X')
    arr[0].b = 0x41414141
    arr[1].c = 99
    raw = bytes(arr)
    assert len(raw) == headers.sizeof('Basic') * 2
    reparsed = headers.parse('Basic', raw)
    assert reparsed.a.value == ord('X')
    assert reparsed.b.value == 0x41414141


def test_describe_dotpath(headers, capsys):
    """describe('BossFight.u') prints layout for UnionMadness, not BossFight."""
    headers.describe('BossFight.u')
    out = capsys.readouterr().out
    assert 'BossFight.u' in out
    assert 'union' in out
    assert 'type' in out
    assert 'data' in out
    lines = [l for l in out.splitlines() if '0x' in l]
    field_names = {l.split()[-1] for l in lines}
    assert 'b' not in field_names, f"BossFight field 'b' leaked into describe output: {out}"


def test_describe_dotpath_invalid(headers):
    """describe on a primitive field raises ValueError (not a struct/union)."""
    with pytest.raises(ValueError):
        headers.describe('FinalBoss.negative_val')


def test_describe_array_of_struct(headers, capsys):
    """describe('BossFight.b') unwraps through the array to describe Basic."""
    headers.describe('BossFight.b')
    out = capsys.readouterr().out
    assert 'struct' in out
    assert 'element of [2]' in out
    lines = [l for l in out.splitlines() if '0x' in l]
    field_names = {l.split()[-1] for l in lines}
    assert field_names == {'a', 'b', 'c'}


def test_describe_nested_through_array(headers, capsys):
    """describe('GlobalTest.arr.ptr') unwraps ArrayFun[] to describe ptr's type (a pointer, which should fail)."""
    with pytest.raises(ValueError, match="not a struct/union"):
        headers.describe('GlobalTest.arr.ptr')


def test_offsetof_through_array_field(headers):
    """offsetof through an array-of-struct field resolves element member offsets."""
    off_b_a = headers.offsetof('BossFight', 'b.a')
    off_b_b = headers.offsetof('BossFight', 'b.b')
    assert off_b_a == headers.offsetof('BossFight', 'b')
    assert off_b_b == off_b_a + headers.offsetof('Basic', 'b')

    off_indexed = headers.offsetof('BossFight', 'b[1].b')
    assert off_indexed == off_b_a + headers.sizeof('Basic') + headers.offsetof('Basic', 'b')


def test_cast_dotpath_offset_adjustment(headers):
    """cast('BossFight.u', base_addr) returns an address offset by the field's position."""
    u_offset = headers.offsetof('BossFight', 'u')
    base = 0x10000
    result = headers.cast('BossFight.u', base)
    assert int(result) == base + u_offset


def test_cast_dotpath_deep_field(headers):
    """cast('BossFight.u.data.raw', base_addr) adjusts for the nested offset."""
    base = 0x20000
    raw_offset = headers.offsetof('BossFight', 'u.data.raw')
    result = headers.cast('BossFight.u.data.raw', base)
    assert int(result) == base + raw_offset


def test_cast_dotpath_no_dotpath_unchanged(headers):
    """cast without a dot-path still returns address unchanged (regression)."""
    base = 0x30000
    result = headers.cast('Basic', base)
    assert int(result) == base


# ============================================================
# C64 built-in type sizes
# ============================================================

def test_c64_stdint_types():
    assert C64.sizeof('uint64_t') == 8
    assert C64.sizeof('uint32_t') == 4
    assert C64.sizeof('uint8_t') == 1
    assert C64.sizeof('int64_t') == 8
    assert C64.sizeof('size_t') == 8
    assert C64.sizeof('ptrdiff_t') == 8


# ============================================================
# ELF hijack patches: sym_obj / resolve_field
# ============================================================

def test_resolve_field_symbol_base(chal_pwn_elf):
    assert chal_pwn_elf.resolve_field('target_sym') == chal_pwn_elf.symbols['target_sym']


def test_resolve_field_with_explicit_struct_name(chal_pwn_elf):
    expected = int(chal_pwn_elf.sym_obj['target_sym'].arr[2].ptr)
    assert chal_pwn_elf.resolve_field('target_sym', 'arr[2].ptr', struct_name='GlobalTest') == expected


def test_resolve_field_invalid_path_raises(chal_pwn_elf):
    with pytest.raises(PwnlibException):
        chal_pwn_elf.resolve_field('target_sym', 'arr[2].does_not_exist')


def test_resolve_field_missing_symbol_raises(chal_pwn_elf):
    with pytest.raises(PwnlibException):
        chal_pwn_elf.resolve_field('does_not_exist', 'arr[0]')


# ============================================================
# ORCHeader / ORCInline setup
# ============================================================

def test_cheader_include_dirs(tmp_path):
    inc = tmp_path / 'include'
    inc.mkdir()
    (inc / 'inner.h').write_text(
        "typedef struct inner {\n"
        "    int field_value;\n"
        "} inner;\n"
    )
    (tmp_path / 'outer.h').write_text(
        '#include "inner.h"\n'
        "typedef struct outer {\n"
        "    inner field;\n"
        "} outer;\n"
    )

    hdr = ORCHeader(str(tmp_path / 'outer.h'), include_dirs=[str(inc)])
    outer = hdr.craft('outer')
    outer.field.field_value = 7

    assert outer.field.field_value.value == 7


def test_cheader_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ORCHeader(str(tmp_path / 'missing.h'))


def test_cheader_invalid_header_raises():
    with pytest.raises(PwnlibException):
        ORCInline(
            "typedef struct broken {\n"
            "    int value;\n"
            "    @\n"
            "} broken;\n"
        )


def test_bool_base_type_round_trip():
    hdr = ORCInline(
        "typedef struct boolish {\n"
        "    _Bool flag;\n"
        "} boolish;\n"
    )
    obj = hdr.craft('boolish')

    obj.flag = 0
    assert obj.flag.value is False

    obj.flag = 1
    assert obj.flag.value is True


# ============================================================
# C++ class type labels (DW_TAG_class_type)
# ============================================================

def test_describe_cpp_class_label(change_to_test_dir, capsys):
    """describe() labels DW_TAG_class_type as 'class', not 'union'."""
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.orc import ORC
    elf = ORC('./challenge_cpp')
    elf.describe('Coords')
    out = capsys.readouterr().out
    assert out.startswith('class ')
    assert 'union' not in out.lower()


def test_get_type_name_cpp_class(change_to_test_dir):
    """get_type_name returns 'class Foo' for DW_TAG_class_type, not 'union Foo'."""
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.orc import ORC
    elf = ORC('./challenge_cpp')
    die = elf._get_type_die('Coords')
    name = elf._get_type_name(die)
    assert 'class' in name
    assert 'union' not in name


def test_describe_includes_inherited_fields(change_to_test_dir, capsys):
    """describe() shows inherited base-class fields for C++ classes."""
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.orc import ORC
    elf = ORC('./challenge_cpp')
    elf.describe('Player')
    out = capsys.readouterr().out
    assert 'health' in out
    assert 'id' in out
    assert 'name' in out
    assert 'weapon' in out


# ============================================================
# Regression: forward-declaration skipping
# ============================================================

def test_declaration_skipping_python_parser():
    """Python parser skips DW_AT_declaration and keeps the full definition."""
    t = ORCInline('''
        struct opaque;
        struct opaque { int x; int y; };
    ''')
    assert t.sizeof('opaque') == 8
    c = t.craft('opaque')
    c.x = 1; c.y = 2
    assert c.x.value == 1
    assert c.y.value == 2
