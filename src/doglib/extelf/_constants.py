"""
Centralised DWARF-related constants and small utilities for the extelf module.
"""

# Tags that are transparent wrappers (stripped by _unwrap_type)
PASSTHROUGH_TAGS = (
    'DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
    'DW_TAG_restrict_type', 'DW_TAG_atomic_type',
)

# Aggregate tags: struct, class, union
STRUCT_TAGS = ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type')

# Scalar/leaf tags that have a single numeric value
PRIMITIVE_TAGS = ('DW_TAG_base_type', 'DW_TAG_pointer_type', 'DW_TAG_enumeration_type')

# Tags indexed when building the DWARF cache (pyelftools fallback)
CACHEABLE_TAGS = (
    'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_class_type',
    'DW_TAG_union_type', 'DW_TAG_typedef', 'DW_TAG_enumeration_type',
    'DW_TAG_base_type',
)


def dims_str(dims):
    """'[2][3]'-style string from an iterable of dimension sizes."""
    return ''.join(f'[{d}]' for d in dims)


def inner_count(dims):
    """Product of all dimensions after the first (stride of the outermost dim)."""
    result = 1
    for d in dims[1:]:
        if d is None:
            return 1
        result *= d
    return result


def va_mask(bits):
    """VA-space mask for the given bit width (e.g. 0xffffffff for 32-bit)."""
    return (1 << bits) - 1


def array_stride(elf, array_die, subrange_start=0):
    """
    Compute stride and element type for indexing into a DWARF array type.
    Returns (stride, elem_type, remaining_len) where:
      - stride: bytes per outermost index
      - elem_type: unwrapped DIE of the element type
      - remaining_len: number of dimensions remaining (1 = scalar element)
    """
    subranges = elf._get_array_subranges(array_die)
    remaining = subranges[subrange_start:]
    elem_type = elf._unwrap_type(elf._get_die_from_attr(array_die, 'DW_AT_type'))
    elem_size = elf._get_byte_size(elem_type)
    stride = elem_size
    for dim in remaining[1:]:
        stride *= dim
    return stride, elem_type, len(remaining)
