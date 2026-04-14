"""
_CVarAccessor: bridges pwntools ELF symbols with ORC DWARF type info.

Used by _hijack.py to patch sym_obj onto pwntools ELF.
"""
from ._address import DWARFAddress


class _CVarAccessor:
    """
    Provides sym_obj['name'] access on a pwntools ELF: looks up the symbol
    address from the ELF and the type layout from ORC's DWARF cache, returning
    a DWARFAddress that supports field traversal.
    """
    def __init__(self, elf):
        self._elf = elf

    def __getitem__(self, name):
        orc = self._elf.orc
        orc._build_dwarf_cache()

        base_addr = self._elf.symbols.get(name)
        if base_addr is None:
            raise KeyError(f"Symbol '{name}' not found in ELF symbol table.")

        var_die_offset = orc._dwarf_vars.get(name)
        if not var_die_offset:
            raise KeyError(f"Variable '{name}' not found in DWARF info. Does it have debug symbols?")

        dwarfinfo = orc._get_dwarfinfo()
        var_die = dwarfinfo.get_DIE_from_refaddr(var_die_offset)
        type_die = orc._get_die_from_attr(var_die, 'DW_AT_type')

        if not type_die:
            raise KeyError(f"Missing type info for variable '{name}'.")

        return DWARFAddress(base_addr, orc, type_die.offset)

    def __contains__(self, name):
        orc = self._elf.orc
        orc._build_dwarf_cache()
        return name in self._elf.symbols and name in orc._dwarf_vars
