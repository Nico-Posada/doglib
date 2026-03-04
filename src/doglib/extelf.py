import os
import pickle
import hashlib
import subprocess
import tempfile
import struct
from pwn import *
from elftools.elf.elffile import ELFFile

# GPT slopped extension to ELF
# lets you do struct math on symbols (if the elf has debuginfo)
'''
libc = ExtendedELF('./libc.so.6')
libc.address = 0x7ffff7a00000  # PIE slides are automatically respected dynamically!
target_fd = libc.sym_obj['main_arena'].bins[3].fd
'''
# can also cast things as structs
'''
heap_chunk_addr = 0x55555555b000
chunk_struct = libc.cast('malloc_chunk', heap_chunk_addr)
log.info(f"Size field is at: {hex(chunk_struct.size)}") 
'''
# can also craft structs!
'''
chunk = j.craft("malloc_chunk")
chunk.mchunk_prev_size = 0x420
chunk.fd = 0x123456789
chunk.bk_nextsize = 0x11037
bytes(chunk) # in memory
'''
# also if the headers are in a .h file (like exported from ida) you can use that too
'''
structs = CHeader("custom_structs.h")
payload = structs.craft("MyVulnerableStruct")
payload.buffer = b"A" * 64
payload.func_ptr = 0xdeadbeef
'''
# i have not battle-tested all of this but it seems to mostly work
# and if it doesn't then just yell at your own ai agent and submit a pr #ILoveVibeCoding
# feel free to merge this into pwntools


class DWARFAddress(int):
    """
    An integer subclass representing a memory address that retains its C-type.
    Allows attribute access (obj.field) and indexing (obj[index]).
    """
    def __new__(cls, value, elf, type_die_offset):
        obj = super().__new__(cls, value)
        obj._elf = elf
        obj._type_die_offset = type_die_offset
        return obj

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
            
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        
        if current_die.tag == 'DW_TAG_pointer_type':
            log.error(f"Cannot statically resolve through a pointer at '.{name}'. Dereference first.")
            raise AttributeError(name)
            
        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")
            
        for child in current_die.iter_children():
            if child.tag == 'DW_TAG_member':
                name_attr = child.attributes.get('DW_AT_name')
                if name_attr and name_attr.value.decode('utf-8') == name:
                    loc = child.attributes.get('DW_AT_data_member_location')
                    member_offset = 0
                    
                    if loc:
                        if isinstance(loc.value, int):
                            member_offset = loc.value
                        elif isinstance(loc.value, list) and len(loc.value) > 0:
                            if loc.value[0] == 0x23: 
                                val, shift = 0, 0
                                for b in loc.value[1:]:
                                    val |= (b & 0x7f) << shift
                                    if (b & 0x80) == 0: break
                                    shift += 7
                                member_offset = val
                                
                    next_type_die = self._elf._get_die_from_attr(child, 'DW_AT_type')
                    if not next_type_die:
                        raise AttributeError(f"Missing type info for field '{name}'")
                        
                    return DWARFAddress(int(self) + member_offset, self._elf, next_type_die.offset)
                    
        raise AttributeError(f"Field '{name}' not found in struct")

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")
            
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        
        if current_die.tag == 'DW_TAG_pointer_type':
            log.error(f"Cannot statically index a pointer variable. Dereference first.")
            raise IndexError(index)
            
        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError(f"Cannot index into non-array type {current_die.tag}")
            
        elem_type = self._elf._unwrap_type(self._elf._get_die_from_attr(current_die, 'DW_AT_type'))
        elem_size = self._elf._get_byte_size(elem_type)
        
        return DWARFAddress(int(self) + (index * elem_size), self._elf, elem_type.offset)


class DWARFCrafter:
    """
    A mutable byte-array wrapper that allows C-style struct member assignments.
    Calling bytes(obj) yields the fully crafted memory structure.
    """
    def __init__(self, elf, type_die_offset, backing=None, offset=0):
        # Bypass __setattr__ for internal initialization
        super().__setattr__('_elf', elf)
        super().__setattr__('_type_die_offset', type_die_offset)
        
        dwarfinfo = elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(type_die_offset)
        current_die = elf._unwrap_type(die)
        size = elf._get_byte_size(current_die)
        
        super().__setattr__('_size', size)
        super().__setattr__('_offset', offset)
        
        if backing is None:
            super().__setattr__('_backing', bytearray(size))
        else:
            super().__setattr__('_backing', backing)

    def __bytes__(self):
        return bytes(self._backing[self._offset : self._offset + self._size])

    def __repr__(self):
        hex_data = bytes(self).hex()
        preview = hex_data[:32] + ('...' if len(hex_data) > 32 else '')
        return f"<DWARFCrafter size={self._size} data={preview}>"

    def _get_field_info(self, name):
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        
        if current_die.tag == 'DW_TAG_pointer_type':
            raise AttributeError(f"Cannot resolve through a pointer at '.{name}'. Set the pointer directly.")
            
        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")
            
        for child in current_die.iter_children():
            if child.tag == 'DW_TAG_member':
                name_attr = child.attributes.get('DW_AT_name')
                if name_attr and name_attr.value.decode('utf-8') == name:
                    loc = child.attributes.get('DW_AT_data_member_location')
                    member_offset = 0
                    
                    if loc:
                        if isinstance(loc.value, int):
                            member_offset = loc.value
                        elif isinstance(loc.value, list) and len(loc.value) > 0:
                            if loc.value[0] == 0x23: 
                                val, shift = 0, 0
                                for b in loc.value[1:]:
                                    val |= (b & 0x7f) << shift
                                    if (b & 0x80) == 0: break
                                    shift += 7
                                member_offset = val
                                
                    next_type_die = self._elf._get_die_from_attr(child, 'DW_AT_type')
                    if not next_type_die:
                        raise AttributeError(f"Missing type info for field '{name}'")
                        
                    return member_offset, next_type_die
                    
        raise AttributeError(f"Field '{name}' not found in struct")

    def _get_elem_info(self, index):
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")
            
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        
        if current_die.tag == 'DW_TAG_pointer_type':
            raise TypeError("Cannot index a pointer in struct crafter. Set the pointer address directly.")
            
        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError(f"Cannot index into non-array type {current_die.tag}")
            
        elem_type = self._elf._unwrap_type(self._elf._get_die_from_attr(current_die, 'DW_AT_type'))
        elem_size = self._elf._get_byte_size(elem_type)
        return index * elem_size, elem_type

    def _write_value(self, offset, type_die, value):
        size = self._elf._get_byte_size(type_die)
        absolute_offset = self._offset + offset
        
        if isinstance(value, int):
            byte_order = 'little' if self._elf.little_endian else 'big'
            # Bitwise mask prevents OverflowError for negative integers and automatically trims
            val_bytes = (value & ((1 << (size * 8)) - 1)).to_bytes(size, byteorder=byte_order)
        elif isinstance(value, float):
            byte_order = '<' if self._elf.little_endian else '>'
            if size == 4:
                val_bytes = struct.pack(byte_order + 'f', value)
            elif size == 8:
                val_bytes = struct.pack(byte_order + 'd', value)
            else:
                raise ValueError(f"Unsupported float size {size} for struct crafting")
        elif isinstance(value, bytes):
            # Pad string/bytes payloads with null terminators automatically
            val_bytes = value.ljust(size, b'\x00')[:size]
        else:
            raise TypeError(f"Unsupported type {type(value)} for struct crafting (must be int, float, or bytes)")
            
        self._backing[absolute_offset : absolute_offset + size] = val_bytes

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        member_offset, member_type_die = self._get_field_info(name)
        return DWARFCrafter(self._elf, member_type_die.offset, self._backing, self._offset + member_offset)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            return super().__setattr__(name, value)
        member_offset, member_type_die = self._get_field_info(name)
        self._write_value(member_offset, member_type_die, value)

    def __getitem__(self, index):
        elem_offset, elem_type_die = self._get_elem_info(index)
        return DWARFCrafter(self._elf, elem_type_die.offset, self._backing, self._offset + elem_offset)

    def __setitem__(self, index, value):
        elem_offset, elem_type_die = self._get_elem_info(index)
        self._write_value(elem_offset, elem_type_die, value)


class _CVarAccessor:
    def __init__(self, elf):
        self._elf = elf
        
    def __getitem__(self, name):
        self._elf._build_dwarf_cache()
        
        base_addr = self._elf.symbols.get(name)
        if base_addr is None:
            raise KeyError(f"Symbol '{name}' not found in ELF symbol table.")
            
        var_die_offset = self._elf._dwarf_vars.get(name)
        if not var_die_offset:
            raise KeyError(f"Variable '{name}' not found in DWARF info. Does it have debug symbols?")
            
        dwarfinfo = self._elf._get_dwarfinfo()
        var_die = dwarfinfo.get_DIE_from_refaddr(var_die_offset)
        type_die = self._elf._get_die_from_attr(var_die, 'DW_AT_type')
        
        if not type_die:
            raise KeyError(f"Missing type info for variable '{name}'.")
            
        return DWARFAddress(base_addr, self._elf, type_die.offset)


class ExtendedELF(ELF):
    """
    An extension of the pwntools ELF class that adds support for resolving 
    complex C-struct offsets dynamically using DWARF debug information.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dwarf_vars = {}
        self._dwarf_types = {}
        self._dwarf_parsed = False
        self._dwarf_file = None
        self._dwarfinfo = None
        
        # The intuitive C-style accessor (e.g., libc.sym_obj['main_arena'].bins[3].fd)
        self.sym_obj = _CVarAccessor(self)

    def _get_dwarfinfo(self):
        """Lazy-loads and caches the DWARF info to avoid reopening the file repeatedly."""
        if self._dwarfinfo is None:
            self._dwarf_file = open(self.path, 'rb')
            elffile = ELFFile(self._dwarf_file)
            if elffile.has_dwarf_info():
                self._dwarfinfo = elffile.get_dwarf_info()
        return self._dwarfinfo

    def _get_die_from_attr(self, die, attr_name):
        """Helper to follow DWARF type references (e.g., DW_AT_type)."""
        if attr_name not in die.attributes: return None
        attr = die.attributes[attr_name]
        offset = attr.value
        
        # Relative references need the Compilation Unit's base offset added
        if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_udata'):
            offset += die.cu.cu_offset
            
        return die.cu.dwarfinfo.get_DIE_from_refaddr(offset)

    def _unwrap_type(self, die):
        """Strips away typedefs, const, and volatile modifiers to get the real underlying type."""
        while die and die.tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type'):
            die = self._get_die_from_attr(die, 'DW_AT_type')
        return die

    def _get_byte_size(self, die):
        """Recursively determines the byte size of a DWARF type (useful for array indexing strides)."""
        die = self._unwrap_type(die)
        if not die: return 0
        
        if 'DW_AT_byte_size' in die.attributes:
            return die.attributes['DW_AT_byte_size'].value
            
        # Pointers don't always declare byte size, derive it from ELF architecture
        if die.tag == 'DW_TAG_pointer_type':
            return self.elfclass // 8
            
        # Enums sometimes omit byte_size natively depending on optimizations
        if die.tag == 'DW_TAG_enumeration_type':
            return 4
            
        # Arrays derive size from element count * element size
        if die.tag == 'DW_TAG_array_type':
            elem_type = self._unwrap_type(self._get_die_from_attr(die, 'DW_AT_type'))
            elem_size = self._get_byte_size(elem_type)
            count = 1
            has_subrange = False
            for child in die.iter_children():
                # DWARF multi-dimensional arrays declare multiple subranges. 
                # We must multiply them together! (e.g., int[3][4] = 12 elements)
                if child.tag == 'DW_TAG_subrange_type':
                    has_subrange = True
                    if 'DW_AT_count' in child.attributes:
                        count *= child.attributes['DW_AT_count'].value
                    elif 'DW_AT_upper_bound' in child.attributes:
                        count *= (child.attributes['DW_AT_upper_bound'].value + 1)
            return (elem_size * count) if has_subrange else 0
        return 0

    def _build_dwarf_cache(self):
        """Parses the DWARF tree and caches variable/struct DIE offsets to disk to save time."""
        if self._dwarf_parsed: return
        
        extelf_cache_dir = os.path.join(context.cache_dir, 'extelf_cache')
        os.makedirs(extelf_cache_dir, exist_ok=True)

        bid = self.buildid.hex() if hasattr(self, 'buildid') and self.buildid else (os.path.basename(self.path) + str(os.path.getsize(self.path)))
        cache_file = os.path.join(extelf_cache_dir, f"dwarf_cache_v4_{bid}.pkl")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'rb') as f:
                    self._dwarf_vars, self._dwarf_types = pickle.load(f)
                self._dwarf_parsed = True
                return
            except Exception as e:
                log.warning(f"Failed to load DWARF cache: {e}. Rebuilding...")

        log.info(f"Parsing DWARF info for {os.path.basename(self.path)}... (This will be cached)")
        dwarfinfo = self._get_dwarfinfo()
        if not dwarfinfo:
            log.warning("ELF has no DWARF info. Path resolution won't work.")
            self._dwarf_parsed = True
            return
            
        for CU in dwarfinfo.iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag in ('DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_typedef'):
                    name_attr = die.attributes.get('DW_AT_name')
                    if name_attr:
                        name = name_attr.value.decode('utf-8', errors='ignore')
                        if die.tag == 'DW_TAG_variable':
                            self._dwarf_vars[name] = die.offset
                        else:
                            self._dwarf_types[name] = die.offset
                            
        os.makedirs(extelf_cache_dir, exist_ok=True)
        with open(cache_file, 'wb') as f:
            pickle.dump((self._dwarf_vars, self._dwarf_types), f)
        self._dwarf_parsed = True

    def cast(self, type_name, address):
        """
        Cast an arbitrary memory address to a DWARF C-type object.
        Example: libc.cast_c_type('malloc_chunk', 0x55555555b000).fd
        """
        self._build_dwarf_cache()
        type_die_offset = self._dwarf_types.get(type_name)
        if not type_die_offset:
            raise ValueError(f"Struct/Type '{type_name}' not found in DWARF info.")
        return DWARFAddress(address, self, type_die_offset)

    def craft(self, type_name):
        """
        Creates a byte-backed structure that allows assigning C-fields dynamically.
        Use bytes(obj) to extract the raw crafted payload.
        
        Example: 
            chunk = libc.craft_struct('malloc_chunk')
            chunk.size = 0x21
            chunk.fd = 0xdeadbeef
            payload = bytes(chunk)
        """
        self._build_dwarf_cache()
        type_die_offset = self._dwarf_types.get(type_name)
        if not type_die_offset:
            raise ValueError(f"Struct/Type '{type_name}' not found in DWARF info.")
        return DWARFCrafter(self, type_die_offset)

    def resolve_field(self, symbol_name, field_path=None, struct_name=None):
        """
        Dynamically calculates the exact memory address of a field inside a struct/array.
        """
        base_addr = self.symbols.get(symbol_name)
        if base_addr is None:
            log.error(f"Symbol '{symbol_name}' not found in standard ELF symbol table.")
            return None

        if not field_path:
            return base_addr

        tokens = []
        for part in field_path.replace(']', '').split('['):
            for subpart in part.split('.'):
                if subpart:
                    tokens.append(int(subpart) if subpart.isdigit() else subpart)

        self._build_dwarf_cache()
        
        dwarfinfo = self._get_dwarfinfo()
        start_die_offset = None
        
        if struct_name:
            start_die_offset = self._dwarf_types.get(struct_name)
            if not start_die_offset:
                log.error(f"Struct '{struct_name}' not found in DWARF info.")
                return None
        else:
            var_die_offset = self._dwarf_vars.get(symbol_name)
            if not var_die_offset:
                log.error(f"Variable '{symbol_name}' not found in DWARF info. Try passing struct_name explicitly.")
                return None
            var_die = dwarfinfo.get_DIE_from_refaddr(var_die_offset)
            type_die = self._get_die_from_attr(var_die, 'DW_AT_type')
            if not type_die: return None
            start_die_offset = type_die.offset
                
        current_die = dwarfinfo.get_DIE_from_refaddr(start_die_offset)
        offset_accumulator = 0
        
        for token in tokens:
            current_die = self._unwrap_type(current_die)
            
            if current_die.tag == 'DW_TAG_pointer_type':
                log.error(f"Cannot statically resolve through a pointer at token '{token}'. You must read memory manually in your exploit.")
                return None
            
            if isinstance(token, int):
                if current_die.tag != 'DW_TAG_array_type':
                    log.error(f"Expected array type for index '{token}', got {current_die.tag}")
                    return None
                elem_type = self._unwrap_type(self._get_die_from_attr(current_die, 'DW_AT_type'))
                elem_size = self._get_byte_size(elem_type)
                offset_accumulator += token * elem_size
                current_die = elem_type
                
            else:
                if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                    log.error(f"Expected struct/union for field '{token}', got {current_die.tag}")
                    return None
                
                found = False
                for child in current_die.iter_children():
                    if child.tag == 'DW_TAG_member':
                        name_attr = child.attributes.get('DW_AT_name')
                        if name_attr and name_attr.value.decode('utf-8') == token:
                            loc = child.attributes.get('DW_AT_data_member_location')
                            member_offset = 0
                            
                            if loc:
                                if isinstance(loc.value, int):
                                    member_offset = loc.value
                                elif isinstance(loc.value, list) and len(loc.value) > 0:
                                    if loc.value[0] == 0x23: 
                                        val, shift = 0, 0
                                        for b in loc.value[1:]:
                                            val |= (b & 0x7f) << shift
                                            if (b & 0x80) == 0: break
                                            shift += 7
                                        member_offset = val
                                        
                            offset_accumulator += member_offset
                            current_die = self._get_die_from_attr(child, 'DW_AT_type')
                            found = True
                            break
                            
                if not found:
                    log.error(f"Field '{token}' not found in struct.")
                    return None
                    
        return base_addr + offset_accumulator


class CHeader(ExtendedELF):
    """
    Takes a C header file, automatically compiles it into a temporary ELF 
    with standalone DWARF symbols via GCC, and wraps it in an ExtendedELF interface.
    """
    def __init__(self, header_path, **kwargs):
        header_path = os.path.abspath(header_path)
        if not os.path.exists(header_path):
            raise FileNotFoundError(f"Header file not found: {header_path}")

        # Hash the header content to allow intelligent caching
        with open(header_path, 'rb') as f:
            header_data = f.read()
            
        header_hash = hashlib.sha256(header_data).hexdigest()[:16]
        
        extelf_cache_dir = os.path.join(context.cache_dir, 'extelf_cache')
        os.makedirs(extelf_cache_dir, exist_ok=True)
        
        # Bumped to v4 to force a rebuild with the new GCC flags
        elf_path = os.path.join(extelf_cache_dir, f"cheader_v4_{header_hash}.elf")

        if not os.path.exists(elf_path):
            log.info(f"Compiling {os.path.basename(header_path)} to DWARF ELF...")
            try:
                # Use GCC to directly compile the header as C code and keep unused debug types
                cmd = ['gcc', '-x', 'c', '-c', '-g', '-fno-eliminate-unused-debug-types', header_path, '-o', elf_path]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                log.error("Failed to compile header: 'gcc' is not installed or not in PATH.")
                raise
            except subprocess.CalledProcessError as e:
                log.error(f"GCC failed to compile the header. Syntax error? Details:\n{e.stderr.decode() if e.stderr else ''}")
                raise

        kwargs.setdefault('checksec', False)
        super().__init__(elf_path, **kwargs)