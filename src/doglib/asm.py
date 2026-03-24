from keystone import *
from capstone import *

"""
Assembly/disassembly functions because pwntools is freakishly slow.

Only x86/ARM support because every other ISA is made up to sell more CPUs.
"""

def ks_asm(arch, mode, code):
    ks = Ks(arch, mode)
    encoding, count = ks.asm(code)
    return bytes(encoding)

def asm_x64(code):
    return ks_asm(KS_ARCH_X86, KS_MODE_64, code)
    
def asm_x86(code):
    return ks_asm(KS_ARCH_X86, KS_MODE_32, code)

def asm_arm(code):
    return ks_asm(KS_ARCH_ARM, KS_MODE_ARM, code)

def asm_arm64(code):
    return ks_asm(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, code)
    
def cs_disasm_str(arch, mode, code, addr=0):
    md = Cs(arch, mode)
    instructions = md.disasm(code, addr)
    return "\n".join(f"{insn.mnemonic} {insn.op_str};" for insn in instructions)

def dis_x64(code, addr=0):
    return cs_disasm_str(CS_ARCH_X86, CS_MODE_64, code, addr)

def dis_x86(code, addr=0):
    return cs_disasm_str(CS_ARCH_X86, CS_MODE_32, code, addr)

def dis_arm(code, addr=0):
    return cs_disasm_str(CS_ARCH_ARM, CS_MODE_ARM, code, addr)

def dis_arm64(code, addr=0):
    return cs_disasm_str(CS_ARCH_ARM64, CS_MODE_ARM, code, addr)
