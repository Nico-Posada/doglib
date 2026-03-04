#!/usr/bin/env python3
from pwn import *

from doglib.extelf import CHeader, ExtendedELF

# Load our types
headers = CHeader("complex_structs.h")

# Ensure you compile the challenge first: gcc challenge.c -o challenge -g -no-pie
# We load it with ExtendedELF so we can parse its global variables!
chal_elf = ExtendedELF("./challenge")

io = process("./challenge")

# --- LEVEL 1: Padding & Basics ---
log.info("Solving Level 1...")
basic = headers.craft('Basic')
basic.a = ord('X')
basic.b = 0x1337
basic.c = 0x42
io.sendafter(b"Basic\n", bytes(basic))

# --- LEVEL 2: Arrays & Pointers ---
log.info("Solving Level 2...")
arr_fun = headers.craft('ArrayFun')
arr_fun.arr[0] = 10
arr_fun.arr[4] = 50
arr_fun.ptr = 0xdeadbeef
io.sendafter(b"ArrayFun\n", bytes(arr_fun))

# --- LEVEL 3: Unions & Anonymous Structs ---
log.info("Solving Level 3...")
union_madness = headers.craft('UnionMadness')
union_madness.type = 1
union_madness.data.coords.x = 0x11223344
union_madness.data.coords.y = 0x55667788
io.sendafter(b"UnionMadness\n", bytes(union_madness))

# --- LEVEL 4: Deep Nesting & Array Bytes ---
log.info("Solving Level 4...")
boss = headers.craft('BossFight')
boss.b[1].a = ord('Z')
boss.b[1].b = 999
boss.u.data.raw = b"AAAAAAAW"
io.sendafter(b"BossFight\n", bytes(boss))

# --- LEVEL 5: Truncation & Overflows ---
log.info("Solving Level 5...")
edge = headers.craft('EdgeCases')
edge.small_int = 0xdeadbeef 
edge.small_buf = b"AAAA\x00TRASH_DATA_THAT_GETS_DROPPED"
edge.big_int = -1
io.sendafter(b"EdgeCases\n", bytes(edge))

# --- LEVEL 6: DWARF Array Strides & Offset Math ---
log.info("Solving Level 6...")
target_addr = int(chal_elf.sym_obj['target_sym'].arr[2].ptr)

log.info(f"Dynamically calculated array sub-field address: {hex(target_addr)}")
io.sendafter(b"(8 bytes)\n", p64(target_addr))

# --- LEVEL 7: Enums, Signed Values, Multi-Dimensional Arrays, & Floats ---
log.info("Solving Level 7...")
final = headers.craft('FinalBoss')
final.current_state = -1  # CRASHED (Tests setting Enums natively)

# For negative integer masking (-1337 mathematically translates to 0xfac7 on unsigned bounds).
final.negative_val = -1337

# DWARF physically flattens multi-dimensional C arrays in memory. 
# We access matrix[1][2] dynamically by flattening the index (row * NUM_COLS) + col -> (1 * 3) + 2 = [5]
final.matrix[5] = 9999

# Python floats/doubles are now naturally serialized!
final.max_hp = 1000.5
final.current_hp = 1337.75

io.sendafter(b"FinalBoss\n", bytes(final))

io.interactive()