#!/usr/bin/env python3
"""Dump all 75 missing addresses with disassembly-like comments."""
import struct

binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"

with open(binary, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
fh = e_lfanew + 4
num_sections = struct.unpack_from('<H', data, fh+2)[0]
sizeof_opt = struct.unpack_from('<H', data, fh+16)[0]
oh = fh + 20
sec_table = fh + 20 + sizeof_opt

sections = []
for i in range(num_sections):
    off = sec_table + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vs = struct.unpack_from('<I', data, off+8)[0]
    va = struct.unpack_from('<I', data, off+12)[0]
    raw_size = struct.unpack_from('<I', data, off+16)[0]
    raw_ptr = struct.unpack_from('<I', data, off+20)[0]
    sections.append({'name': name, 'va': va, 'vs': vs, 'raw_size': raw_size, 'raw_ptr': raw_ptr})

def read_at(addr, size):
    rva = addr - 0x140000000
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vs']:
            off = s['raw_ptr'] + (rva - s['va'])
            return data[off:off+size] if off + size <= len(data) else data[off:]
    return None

def addr_section(addr):
    rva = addr - 0x140000000
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vs']:
            return s['name']
    return '??'

# All missing addresses from comparison
all_missing = [
    0x140001440, 0x140001460, 0x140001480, 0x1400014c0,
    0x1400015d0, 0x1400015f0, 0x140001630, 0x140001650,
    0x140001670, 0x140001690, 0x140001e70, 0x140002344,
    0x1400068b0, 0x140007d30, 0x140007d60, 0x14000b6c0,
    0x14000d370, 0x140010140, 0x140011890, 0x14001e800,
    0x140020720, 0x140020730, 0x1400209d0, 0x140020a00,
    0x140022160, 0x140022b70, 0x140022ee0, 0x140022ef0,
    0x140022f00, 0x140022f10, 0x14002372a, 0x1400237b5,
    0x1400237c7, 0x1400237d9, 0x1400237eb, 0x1400237fd,
    0x14002380f, 0x140023821, 0x140023833, 0x140023845,
    0x140023857, 0x140023869, 0x14002387b, 0x14002388d,
    0x1400238ab, 0x1400238c9, 0x1400238db, 0x1400249cc,
    0x140024a00, 0x140024b30, 0x140024c81, 0x140024c93,
    0x140024d1e, 0x140024d30, 0x140024d42, 0x140024d54,
    0x140024d66, 0x140024d78, 0x140024d8a, 0x140024d9c,
    0x140024dae, 0x140024e39, 0x140024e4b, 0x140024ed6,
    0x140024ee8, 0x140024efa, 0x140024f0c, 0x140024f1e,
    0x140024f30, 0x140024f42, 0x140024f54, 0x140024fdf,
    0x140024ff1, 0x140025003
]

print(f"Total addresses: {len(all_missing)}")
print()
print(f"{'Address':>18s} {'Section':8s} {'Bytes':46s} {'Pattern'}")
print("="*120)

for addr in all_missing:
    bytes_ = read_at(addr, 16)
    sec = addr_section(addr)
    if bytes_ is None:
        print(f"0x{addr:016x}  {sec:8s}  [NO DATA]")
        continue
    hex_str = ' '.join(f'{b:02x}' for b in bytes_[:12])
    hex_str = hex_str.ljust(35)
    
    # Detect pattern
    pattern = ""
    if bytes_[0] == 0x48 and bytes_[1] == 0x8d:
        if bytes_[2] == 0x05 or bytes_[2] == 0x0d or bytes_[2] == 0x15 or bytes_[2] == 0x1d:
            pattern = "LEA RIP-REL (possible delay-load / import helper)"
        else:
            pattern = "LEA (possible function start)"
    elif bytes_[0] == 0x48 and bytes_[1] in (0x89, 0x8b) and bytes_[2] in (0x5c, 0x74, 0x6c, 0x4c, 0x54):
        pattern = "Standard x64 function prologue"
    elif bytes_[0] == 0x48 and bytes_[1:3] == b'\x83\xec':
        pattern = "SUB RSP (function start)"
    elif bytes_[0] == 0x48 and bytes_[1:3] == b'\x81\xec':
        pattern = "SUB RSP,large (function prologue)"
    elif bytes_[0] == 0x4c and bytes_[1:3] == b'\x8b\xdc':
        pattern = "MOV R11,RSP (function prologue)"
    elif bytes_[0] == 0xcc:
        pattern = "INT3 (padding)"
    elif bytes_[0] == 0xe9:
        pattern = "JMP (thunk/tail call)"
    elif bytes_[0] == 0xeb:
        pattern = "SHORT JMP"
    elif bytes_[0] == 0xff and bytes_[1] == 0x25:
        pattern = "JMP [RIP+offset] (import thunk)"
    elif bytes_[0] == 0x48 and bytes_[1] == 0xff and bytes_[2] == 0x25:
        pattern = "JMP [RIP+offset] (import thunk, REX)"
    elif bytes_[0] == 0x40 and bytes_[1] == 0x53:
        pattern = "PUSH RBX (prologue)"
    elif bytes_[0] == 0x53 and bytes_[1] == 0x56:
        pattern = "PUSH RBX,RSI (prologue)"
    elif bytes_[0] == 0x48 and bytes_[1:4] == b'\x8b\xc4\x48':
        pattern = "MOV RAX,RSP / SUB RSP (prologue)"
    
    if bytes_[1] == 0xff and bytes_[2] == 0x25:
        target = struct.unpack_from('<i', bytes_, 3)[0]
        pattern = f"JMP [RIP{target:+d}] (import thunk)"
    
    if not pattern:
        if bytes_[0] in (0x48, 0x4c, 0x40):
            pattern = "REX-prefixed instruction (possible code)"
        else:
            pattern = "Unknown"
    
    print(f"0x{addr:016x}  {sec:8s}  {hex_str}  {pattern}")
