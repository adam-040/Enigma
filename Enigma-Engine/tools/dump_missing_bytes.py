#!/usr/bin/env python3
"""Hex dump of missing function addresses from binary."""
import sys, io, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"

# Missing function addresses (from Ghidra-only comparison)
missing = [
    0x140001008, 0x140001440, 0x140001460, 0x140001480, 0x1400014c0,
    0x1400015d0, 0x1400015f0, 0x140001630, 0x140001650, 0x140001670,
    0x140001690, 0x140001e70, 0x140002344, 0x1400068b0, 0x140007d30,
    0x140007d60, 0x14000b6c0, 0x14000d370, 0x140010140, 0x140011890,
    0x14001e800, 0x140020720, 0x140020730, 0x1400209d0, 0x140020a00,
    0x140022160, 0x140022b70, 0x140022ee0, 0x140022ef0, 0x140022f00,
    0x140022f10, 0x14002372a, 0x1400237b5, 0x1400237c7, 0x1400237d9,
    0x1400237eb, 0x1400237fd, 0x14002380f, 0x140023821, 0x140023833,
    0x140023845, 0x140023857, 0x140023869, 0x14002387b, 0x14002388d,
    0x1400238ab, 0x1400238c9, 0x1400238db, 0x1400249cc, 0x140024a00,
    0x140024b30, 0x140024c81, 0x140024c93, 0x140024d1e, 0x140024d30,
    0x140024d42, 0x140024d54, 0x140024d66, 0x140024d78, 0x140024d8a,
    0x140024d9c, 0x140024dae, 0x140024e39, 0x140024e4b, 0x140024ed6,
    0x140024ee8, 0x140024efa, 0x140024f0c, 0x140024f1e, 0x140024f30,
    0x140024f42, 0x140024f54, 0x140024fdf, 0x140024ff1, 0x140025003
]

with open(binary, 'rb') as f:
    f.seek(0x3C)
    e_lfanew = struct.unpack('<I', f.read(4))[0]
    f.seek(e_lfanew + 4 + 16)
    num_sections = struct.unpack('<H', f.read(2))[0]
    sizeof_opt = struct.unpack('<H', f.read(2))[0]
    
    f.seek(e_lfanew + 4 + 20 + sizeof_opt)
    sections = []
    for i in range(num_sections):
        name = f.read(8).rstrip(b'\x00').decode('ascii', errors='replace')
        vs = struct.unpack('<I', f.read(4))[0]
        va = struct.unpack('<I', f.read(4))[0]
        raw_size = struct.unpack('<I', f.read(4))[0]
        raw_ptr = struct.unpack('<I', f.read(4))[0]
        f.read(16)
        sections.append((name, va, vs, raw_size, raw_ptr))
    
    def read_at(addr, size):
        rva = addr - 0x140000000
        for sname, va, vs, raw_size, raw_ptr in sections:
            if va <= rva < va + vs:
                off = raw_ptr + (rva - va)
                if raw_size > off - raw_ptr:
                    f.seek(off)
                    return f.read(min(size, raw_size - (off - raw_ptr)))
                return None
        return None
    
    # Hex dump all missing addresses
    for addr in missing:
        data = read_at(addr, 16)
        if data is None:
            print(f"0x{addr:x} [NO DATA]")
        else:
            hex_str = ' '.join(f'{b:02x}' for b in data)
            ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in data)
            print(f"0x{addr:x} {hex_str:48s} {ascii_str}")
