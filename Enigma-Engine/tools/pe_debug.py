#!/usr/bin/env python3
"""Debug PE section parsing."""
import struct

binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"

with open(binary, 'rb') as f:
    data = f.read()

# Read e_lfanew at offset 0x3C (4 bytes little-endian)
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
print(f"e_lfanew = 0x{e_lfanew:x}")

# Verify PE signature
sig = data[e_lfanew:e_lfanew+4]
print(f"PE sig = {sig}")
assert sig == b'PE\x00\x00'

# File header (20 bytes after signature)
fh = e_lfanew + 4
machine = struct.unpack_from('<H', data, fh)[0]
num_sections = struct.unpack_from('<H', data, fh+2)[0]
timestamp = struct.unpack_from('<I', data, fh+4)[0]
ptr_symtab = struct.unpack_from('<I', data, fh+8)[0]
num_symbols = struct.unpack_from('<I', data, fh+12)[0]
sizeof_opt = struct.unpack_from('<H', data, fh+16)[0]
characteristics = struct.unpack_from('<H', data, fh+18)[0]

print(f"num_sections = {num_sections}")
print(f"sizeof_opt = {sizeof_opt}")
print(f"machine = 0x{machine:x}")

# Optional header: starts at fh + 20
oh = fh + 20
magic = struct.unpack_from('<H', data, oh)[0]
print(f"magic = 0x{magic:04x} {'PE32+' if magic == 0x20b else 'PE32' if magic == 0x10b else 'UNKNOWN'}")

# Section table: starts at fh + 20 + sizeof_opt
sec_table = fh + 20 + sizeof_opt
print(f"Section table at offset 0x{sec_table:x}")

sections = []
for i in range(num_sections):
    off = sec_table + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vs = struct.unpack_from('<I', data, off+8)[0]
    va = struct.unpack_from('<I', data, off+12)[0]
    raw_size = struct.unpack_from('<I', data, off+16)[0]
    raw_ptr = struct.unpack_from('<I', data, off+20)[0]
    sections.append((name, va, vs, raw_size, raw_ptr))
    print(f"  {name:8s} va=0x{va:05x} vs=0x{vs:05x} raw_size=0x{raw_size:05x} raw_ptr=0x{raw_ptr:05x}")
    # Verify: read first 4 bytes from raw_ptr
    if raw_ptr > 0 and raw_size > 0:
        first_bytes = data[raw_ptr:raw_ptr+4]
        print(f"    First bytes: {' '.join(f'{b:02x}' for b in first_bytes)}")

# Now test read_at for specific addresses
def read_at(addr, size):
    rva = addr - 0x140000000
    for name, va, vs, raw_size, raw_ptr in sections:
        if va <= rva < va + vs:
            off = raw_ptr + (rva - va)
            if off >= 0 and off + size <= len(data):
                return data[off:off+size]
            elif off >= 0:
                return data[off:]
            return None
    return None

# Test a specific address
test_addrs = [0x140001008, 0x140001440, 0x14002372a, 0x1400249cc, 0x1400267e8]
for addr in test_addrs:
    rva = addr - 0x140000000
    sname = "???"
    for name, va, vs, _, _ in sections:
        if va <= rva < va + vs:
            sname = name
            break
    data_ = read_at(addr, 12)
    if data_:
        h = ' '.join(f'{b:02x}' for b in data_)
        print(f"\n0x{addr:x} (section={sname})")
        print(f"  {h}")
    else:
        print(f"\n0x{addr:x} (section={sname}) [NO DATA]")
