#!/usr/bin/env python3
"""Verify .pdata entries for the 31 unknown missing functions."""
import struct

binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"

with open(binary, 'rb') as f:
    data = f.read()

# Parse sections
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
fh = e_lfanew + 4
num_sections = struct.unpack_from('<H', data, fh+2)[0]
sizeof_opt = struct.unpack_from('<H', data, fh+16)[0]
sec_table = fh + 20 + sizeof_opt

sections = {}
for i in range(num_sections):
    off = sec_table + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vs = struct.unpack_from('<I', data, off+8)[0]
    va = struct.unpack_from('<I', data, off+12)[0]
    raw_size = struct.unpack_from('<I', data, off+16)[0]
    raw_ptr = struct.unpack_from('<I', data, off+20)[0]
    sections[name] = {'va': va, 'vs': vs, 'raw_size': raw_size, 'raw_ptr': raw_ptr}

# Read .pdata
IMAGE_BASE = 0x140000000
pdata_sec = sections['.pdata']
pdata_off = pdata_sec['raw_ptr']
pdata_size = min(pdata_sec['raw_size'], pdata_sec['vs'])  # use raw for file, vs for memory

# Parse entries
pdata_entries = []
for i in range(pdata_size // 12):
    off = pdata_off + i * 12
    brva = struct.unpack_from('<I', data, off)[0]
    erva = struct.unpack_from('<I', data, off+4)[0]
    urva = struct.unpack_from('<I', data, off+8)[0]
    if brva == 0 and erva == 0 and urva == 0:
        continue
    pdata_entries.append({
        'begin': IMAGE_BASE + brva,
        'end': IMAGE_BASE + (erva & 0x7fffffff),
        'begin_rva': brva,
        'unwind_rva': urva & 0x7fffffff
    })

print(f"Total .pdata entries: {len(pdata_entries)}")
print()

# Build set of all pdata begin addresses
pdata_begins = set(e['begin'] for e in pdata_entries)

# Load Enigma and Ghidra addresses
import csv
enigma_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_enigma_functions.csv"
ghidra_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_ghidra_functions.csv"

enigma_addrs = set()
with open(enigma_csv, 'r') as f:
    for row in csv.reader(f):
        if not row: continue
        try: enigma_addrs.add(int(row[0].strip(), 16))
        except: pass

ghidra_funcs = {}
with open(ghidra_csv, 'r') as f:
    for row in csv.reader(f):
        if not row: continue
        try:
            addr = int(row[0].strip(), 16)
            ghidra_funcs[addr] = row[-1].strip() if len(row) > 1 else ""
        except: pass

missing = sorted(set(ghidra_funcs.keys()) - enigma_addrs)
print(f"Missing total: {len(missing)}")
print()

# CLASSIFY: For each missing address, check various sources
delay_thunk_names = {a for a in missing if ghidra_funcs.get(a, '').startswith('DelayLoad_')}
print(f"Delay-load thunks: {len(delay_thunk_names)}")

# Check .pdata coverage
in_pdata = {a for a in missing if a in pdata_begins}
print(f"Missing but in .pdata: {len(in_pdata)}")
for a in sorted(in_pdata):
    e = [e for e in pdata_entries if e['begin'] == a][0]
    print(f"  0x{a:x} begin=0x{e['begin_rva']:x} end=0x{e['end']:x} size={e['end']-e['begin']}")

# Check the remaining
other = set(missing) - delay_thunk_names - in_pdata
print(f"\nRemaining (non-delay, non-pdata): {len(other)}")

# For these, check if they're inside any .pdata span
for a in sorted(other):
    name = ghidra_funcs.get(a, "???")
    inside_pdata = False
    for e in pdata_entries:
        if e['begin'] < a < e['end']:
            inside_pdata = True
            break
    print(f"  0x{a:x} {name:50s} inside_pdata_span={inside_pdata}")
