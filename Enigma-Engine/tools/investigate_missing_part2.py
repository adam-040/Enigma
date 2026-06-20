#!/usr/bin/env python3
"""Deeper investigation of the 25 unknown and 3 pdata misses."""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import csv

binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"
enigma_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_enigma_functions.csv"
ghidra_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_ghidra_functions.csv"

# Load Enigma addresses
enigma_addrs = set()
with open(enigma_csv, 'r') as f:
    for row in csv.reader(f):
        if not row: continue
        try: enigma_addrs.add(int(row[0].strip(), 16))
        except: pass

# Load Ghidra addresses
ghidra_funcs = {}
with open(ghidra_csv, 'r') as f:
    for row in csv.reader(f):
        if not row: continue
        try:
            addr = int(row[0].strip(), 16)
            ghidra_funcs[addr] = row[-1].strip() if len(row) > 1 else ""
        except: pass

missing = sorted(set(ghidra_funcs.keys()) - enigma_addrs)
print(f"Ghidra has {len(ghidra_funcs)} funcs, Enigma has {len(enigma_addrs)}")
print(f"Missing: {len(missing)}")

# Parse binary to get bytes
with open(binary, 'rb') as f:
    # Quick PE parse
    f.seek(0x3C)
    e_lfanew = int.from_bytes(f.read(4), 'little')
    f.seek(e_lfanew + 4 + 16)  # skip sig + machine + sections + timestamp + symtab ptr
    num_sections = int.from_bytes(f.read(2), 'little')
    sizeof_opt = int.from_bytes(f.read(2), 'little')
    
    # Read sections
    f.seek(e_lfanew + 4 + 20 + sizeof_opt)
    sections = {}
    for i in range(num_sections):
        name = f.read(8).rstrip(b'\x00').decode('ascii', errors='ignore')
        vs = int.from_bytes(f.read(4), 'little')
        va = int.from_bytes(f.read(4), 'little')
        raw_size = int.from_bytes(f.read(4), 'little')
        raw_ptr = int.from_bytes(f.read(4), 'little')
        f.read(16)
        sections[name] = {'va': va, 'vs': vs, 'raw_size': raw_size, 'raw_ptr': raw_ptr}
    
    def read_bytes_at(addr, size):
        rva = addr - 0x140000000
        for sname, sec in sections.items():
            if sec['va'] <= rva < sec['va'] + sec['vs']:
                off = sec['raw_ptr'] + (rva - sec['va'])
                avail = sec['raw_size'] - (off - sec['raw_ptr'])
                if avail <= 0:
                    return None
                f.seek(off)
                return f.read(min(size, avail))
        return None
    
    def addr_in_section(addr):
        rva = addr - 0x140000000
        for sname, sec in sections.items():
            if sec['va'] <= rva < sec['va'] + sec['vs']:
                return sname
        return "???"
    
    def find_nearest_enigma(addr):
        if not enigma_addrs: return None
        nearest = min(enigma_addrs, key=lambda x: abs(x - addr))
        if abs(nearest - addr) <= 64:
            return nearest, addr - nearest
        return None, None

    def find_nearest_ghidra(addr, n=10):
        """Find nearest n Ghidra functions"""
        ret = []
        for a in sorted(ghidra_funcs.keys()):
            if a != addr:
                ret.append((a, a - addr))
        ret.sort(key=lambda x: abs(x[1]))
        return ret[:n]

    print()
    print("=" * 80)
    print("ANALYSIS OF 25 UNKNOWN MISSING FUNCTIONS")
    print("=" * 80)
    
    unknowns = [
        0x140001440, 0x140001460, 0x140001480, 0x1400014c0,
        0x1400015d0, 0x1400015f0, 0x140001630, 0x140001650,
        0x140001670, 0x140001690, 0x140001e70,
        0x140007d30,
        0x14000d370, 0x140010140, 0x140011890, 0x14001e800,
        0x140020720, 0x1400209d0, 0x140020a00, 0x140022160,
        0x140022b70, 0x140022ee0, 0x140022ef0, 0x140022f00,
        0x140024a00
    ]
    
    for addr in unknowns:
        name = ghidra_funcs.get(addr, "???")
        sec = addr_in_section(addr)
        near_ef, offset = find_nearest_enigma(addr)
        near_ghidra = find_nearest_ghidra(addr, 3)
        
        bytes_ = read_bytes_at(addr, 12)
        hex_str = ' '.join(f'{b:02x}' for b in (bytes_ or b''))
        
        print(f"\n0x{addr:x} ({name})")
        print(f"  Section: {sec}")
        print(f"  Bytes: {hex_str}")
        if near_ef:
            print(f"  Nearest Enigma: 0x{near_ef:x} (offset={offset:+d})")
            ebytes = read_bytes_at(near_ef, 12)
            print(f"  Enigma bytes: {' '.join(f'{b:02x}' for b in (ebytes or b''))}")
        else:
            print(f"  Nearest Enigma: N/A (>64 bytes away)")
        
        print(f"  Nearest Ghidra: ", end="")
        for a, d in near_ghidra[:3]:
            print(f"0x{a:x}({d:+d}) ", end="")
        print()

    print()
    print("=" * 80)
    print("ANALYSIS OF 3 MISSED .PDATA ENTRIES")
    print("=" * 80)
    
    pdata_misses = [0x140001008, 0x140002344, 0x1400249cc]
    for addr in pdata_misses:
        name = ghidra_funcs.get(addr, "???")
        bytes_ = read_bytes_at(addr, 16)
        hex_str = ' '.join(f'{b:02x}' for b in (bytes_ or b''))
        
        near_ef, offset = find_nearest_enigma(addr)
        
        print(f"\n0x{addr:x} ({name})")
        print(f"  Bytes: {hex_str}")
        if near_ef:
            print(f"  Nearest Enigma: 0x{near_ef:x} (offset={offset:+d})")
            ebytes = read_bytes_at(near_ef, 12)
            print(f"  Enigma bytes: {' '.join(f'{b:02x}' for b in (ebytes or b''))}")
        
        # Check if this address is between two Enigma functions
        enigma_sorted = sorted(enigma_addrs)
        for i, ea in enumerate(enigma_sorted):
            if ea > addr:
                if i > 0:
                    print(f"  Previous Enigma func: 0x{enigma_sorted[i-1]:x} (distance={addr - enigma_sorted[i-1]})")
                print(f"  Next Enigma func: 0x{ea:x} (distance={ea - addr})")
                break
