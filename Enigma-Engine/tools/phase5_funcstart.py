#!/usr/bin/env python3
"""Phase 5: Deep-dive on func_start and func_call extras.

For each binary, extract func_start and func_call extras, then:
1. Count by section (.text vs other)
2. Analyze first bytes / prologue patterns
3. Check if preceded by valid boundary bytes
4. Check if referenced by CALL (for func_start)
"""

import csv
import struct
import sys
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")

pairs = {
    "kernel32": ("enigma_kernel32_nopfix.csv", "ghidra_kernel32.csv", "stress/kernel32.dll"),
    "ntdll": ("enigma_ntdll_nopfix.csv", "ghidra_ntdll.csv", "stress/ntdll.dll"),
    "user32": ("enigma_user32_nopfix.csv", "ghidra_user32.csv", "stress/user32.dll"),
}

def load_pe(path):
    with open(path, 'rb') as f:
        dos_hdr = f.read(64)
        if dos_hdr[:2] != b'MZ':
            return None, [], [], []
        e_lfanew = struct.unpack_from('<I', dos_hdr, 0x3C)[0]
        f.seek(e_lfanew)
        nt_hdr = f.read(24)
        if nt_hdr[:4] != b'PE\x00\x00':
            return None, [], [], []
        num_sections = struct.unpack_from('<H', nt_hdr, 6)[0]
        opt_hdr_size = struct.unpack_from('<H', nt_hdr, 20)[0]
        f.seek(e_lfanew + 24)
        opt_hdr = f.read(opt_hdr_size)
        magic = struct.unpack('<H', opt_hdr[:2])[0]
        if magic == 0x10B:
            image_base = struct.unpack('<I', opt_hdr[28:32])[0]
        else:
            image_base = struct.unpack('<Q', opt_hdr[24:32])[0]
        f.seek(e_lfanew + 24 + opt_hdr_size)
        sections = []
        for _ in range(num_sections):
            raw = f.read(40)
            name = raw[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', raw[8:12])[0]
            vaddr = struct.unpack('<I', raw[12:16])[0]
            rsize = struct.unpack('<I', raw[16:20])[0]
            roff = struct.unpack('<I', raw[20:24])[0]
            sections.append({'name': name, 'vaddr': vaddr, 'vsize': vsize, 'roff': roff, 'rsize': rsize})
        return image_base, sections, magic, num_sections

def rva_to_section(sections, rva):
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return s['name']
    return '??'

def read_bytes(path, offset, size=16):
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            return f.read(size)
    except:
        return b''

# Known prologue patterns for classification
prologue_cats = {
    0x48: 'REX.W (mov/push/etc)',
    0x4C: 'REX.WR',
    0x55: 'PUSH RBP',
    0x8B: 'MOV',
    0x33: 'XOR (zero reg)',
    0x89: 'MOV [r], r',
    0x85: 'TEST',
    0x0F: '2-byte opcode',
    0xE8: 'CALL',
    0xE9: 'JMP',
    0xEB: 'SHORT JMP',
    0xC3: 'RET',
    0xCC: 'INT3',
    0x90: 'NOP',
    0x64: 'FS prefix',
    0x65: 'GS prefix',
    0x66: 'OPSIZE prefix',
    0xF2: 'REPNE prefix',
    0xF3: 'REPE prefix',
}

def prologue_desc(fb):
    return prologue_cats.get(fb, f'0x{fb:02X}')

for target in ['kernel32', 'ntdll', 'user32']:
    enigma_csv, ghidra_csv, bin_path = pairs[target]
    image_base, sections, _, _ = load_pe(BASE / bin_path)
    
    # Load Ghidra
    ghidra = set()
    with open(BASE / ghidra_csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            ghidra.add(int(row['address'], 16))
    
    # Load Enigma
    enigma = {}
    with open(BASE / enigma_csv, encoding='utf-8', errors='ignore') as f:
        hdr = False
        for line in f:
            line = line.strip()
            if line.startswith('address,type,name'):
                hdr = True; continue
            if not hdr: continue
            parts = line.split(',')
            addr = int(parts[0], 16)
            name = parts[2] if len(parts) > 2 else ''
            enigma[addr] = name
    
    print(f"\n{'='*60}")
    print(f"  {target.upper()}")
    print(f"{'='*60}")
    print(f"  Enigma: {len(enigma)}, Ghidra: {len(ghidra)}, Extras: {len(enigma) - len(ghidra & set(enigma.keys()))}")
    
    for cat_name in ['func_start', 'func_call']:
        entries = [(a, n) for a, n in enigma.items() if a not in ghidra and n.startswith(cat_name + '_')]
        if not entries:
            print(f"\n  {cat_name}: 0 entries")
            continue
        
        # Section distribution
        section_counts = Counter()
        first_bytes = Counter()
        boundary_ok = 0
        boundary_bad = 0
        
        for addr, name in entries:
            rva = addr - image_base
            sec = rva_to_section(sections, rva)
            section_counts[sec] += 1
            
            # Read first bytes
            for s in sections:
                if s['name'] == sec:
                    offset = rva - s['vaddr'] + s['roff']
                    break
            else:
                continue
            
            data = read_bytes(BASE / bin_path, offset, 8)
            if data:
                first_bytes[data[0]] += 1
            
                # Check boundary
                if offset > 0:
                    prev = read_bytes(BASE / bin_path, offset - 1, 1)
                    if prev and prev[0] in {0xCC, 0xC3, 0xE9, 0xEB, 0x00, 0x90, 0xC2}:
                        boundary_ok += 1
                    else:
                        boundary_bad += 1
        
        print(f"\n  {cat_name}: {len(entries)} entries")
        print(f"  Sections: {dict(section_counts.most_common())}")
        print(f"  Boundary OK: {boundary_ok}, Bad: {boundary_bad} ({'%.0f' % (boundary_ok/(boundary_ok+boundary_bad)*100 if (boundary_ok+boundary_bad) else 0)}% ok)")
        print(f"  Top first bytes:")
        for fb, cnt in first_bytes.most_common(10):
            print(f"    {prologue_desc(fb):>20}: {cnt:>5} ({cnt/len(entries)*100:.0f}%)")
        
        # For func_start: check if address starts with typical prologue patterns
        if cat_name == 'func_start':
            # Count how many have XOR-zero-prologue (33 C0, 33 C9, 33 D2, 33 DB)
            xor_zero = 0
            push_rbp = 0
            rex_48 = 0
            gs_prefix = 0  # TEB access prologue
            for addr, name in entries:
                rva = addr - image_base
                sec = rva_to_section(sections, rva)
                for s in sections:
                    if s['name'] == sec:
                        offset = rva - s['vaddr'] + s['roff']
                        break
                else:
                    continue
                data = read_bytes(BASE / bin_path, offset, 3)
                if data:
                    fb = data[0]
                    if fb == 0x33 and len(data) >= 2 and data[1] in {0xC0, 0xC9, 0xD2, 0xDB}:
                        xor_zero += 1
                    elif fb == 0x55:
                        push_rbp += 1
                    elif fb in {0x48, 0x4C}:
                        rex_48 += 1
                    elif fb in {0x64, 0x65}:
                        gs_prefix += 1
            print(f"  Prologue patterns:")
            print(f"    XOR-zero (33 XX): {xor_zero}")
            print(f"    PUSH RBP (55):    {push_rbp}")
            print(f"    REX.W (48/4C):    {rex_48}")
            print(f"    FS/GS (64/65):    {gs_prefix}")
            print(f"    Other:            {len(entries) - xor_zero - push_rbp - rex_48 - gs_prefix}")
