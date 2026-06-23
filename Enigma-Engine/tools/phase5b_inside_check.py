#!/usr/bin/env python3
"""Phase 5b: Check if func_start entries fall inside Ghidra functions."""

import csv
import struct
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")

pairs = {
    "kernel32": ("enigma_kernel32_nopfix.csv", "ghidra_kernel32.csv", "stress/kernel32.dll"),
    "ntdll": ("enigma_ntdll_nopfix.csv", "ghidra_ntdll.csv", "stress/ntdll.dll"),
    "user32": ("enigma_user32_nopfix.csv", "ghidra_user32.csv", "stress/user32.dll"),
}

for target in ['kernel32', 'ntdll', 'user32']:
    enigma_csv, ghidra_csv, _ = pairs[target]
    
    # Load Ghidra function ranges
    ghidra_ranges = {}
    with open(BASE / ghidra_csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = int(row['address'], 16)
            size = int(row['size'], 16) if row.get('size', '').strip() else 0
            ghidra_ranges[addr] = size
    
    # Sort Ghidra addresses
    ghidra_addrs = sorted(ghidra_ranges.keys())
    
    # Build interval list for fast lookup
    intervals = []
    for addr, size in ghidra_ranges.items():
        end = addr + size if size > 0 else addr + 1
        intervals.append((addr, end, size))
    intervals.sort()
    
    def find_containing_function(target_addr):
        """Return the Ghidra function containing target_addr, or None."""
        for start, end, sz in intervals:
            if start <= target_addr < end:
                return start, end, sz
            if start > target_addr:
                break
        return None
    
    # Load Enigma func_start extras
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
    
    ghidra_set = set(ghidra_ranges.keys())
    
    print(f"\n{'='*60}")
    print(f"  {target.upper()} — func_start inside Ghidra functions")
    print(f"{'='*60}")
    
    for cat in ['func_start', 'func_call']:
        entries = [(a, n) for a, n in enigma.items() if a not in ghidra_set and n.startswith(cat + '_')]
        inside = 0
        outside = 0
        inside_set = set()
        
        for addr, name in entries:
            container = find_containing_function(addr)
            if container:
                inside += 1
                inside_set.add(container[0])
            else:
                outside += 1
        
        print(f"\n  {cat}: {len(entries)} entries")
        print(f"    Inside Ghidra function: {inside} ({inside/len(entries)*100:.0f}%) — FALSE POSITIVES")
        print(f"    Outside Ghidra:         {outside} ({outside/len(entries)*100:.0f}%) — potential genuine")
        if inside:
            print(f"    Affects {len(inside_set)} distinct Ghidra functions")
