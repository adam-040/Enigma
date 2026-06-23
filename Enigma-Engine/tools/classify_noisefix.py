#!/usr/bin/env python3
"""Compare new Enigma CSV vs Ghidra, classify extras by prefix."""

import csv
import sys
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")

pairs = {
    "kernel32": ("enigma_kernel32_rexfix.csv", "ghidra_kernel32.csv"),
    "ntdll": ("enigma_ntdll_rexfix.csv", "ghidra_ntdll.csv"),
    "user32": ("enigma_user32_rexfix.csv", "ghidra_user32.csv"),
}

targets = sys.argv[1:] if len(sys.argv) > 1 else list(pairs.keys())

for target in targets:
    if target not in pairs:
        print(f"Unknown target: {target}. Choose from: {', '.join(pairs.keys())}")
        continue

    enigma_csv, ghidra_csv = pairs[target]

    # Load Ghidra
    ghidra = set()
    with open(BASE / ghidra_csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            ghidra.add(int(row['address'], 16))

    # Load Enigma
    enigma = {}
    with open(BASE / enigma_csv, encoding='utf-8', errors='ignore') as f:
        header_found = False
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('address,type,name'):
                header_found = True
                continue
            if not header_found:
                continue
            parts = line.split(',')
            addr = int(parts[0], 16)
            name = parts[2] if len(parts) > 2 else ''
            enigma[addr] = name

    # Find extras
    extras = {a: n for a, n in enigma.items() if a not in ghidra}

    # Classify by prefix
    prefixes = Counter()
    for addr, name in extras.items():
        if name.startswith('func_data_'):
            prefixes['func_data'] += 1
        elif name.startswith('func_pdata_'):
            prefixes['func_pdata'] += 1
        elif name.startswith('func_start_'):
            prefixes['func_start'] += 1
        elif name.startswith('func_jmp_'):
            prefixes['func_jmp'] += 1
        elif name.startswith('func_call_'):
            prefixes['func_call'] += 1
        elif name.startswith('func_gap_'):
            prefixes['func_gap'] += 1
        elif name.startswith('func_wrapper_'):
            prefixes['func_wrapper'] += 1
        elif name.startswith('func_multi_'):
            prefixes['func_multi'] += 1
        elif name.startswith('func_zero_'):
            prefixes['func_zero'] += 1
        elif name.startswith('func_pattern_'):
            prefixes['func_pattern'] += 1
        else:
            prefixes['other'] += 1

    print(f"\n=== {target.upper()} ===")
    print(f"Ghidra: {len(ghidra)} functions")
    print(f"Enigma: {len(enigma)} functions")
    print(f"Extras: {len(extras)} functions\n")

    total = sum(prefixes.values())
    print(f"{'Category':<20} {'Count':>6} {'%':>8}")
    print("-" * 36)
    for cat, count in sorted(prefixes.items(), key=lambda x: -x[1]):
        print(f"{cat:<20} {count:>6} {count/total*100:>7.1f}%")
    print("-" * 36)
    print(f"{'TOTAL':<20} {total:>6} {100:>7.1f}%")
