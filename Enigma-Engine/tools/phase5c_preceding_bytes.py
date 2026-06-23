#!/usr/bin/env python3
"""Verify what bytes precede func_start XOR-zero entries that fail boundary check."""

import csv
import struct
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")

for target in ['kernel32', 'ntdll', 'user32']:
    enigma_csv, _, bin_path = [
        ("enigma_kernel32_nopfix.csv", "ghidra_kernel32.csv", "stress/kernel32.dll"),
        ("enigma_ntdll_nopfix.csv", "ghidra_ntdll.csv", "stress/ntdll.dll"),
        ("enigma_user32_nopfix.csv", "ghidra_user32.csv", "stress/user32.dll"),
    ][['kernel32','ntdll','user32'].index(target)]
    
    # Load PE
    with open(BASE / bin_path, 'rb') as f:
        dos = f.read(64)
        elfanew = struct.unpack_from('<I', dos, 0x3C)[0]
        f.seek(elfanew + 24)
        magic = struct.unpack('<H', f.read(2))[0]
        if magic == 0x10B:
            f.seek(elfanew + 24 + 28)
            ib = struct.unpack('<I', f.read(4))[0]
        else:
            f.seek(elfanew + 24 + 24)
            ib = struct.unpack('<Q', f.read(8))[0]
        f.seek(elfanew + 20)
        ohs = struct.unpack('<H', f.read(2))[0]
        f.seek(elfanew + 24 + ohs)
        secs = []
        for _ in range(struct.unpack_from('<H', nt := (f.seek(elfanew+6), None)[0] or open(BASE/bin_path,'rb').seek(elfanew+6) or ...):
            pass  # Done below
        
    # Simple approach: read sections
    with open(BASE / bin_path, 'rb') as f:
        dos = f.read(64)
        e = struct.unpack_from('<I', dos, 0x3C)[0]
        f.seek(e + 24)
        m = struct.unpack('<H', f.read(2))[0]
        if m == 0x10B:
            f.seek(e + 24 + 28)
            ib = struct.unpack('<I', f.read(4))[0]
        else:
            f.seek(e + 24 + 24)
            ib = struct.unpack('<Q', f.read(8))[0]
        f.seek(e + 20)
        ohs = struct.unpack('<H', f.read(2))[0]
        f.seek(e + 24 + ohs)
        secs = []
        for i in range(struct.unpack_from('<H', (f.seek(e+6), open(BASE/bin_path,'rb').read(2))[1])[0]):
            pass
