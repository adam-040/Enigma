"""Debug: check actual bytes at func_start XOR-zero entries."""
import csv, struct
from pathlib import Path

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")

def load_pe(path):
    with open(path, 'rb') as f:
        dos = f.read(64)
        elf = struct.unpack_from('<I', dos, 0x3C)[0]
        f.seek(elf + 24)
        m = struct.unpack('<H', f.read(2))[0]
        if m == 0x10B:
            f.seek(elf + 24 + 28)
            ib = struct.unpack('<I', f.read(4))[0]
        else:
            f.seek(elf + 24 + 24)
            ib = struct.unpack('<Q', f.read(8))[0]
        f.seek(elf + 6)
        ns = struct.unpack('<H', f.read(2))[0]
        f.seek(elf + 20)
        ohs = struct.unpack('<H', f.read(2))[0]
        f.seek(elf + 24 + ohs)
        secs = []
        for _ in range(ns):
            r = f.read(40)
            secs.append({
                'name': r[:8].rstrip(b'\x00').decode('ascii', errors='replace'),
                'vaddr': struct.unpack('<I', r[12:16])[0],
                'vsize': struct.unpack('<I', r[8:12])[0],
                'roff': struct.unpack('<I', r[20:24])[0],
            })
        return ib, secs

for target in ['kernel32']:
    en = f'enigma_{target}_rexfix.csv'
    gh = f'ghidra_{target}.csv'
    bp = f'stress/{target}.dll'
    
    ib, secs = load_pe(BASE / bp)
    
    def rva_to_off(rva):
        for s in secs:
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return rva - s['vaddr'] + s['roff']
        return None
    
    gh_set = set()
    with open(BASE / gh) as f:
        next(f)
        for line in f:
            gh_set.add(int(line.split(',')[0], 16))
    
    en_data = {}
    with open(BASE / en, encoding='utf-8', errors='ignore') as f:
        h = False
        for line in f:
            line = line.strip()
            if line.startswith('address,type,name'):
                h = True; continue
            if not h: continue
            p = line.split(',')
            en_data[int(p[0], 16)] = p[2] if len(p) > 2 else ''
    
    fs = [(a, n) for a, n in en_data.items() if a not in gh_set and n.startswith('func_start_')]
    
    # For XOR-zero entries with preceding 0x45, print the 8-byte context
    with open(BASE / bp, 'rb') as f:
        for addr, name in fs:
            rva = addr - ib
            off = rva_to_off(rva)
            if off is None or off < 1: continue
            f.seek(off)
            cur = f.read(5)
            if len(cur) < 2: continue
            # Check if XOR-zero
            if cur[0] != 0x33 or cur[1] not in {0xC0, 0xC9, 0xD2, 0xDB}:
                continue
            f.seek(off - 1)
            prev = f.read(1)
            pb = prev[0] if prev else 0xFF
            
            # Print context: 3 bytes before, the entry, 2 bytes after
            start_off = max(0, off - 3)
            f.seek(start_off)
            ctx = f.read(8)
            before = ' '.join(f'{b:02X}' for b in ctx[:min(3, off - start_off)])
            after = ' '.join(f'{b:02X}' for b in ctx[min(3, off - start_off):])
            arrow_off = len(before.split(' ')) + (0 if start_off == off - 3 else 1)
            print(f"  0x{addr:08X}  ctx=[{' '.join(f'{b:02X}' for b in ctx)}]  prev=0x{pb:02X}")
