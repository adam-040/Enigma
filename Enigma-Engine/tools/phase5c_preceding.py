"""Check preceding bytes of func_start XOR-zero entries."""
import csv, struct
from pathlib import Path
from collections import Counter

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
                'rsize': struct.unpack('<I', r[16:20])[0],
            })
        return ib, secs

for target, en, gh, bp in [
    ('kernel32', 'enigma_kernel32_rexfix.csv', 'ghidra_kernel32.csv', 'stress/kernel32.dll'),
    ('ntdll', 'enigma_ntdll_rexfix.csv', 'ghidra_ntdll.csv', 'stress/ntdll.dll'),
    ('user32', 'enigma_user32_rexfix.csv', 'ghidra_user32.csv', 'stress/user32.dll'),
]:
    ib, secs = load_pe(BASE / bp)
    dot_text = [s for s in secs if s['name'] == '.text'][0]
    
    def rva_to_off(rva):
        for s in secs:
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return rva - s['vaddr'] + s['roff']
        return None
    
    # Load Ghidra
    gh_set = set()
    with open(BASE / gh) as f:
        next(f)
        for line in f:
            gh_set.add(int(line.split(',')[0], 16))
    
    # Load Enigma
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
    
    print(f"\n=== {target.upper()} ===")
    print(f"func_start entries: {len(fs)}")
    
    # Check preceding bytes for XOR-zero entries
    preceding = Counter()
    xor_without_boundary = 0
    xor_with_boundary = 0
    
    with open(BASE / bp, 'rb') as f:
        for addr, name in fs:
            rva = addr - ib
            off = None
            for s in secs:
                if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                    off = rva - s['vaddr'] + s['roff']
                    break
            if off is None or off < 1:
                continue
            # Read bytes at addr
            f.seek(off)
            cur = f.read(3)
            if len(cur) < 2 or cur[0] != 0x33 or cur[1] not in {0xC0, 0xC9, 0xD2, 0xDB}:
                continue
            # XOR-zero entry
            f.seek(off - 1)
            prev = f.read(1)
            pb = prev[0] if prev else 0xFF
            
            is_boundary = pb in {0xCC, 0xC3, 0xE9, 0xEB, 0x90, 0x00, 0xC2}
            if is_boundary:
                xor_with_boundary += 1
            else:
                xor_without_boundary += 1
            if not is_boundary:
                preceding[pb] += 1
    
    print(f"XOR-zero with boundary:    {xor_with_boundary}")
    print(f"XOR-zero WITHOUT boundary: {xor_without_boundary}")
    if preceding:
        print(f"  Preceding bytes (non-boundary):")
        for pb, cnt in preceding.most_common(15):
            desc = {
                0x48: 'REX.W', 0x8B: 'MOV', 0x89: 'MOV [r]', 0x0F: '2-byte', 0x85: 'TEST',
                0x74: 'JZ', 0x75: 'JNZ', 0x83: 'ARITH', 0x33: 'XOR', 0xEB: 'JMP short',
                0xE8: 'CALL', 0xE9: 'JMP near', 0xC3: 'RET', 0xCC: 'INT3',
                0x4C: 'REX.WR', 0x44: 'REX.R', 0x66: 'OPSIZE', 0x64: 'FS', 0x65: 'GS',
                0xFF: 'FF', 0x00: 'null', 0x90: 'NOP',
            }.get(pb, '')
            label = f"0x{pb:02X} {desc}" if desc else f"0x{pb:02X}"
            print(f"    {label:>24}: {cnt}")
