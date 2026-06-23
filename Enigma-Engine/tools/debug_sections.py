import csv, struct
from pathlib import Path

BASE = Path(r'C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries')
NTDLL_BIN = BASE / 'stress' / 'ntdll.dll'
ENIGMA_CSV = BASE / 'enigma_ntdll_noisefix.csv'

# Load Enigma func_data
func_data = []
with open(ENIGMA_CSV, encoding='utf-8', errors='ignore') as f:
    header = False
    for line in f:
        line = line.strip()
        if line.startswith('address,type,name'):
            header = True; continue
        if not header: continue
        parts = line.split(',')
        addr = int(parts[0], 16)
        name = parts[2] if len(parts) > 2 else ''
        if name.startswith('func_data_'):
            func_data.append(addr)
print(f'Total func_data: {len(func_data)}')
print(f'First 10: {[hex(a) for a in func_data[:10]]}')

# Load PE sections properly
with open(NTDLL_BIN, 'rb') as f:
    f.seek(0x3C)
    e_lfanew = struct.unpack('<I', f.read(4))[0]
    f.seek(e_lfanew)
    nt_sig = f.read(4)
    print(f'NT signature: {nt_sig}')
    f.seek(e_lfanew + 6)
    num_sections = struct.unpack('<H', f.read(2))[0]
    # Get image base from optional header (PE32+ for 64-bit)
    f.seek(e_lfanew + 24)
    magic = struct.unpack('<H', f.read(2))[0]
    if magic == 0x10B:  # PE32
        f.seek(e_lfanew + 24 + 24)
        image_base = struct.unpack('<I', f.read(4))[0]
    else:  # PE32+ (0x20B)
        f.seek(e_lfanew + 24 + 24)
        image_base = struct.unpack('<Q', f.read(8))[0]
    print(f'Magic: 0x{magic:04X} ImageBase: 0x{image_base:X}')
    
    f.seek(e_lfanew + 20)
    opt_hdr_size = struct.unpack('<H', f.read(2))[0]
    f.seek(e_lfanew + 24 + opt_hdr_size)
    sections = []
    for i in range(num_sections):
        raw = f.read(40)
        name = raw[:8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack('<I', raw[8:12])[0]
        vaddr = struct.unpack('<I', raw[12:16])[0]
        rsize = struct.unpack('<I', raw[16:20])[0]
        roff = struct.unpack('<I', raw[20:24])[0]
        sections.append((name, vaddr, vsize, roff, rsize))
        print(f'  Section {i}: {name:>8} VA=0x{vaddr:08X} VSz=0x{vsize:X} RO=0x{roff:X} RSz=0x{rsize:X}')

# Check first 10 func_data
print()
for addr in func_data[:20]:
    found = False
    rva = addr - image_base
    for name, vaddr, vsize, roff, rsize in sections:
        if vaddr <= rva < vaddr + vsize:
            offset = rva - vaddr + roff
            with open(NTDLL_BIN, 'rb') as f:
                f.seek(offset)
                data = f.read(16)
            hex_str = ' '.join(f'{b:02X}' for b in data)
            print(f'  0x{addr:08X} -> Section {name} offset 0x{offset:X}  bytes: {hex_str}')
            found = True
            break
    if not found:
        print(f'  0x{addr:08X} -> NO SECTION FOUND')
