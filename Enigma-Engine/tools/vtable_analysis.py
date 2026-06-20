#!/usr/bin/env python3
"""Analyze vtable runs among adjusted missing functions."""
import sys, io, struct, csv
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BINARY = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\shell32_test.dll"
GHIDRA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\ghidra_shell32_test.csv"
ENIGMA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\enigma_shell32.csv"

def read_word(f): return struct.unpack('<H', f.read(2))[0]
def read_dword(f): return struct.unpack('<I', f.read(4))[0]
def read_qword(f): return struct.unpack('<Q', f.read(8))[0]

def parse_pe(binary_path):
    sections = {}
    image_base = 0
    with open(binary_path, 'rb') as f:
        f.seek(0x3C)
        e_lfanew = read_dword(f)
        f.seek(e_lfanew)
        assert f.read(4) == b'PE\x00\x00'
        f.read(2)  # Machine
        nsec = read_word(f)
        f.read(12)
        opt_sz = read_word(f)
        f.read(2)
        opt_start = f.tell()
        magic = read_word(f)
        is64 = magic == 0x20b
        if is64:
            f.seek(opt_start + 24)
            image_base = read_qword(f)
        else:
            f.seek(opt_start + 28)
            image_base = read_dword(f)
        f.seek(opt_start + opt_sz)
        for _ in range(nsec):
            name = f.read(8).rstrip(b'\x00').decode('ascii', errors='ignore')
            vs = read_dword(f)
            va = read_dword(f)
            rs = read_dword(f)
            rp = read_dword(f)
            f.read(16)
            sections[name] = {'va': va, 'vs': vs, 'raw_size': rs, 'raw_ptr': rp}
    return sections, image_base

def is_table_fp(addr, all_missing):
    sm = sorted(all_missing)
    try: idx = sm.index(addr)
    except: return False
    for s in [16, 32, 48]:
        c = 1
        j = idx - 1
        while j >= 0 and sm[idx] - sm[j] == s * (idx - j): c += 1; j -= 1
        j = idx + 1
        while j < len(sm) and sm[j] - sm[idx] == s * (j - idx): c += 1; j += 1
        if c >= 3: return True
    return False

def main():
    sections, image_base = parse_pe(BINARY)
    print(f"ImageBase: 0x{image_base:x}")
    print(f"Sections: {[s for s in sections if isinstance(s, str) and s.strip()]}")

    ghidra = set()
    with open(GHIDRA_CSV) as f:
        next(f)
        for row in csv.reader(f):
            if not row: continue
            try: ghidra.add(int(row[0].strip(), 16))
            except: pass
    enigma = set()
    with open(ENIGMA_CSV) as f:
        for row in csv.reader(f):
            if not row: continue
            try: enigma.add(int(row[0].strip(), 16))
            except: pass

    missing = sorted(ghidra - enigma)
    all_missing_set = set(missing)
    adj_missing = [a for a in missing if not is_table_fp(a, all_missing_set)]
    adj_set = set(adj_missing)

    # Scan .rdata for 8-byte pointers to adjusted missing
    rsec = sections['.rdata']
    with open(BINARY, 'rb') as f:
        f.seek(rsec['raw_ptr'])
        rdata = f.read(min(rsec['raw_size'], rsec['vs']))

    refs = []
    for off in range(0, len(rdata) - 8, 8):
        ptr = struct.unpack('<Q', rdata[off:off+8])[0]
        if ptr in adj_set:
            refs.append((off, ptr))

    # Group into vtable runs: consecutive 8-byte aligned offsets
    refs.sort()
    vtables = []
    if refs:
        cur = [refs[0]]
        for r in refs[1:]:
            if r[0] - cur[-1][0] == 8:
                cur.append(r)
            else:
                if len(cur) >= 3:
                    vtables.append(cur)
                cur = [r]
        if len(cur) >= 3:
            vtables.append(cur)

    vtable_addrs = set()
    for v in vtables:
        for _, a in v:
            vtable_addrs.add(a)

    non_vtable_rdata = set(a for _, a in refs) - vtable_addrs

    print(f"\nGhidra: {len(ghidra)}, Enigma: {len(enigma)}")
    print(f"Missing: {len(missing)}, Adjusted: {len(adj_missing)}")
    print(f".rdata references: {len(refs)} unique: {len(set(a for _,a in refs))}")
    print(f"In vtable runs (3+): {len(vtable_addrs)} ({len(vtables)} vtables)")
    print(f"Non-vtable .rdata refs: {len(non_vtable_rdata)}")

    # How many adj missing have any .rdata ref?
    any_rdata = set(a for _, a in refs)
    no_rdata = len(adj_set - any_rdata)
    print(f"\nAdjusted missing WITH .rdata ref: {len(adj_set & any_rdata)}")
    print(f"Adjusted missing WITHOUT .rdata ref: {no_rdata}")

    # How many function pointers total does .rdata have?
    total_code_ptrs = 0
    for off in range(0, len(rdata) - 8, 8):
        ptr = struct.unpack('<Q', rdata[off:off+8])[0]
        if rsec['va'] <= ptr - image_base < rsec['va'] + rsec['vs']:
            continue  # skip .rdata pointers
        # Check if in executable range
        for sname, s in sections.items():
            if not isinstance(sname, str): continue
            if s['va'] <= ptr - image_base < s['va'] + s['vs']:
                if s['va'] <= ptr - image_base < s['va'] + s['vs']:
                    pass
                break

    # Count total function pointers in .rdata
    # .text range
    tsec = sections['.text']
    text_start = image_base + tsec['va']
    text_end = image_base + tsec['va'] + tsec['vs']
    total_text_ptrs = 0
    for off in range(0, len(rdata) - 8, 8):
        ptr = struct.unpack('<Q', rdata[off:off+8])[0]
        if text_start <= ptr < text_end:
            total_text_ptrs += 1

    print(f"Total .text pointers in .rdata: {total_text_ptrs}")
    matching = len(enigma & ghidra)
    already_matched = len(set(a for _,a in refs) & enigma)
    print(f"Already matched by Enigma: {already_matched}")
    print(f"Remaining unmatched: {len(adj_missing) - len(any_rdata - enigma)}")

    # Show top vtable runs
    vtables.sort(key=lambda v: -len(v))
    print(f"\nTop vtable runs (by entry count):")
    for v in vtables[:15]:
        rva_start = v[0][0] + rsec['va']
        print(f"  .rdata+0x{rva_start:x} {len(v):4d} entries: ", end="")
        for _, a in v[:4]:
            print(f"0x{a:x} ", end="")
        if len(v) > 4:
            print(f"... +{len(v)-4}", end="")
        print()

if __name__ == '__main__':
    main()
