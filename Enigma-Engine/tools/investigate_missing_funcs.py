#!/usr/bin/env python3
"""
investigate_missing_funcs.py
Analyze the 74 Ghidra-only functions in notepad_test.exe.
"""

import struct
import sys
import csv

def read_word(f):
    return struct.unpack('<H', f.read(2))[0]

def read_dword(f):
    return struct.unpack('<I', f.read(4))[0]

def read_qword(f):
    return struct.unpack('<Q', f.read(8))[0]

def parse_pe(binary_path):
    sections = {}
    data_dirs = {}
    image_base = 0
    pdata_functions = []
    delay_functions = []

    try:
        with open(binary_path, 'rb') as f:
            f.seek(0x3C)
            e_lfanew = read_dword(f)

            f.seek(e_lfanew)
            sig = f.read(4)
            assert sig == b'PE\x00\x00', f"Not PE (sig={sig})"

            machine = read_word(f)
            num_sections = read_word(f)
            timestamp = read_dword(f)
            ptr_symtab = read_dword(f)
            num_syms = read_dword(f)
            sizeof_optional_header = read_word(f)
            characteristics = read_word(f)

            opt_start = f.tell()
            magic = read_word(f)
            is_pe32plus = (magic == 0x20b)

            if is_pe32plus:
                f.seek(opt_start + 24)
                image_base = read_qword(f)
            else:
                f.seek(opt_start + 28)
                image_base = read_dword(f)

            # Data directories
            dd_offset = opt_start + (112 if is_pe32plus else 96)
            f.seek(dd_offset)
            for idx in range(15):
                rva = read_dword(f)
                size = read_dword(f)
                data_dirs[idx] = {'rva': rva, 'size': size}

            # Section table
            sec_table = e_lfanew + 4 + 20 + sizeof_optional_header
            f.seek(sec_table)

            def rva_to_fo(rva):
                for sname, sec in sections.items():
                    s_start = sec['va']
                    if s_start <= rva < s_start + sec['vs']:
                        return sec['raw_ptr'] + (rva - s_start)
                return None

            for i in range(num_sections):
                name_raw = f.read(8)
                name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
                vs = read_dword(f)  # virtual size
                va = read_dword(f)  # virtual address
                raw_size = read_dword(f)
                raw_ptr = read_dword(f)
                f.read(16)
                sections[name] = {
                    'va': va, 'vs': vs,
                    'raw_size': raw_size, 'raw_ptr': raw_ptr
                }
                f.seek(sec_table + (i+1) * 40)

            # Parse .pdata
            ex_dir = data_dirs.get(3, {})
            pdata_fo = rva_to_fo(ex_dir['rva']) if ex_dir.get('rva') else None
            if pdata_fo:
                f.seek(pdata_fo)
                for _ in range(ex_dir['size'] // 12):
                    brva = read_dword(f)
                    erva = read_dword(f)
                    urva = read_dword(f)
                    if brva == 0: continue
                    begin = image_base + brva
                    end = image_base + (erva & 0x7fffffff)
                    size = end - begin
                    pdata_functions.append({
                        'begin': begin, 'size': size,
                        'begin_rva': brva, 'unwind_rva': urva
                    })

            # Parse delay-load directory
            dl_dir = data_dirs.get(13, {})
            dl_fo = rva_to_fo(dl_dir['rva']) if dl_dir.get('rva') else None
            if dl_fo:
                desc_size = 56 if is_pe32plus else 48
                num_desc = min(dl_dir['size'] // desc_size, 50)
                f.seek(dl_fo)
                for di in range(num_desc):
                    if desc_size == 56:
                        grAttrs = read_dword(f)
                        name_rva = read_dword(f)
                        hmod = read_qword(f)
                        iat_rva_val = read_qword(f)
                        int_rva_val = read_qword(f)
                        f.read(8*3)  # skip bound/unload/time
                    else:
                        grAttrs = read_dword(f)
                        name_rva = read_dword(f)
                        hmod = read_dword(f)
                        iat_rva_val = read_dword(f)
                        int_rva_val = read_dword(f)
                        f.read(4*3)
                    if grAttrs == 0:
                        continue
                    # Read DLL name
                    name_fo = rva_to_fo(name_rva)
                    dll_name = "?"
                    if name_fo:
                        pos = f.tell()
                        f.seek(name_fo)
                        dll_name = b''
                        while True:
                            c = f.read(1)
                            if c == b'\x00' or not c: break
                            dll_name += c
                        dll_name = dll_name.decode('ascii', errors='replace')
                        f.seek(pos)
                    delay_functions.append({
                        'dll': dll_name, 'thunk_addr': 0,
                        'thunks': []
                    })

    except Exception as e:
        import traceback
        print(f"PE parse error: {e}", file=sys.stderr)
        traceback.print_exc()

    return {
        'sections': sections,
        'data_dirs': data_dirs,
        'image_base': image_base,
        'pdata': pdata_functions,
        'delay': delay_functions
    }

def main():
    binary = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe"
    enigma_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_enigma_functions.csv"
    ghidra_csv = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\notepad_ghidra_functions.csv"

    info = parse_pe(binary)
    image_base = info['image_base']
    sections = info['sections']
    pdata_funcs = info['pdata']
    delay_funcs = info['delay']

    enigma_addrs = set()
    with open(enigma_csv, 'r') as f:
        for row in csv.reader(f):
            if not row: continue
            try:
                enigma_addrs.add(int(row[0].strip(), 16))
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

    print(f"ImageBase: 0x{image_base:x}")
    print(f"Enigma functions: {len(enigma_addrs)}")
    print(f"Ghidra functions: {len(ghidra_funcs)}")
    print(f"Missing (Ghidra only): {len(missing)}")

    # Section lookup
    def addr_section(addr):
        rva = addr - image_base
        for name, sec in sections.items():
            if sec['va'] <= rva < sec['va'] + sec['vs']:
                return name
        return "???"

    # Build pdata begin address set
    pdata_begins = set(pf['begin'] for pf in pdata_funcs)
    pdata_by_begin = {pf['begin']: pf for pf in pdata_funcs}

    # Check if this function might be inside an Enigma function body
    # Enigma creates functions with body = {entry_point, entry_point} (single address)
    # So getFunctionContaining would only return a func if addr IS the entry point
    # But let's check if any Enigma function entry is close to this address
    def is_near_enigma_func(addr, rad=16):
        for ea in enigma_addrs:
            if abs(addr - ea) <= rad:
                return ea
        return None

    print()
    print("=" * 80)
    print("CLASSIFICATION OF MISSING FUNCTIONS")
    print("=" * 80)

    categories = {
        'pdata_entry': [],
        'delay_load_thunk': [],
        'near_enigma_func': [],
        'unknown': []
    }

    for addr in missing:
        name = ghidra_funcs.get(addr, "???")
        sec = addr_section(addr)
        in_pdata = addr in pdata_begins
        in_delay = any(True for _ in [])  # placeholder

        is_delay = name.startswith("DelayLoad_")
        near_ef = is_near_enigma_func(addr)

        print(f"\n0x{addr:x} ({name})")
        print(f"  Section: {sec}")
        print(f"  .pdata begin: {in_pdata}, Near Enigma func: {near_ef != None}")

        if is_delay:
            print(f"  TYPE: DELAY-LOAD THUNK")
            categories['delay_load_thunk'].append(addr)
        elif in_pdata:
            pf = pdata_by_begin.get(addr)
            print(f"  TYPE: .pdata EXCEPTION ENTRY (size={pf['size'] if pf else '?'})")
            categories['pdata_entry'].append(addr)
        elif near_ef:
            print(f"  TYPE: NEAR EXISTING ENIGMA FUNCTION (offset={addr - near_ef})")
            categories['near_enigma_func'].append(addr)
        else:
            print(f"  TYPE: UNKNOWN")
            categories['unknown'].append(addr)

    print()
    print("=" * 80)
    print("CATEGORY COUNTS")
    print("=" * 80)
    for cat, addrs in categories.items():
        print(f"  {cat}: {len(addrs)}")

    print()
    print("=" * 80)
    print("PDATA COVERAGE")
    print("=" * 80)
    print(f"Total .pdata entries: {len(pdata_begins)}")
    enigma_has_pdata = pdata_begins & enigma_addrs
    print(f"Enigma has .pdata entry: {len(enigma_has_pdata)}")
    print(f"Missing .pdata entry: {len(pdata_begins - enigma_addrs)}")
    print()

    # Show .pdata entries that Enigma MISSED
    missed_pdata = sorted(pdata_begins - enigma_addrs)
    print(f"Sample .pdata entries Enigma MISSED ({len(missed_pdata)} total):")
    for begin in missed_pdata[:20]:
        pf = pdata_by_begin[begin]
        print(f"  0x{begin:x} (size {pf['size']})")
    if len(missed_pdata) > 20:
        print(f"  ... and {len(missed_pdata)-20} more")

    # Show .pdata entries Enigma found
    found_pdata = sorted(enigma_has_pdata)
    print(f"\nSample .pdata entries Enigma FOUND ({len(found_pdata)} total):")
    for begin in found_pdata[:5]:
        pf = pdata_by_begin[begin]
        print(f"  0x{begin:x} (size {pf['size']})")

if __name__ == '__main__':
    main()
