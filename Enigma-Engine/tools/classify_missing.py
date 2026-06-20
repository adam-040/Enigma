#!/usr/bin/env python3
"""
classify_missing.py
Classify shell32 missing functions (adjusted missing = non-table-FP Ghidra-only)
to understand why Enigma doesn't find them.
"""
import sys, io, struct, csv
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
except ImportError:
    print("capstone not available. Install: pip install capstone")
    sys.exit(1)

BINARY = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\shell32_test.dll"
GHIDRA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\ghidra_shell32_test.csv"
ENIGMA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\enigma_shell32.csv"

def read_word(f):
    return struct.unpack('<H', f.read(2))[0]
def read_dword(f):
    return struct.unpack('<I', f.read(4))[0]
def read_qword(f):
    return struct.unpack('<Q', f.read(8))[0]

def parse_pe(binary_path):
    sections = {}
    image_base = 0
    pdata_entries = []
    export_addrs = set()
    data_dirs_rva = {}
    opt_start = 0
    is_pe32plus = False
    with open(binary_path, 'rb') as f:
        f.seek(0x3C)
        e_lfanew = read_dword(f)
        f.seek(e_lfanew)
        sig = f.read(4)
        assert sig == b'PE\x00\x00', "Not PE"
        f.read(2)  # Machine
        num_sections = read_word(f)
        f.read(12)  # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        sizeof_opt = read_word(f)
        f.read(2)  # Characteristics
        opt_start = f.tell()
        magic = read_word(f)
        is_pe32plus = (magic == 0x20b)
        if is_pe32plus:
            f.seek(opt_start + 24)
            image_base = read_qword(f)
        else:
            f.seek(opt_start + 28)
            image_base = read_dword(f)
        # Data directory RVAs
        dd_offset = opt_start + (112 if is_pe32plus else 96)
        f.seek(dd_offset)
        for idx in range(16):
            rva = read_dword(f)
            sz = read_dword(f)
            data_dirs_rva[idx] = rva
        # Section table
        sec_table = opt_start + sizeof_opt
        f.seek(sec_table)
        for i in range(num_sections):
            name_raw = f.read(8)
            name = name_raw.rstrip(b'\x00').decode('ascii', errors='ignore')
            vs = read_dword(f)
            va = read_dword(f)
            raw_size = read_dword(f)
            raw_ptr = read_dword(f)
            f.read(16)
            sections[name] = {'va': va, 'vs': vs, 'raw_size': raw_size, 'raw_ptr': raw_ptr}
        # Parse .pdata
        if '.pdata' in sections:
            psec = sections['.pdata']
            f.seek(psec['raw_ptr'])
            pdata_size = min(psec['raw_size'], psec['vs'])
            for i in range(0, pdata_size, 12):
                raw = f.read(12)
                if len(raw) < 12: break
                brva, erva, urva = struct.unpack('<III', raw)
                if brva == 0: continue
                begin = image_base + brva
                end = image_base + (erva & 0x7fffffff)
                pdata_entries.append({'begin': begin, 'end': end})
        # Parse export directory
        export_rva = data_dirs_rva.get(0, 0)
        if export_rva and sections:
            for sname, sec in sections.items():
                if not isinstance(sname, str): continue
                if sec['va'] <= export_rva < sec['va'] + sec['vs']:
                    export_fo = sec['raw_ptr'] + (export_rva - sec['va'])
                    f.seek(export_fo)
                    f.read(8)  # Char, TimeDate, Major/Minor
                    f.read(4)  # Name RVA
                    f.read(4)  # Ordinal Base
                    num_funcs = read_dword(f)
                    read_dword(f)  # num_names
                    addr_of_funcs = read_dword(f)
                    for sname2, sec2 in sections.items():
                        if not isinstance(sname2, str): continue
                        if sec2['va'] <= addr_of_funcs < sec2['va'] + sec2['vs']:
                            funcs_fo = sec2['raw_ptr'] + (addr_of_funcs - sec2['va'])
                            f.seek(funcs_fo)
                            for _ in range(num_funcs):
                                func_rva = read_dword(f)
                                if func_rva:
                                    export_addrs.add(image_base + func_rva)
                            break
                    break
    return sections, image_base, pdata_entries, export_addrs

def read_bytes_at(binary_path, addr, size):
    sections, image_base, _, _ = parse_pe(binary_path)
    rva = addr - image_base
    with open(binary_path, 'rb') as f:
        for sname, sec in sections.items():
            if not isinstance(sname, str): continue
            if sec['va'] <= rva < sec['va'] + sec['vs']:
                off = sec['raw_ptr'] + (rva - sec['va'])
                raw_sz = sec.get('raw_size', 0)
                if raw_sz:
                    max_read = sec['raw_ptr'] + raw_sz - off
                    if max_read <= 0: return b''
                    size = min(size, max_read)
                f.seek(off)
                return f.read(size)
    return b''

def addr_section(addr, sections, image_base):
    rva = addr - image_base
    for name, sec in sections.items():
        if not isinstance(name, str): continue
        if sec['va'] <= rva < sec['va'] + sec['vs']:
            return name
    return "???"

def is_table_fp(addr, missing_set):
    """Check if addr is in a 16/32/48-byte stride pattern of length 3+"""
    sorted_missing = sorted(missing_set)
    try:
        idx = sorted_missing.index(addr)
    except ValueError:
        return False
    for stride in [16, 32, 48]:
        cnt = 1
        j = idx - 1
        while j >= 0 and sorted_missing[idx] - sorted_missing[j] == stride * (idx - j):
            cnt += 1; j -= 1
        j = idx + 1
        while j < len(sorted_missing) and sorted_missing[j] - sorted_missing[idx] == stride * (j - idx):
            cnt += 1; j += 1
        if cnt >= 3:
            return True
    return False

def main():
    print("=" * 70)
    print("SHELL32 MISSING FUNCTION FORENSICS")
    print("=" * 70)

    sections, image_base, pdata, export_addrs = parse_pe(BINARY)
    print(f"ImageBase: 0x{image_base:x}")
    valid_sections = [s for s in sections.keys() if isinstance(s, str) and s.strip()]
    print(f"Sections: {valid_sections}")
    print(f".pdata entries: {len(pdata)}")

    # Load CSVs
    ghidra_funcs = {}
    with open(GHIDRA_CSV, 'r') as f:
        next(f)
        for row in csv.reader(f):
            if not row: continue
            try: addr = int(row[0].strip(), 16); ghidra_funcs[addr] = row[-1].strip()
            except: pass

    enigma_addrs = set()
    with open(ENIGMA_CSV, 'r') as f:
        for row in csv.reader(f):
            if not row: continue
            try: enigma_addrs.add(int(row[0].strip(), 16))
            except: pass

    missing = sorted(set(ghidra_funcs.keys()) - enigma_addrs)
    # Filter table FPs
    all_missing_set = set(missing)
    adjusted_missing = [a for a in missing if not is_table_fp(a, all_missing_set)]

    print(f"\nGhidra functions: {len(ghidra_funcs)}")
    print(f"Enigma functions: {len(enigma_addrs)}")
    print(f"Raw missing: {len(missing)}")
    print(f"Adjusted missing (non-table-FP): {len(adjusted_missing)}")
    print()

    adjusted_set_fast = set(adjusted_missing)
    pdata_begins = set(e['begin'] for e in pdata)

    # Pre-compute: scan .text for CALL rel32 instructions targeting any adjusted missing addr
    text_calls = set()
    if '.text' in sections:
        tsec = sections['.text']
        with open(BINARY, 'rb') as f:
            f.seek(tsec['raw_ptr'])
            text_data = f.read(min(tsec['raw_size'], tsec['vs']))
        for off in range(len(text_data) - 5):
            if text_data[off] == 0xE8:
                rel = struct.unpack('<i', text_data[off+1:off+5])[0]
                src = image_base + tsec['va'] + off
                tgt = src + 5 + rel
                if tgt in adjusted_set_fast:
                    text_calls.add(tgt)

    # Pre-compute: scan .rdata for 8-byte pointers targeting any adjusted missing addr
    rdata_refs = set()
    if '.rdata' in sections:
        rsec = sections['.rdata']
        with open(BINARY, 'rb') as f:
            f.seek(rsec['raw_ptr'])
            rdata_data = f.read(min(rsec['raw_size'], rsec['vs']))
        for off in range(0, len(rdata_data) - 8, 8):
            ptr = struct.unpack('<Q', rdata_data[off:off+8])[0]
            if ptr in adjusted_set_fast:
                rdata_refs.add(ptr)

    # export_addrs already parsed from parse_pe()

    print(f"CALL references from .text to adjusted missing: {len(text_calls)}")
    print(f".rdata 8-byte pointer references to adjusted missing: {len(rdata_refs)}")
    print(f"Export directory entries among adjusted missing: {len(export_addrs & adjusted_set_fast)}")
    print(f"Adjusted missing with .pdata entry: {len(adjusted_set_fast & pdata_begins)}")
    print()

    # Capstone disassembler (x64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # For each adjusted missing address, classify
    categories = Counter()
    detail = []

    for addr in adjusted_missing:
        name = ghidra_funcs.get(addr, "???")
        sec_name = addr_section(addr, sections, image_base)
        in_pdata = addr in pdata_begins

        # Check distance to nearest Enigma function
        near_ef = None
        for ea in enigma_addrs:
            if abs(addr - ea) <= 32:
                near_ef = (ea, addr - ea)
                break
        sec = sec_name

        # Read bytes and disassemble
        raw = read_bytes_at(BINARY, addr, 16)
        if not raw or len(raw) == 0:
            cat = "no_data"
        elif raw[0] == 0x00:
            cat = "zero_padding"
        elif raw[0] == 0xCC:
            cat = "int3_padding"
        else:
            try:
                insns = list(md.disasm(raw, addr, count=5))
                if insns:
                    mnemonics = [i.mnemonic for i in insns]
                    last = insns[-1]
                    first = insns[0]

                    if last.mnemonic in ('ret', 'retn'):
                        if len(insns) <= 3:
                            cat = "trivial_ret_stub"
                        else:
                            cat = "ret_sequence"
                    elif last.mnemonic == 'jmp' and len(insns) <= 5:
                        cat = "tail_call_wrapper"
                    elif first.mnemonic == 'int3':
                        cat = "int3_padding"
                    elif any(m in ('call',) for m in mnemonics[:-1]):
                        cat = "contains_call"
                    elif len(insns) >= 3 and all(
                        m not in ('ret', 'jmp', 'call') for m in mnemonics):
                        cat = "fallthrough_block"
                    elif len(insns) >= 1:
                        cat = "short_code"
                    else:
                        cat = "unknown_code"
                else:
                    cat = "no_decode"
            except Exception:
                cat = "decode_error"

        # Remap to task-standard categories
        if cat == "no_data" or cat == "zero_padding" or cat == "int3_padding":
            cat = "speculative_or_data"  # Ghidra likely wrong
        elif cat == "no_decode" or cat == "decode_error":
            cat = "speculative_or_data"
        elif cat == "trivial_ret_stub":
            cat = "tail_call_wrapper"
        elif cat == "tail_call_wrapper":
            cat = "tail_call_wrapper"
        elif cat == "contains_call":
            cat = "unreachable_code"  # has call, not a wrapper
        elif cat == "fallthrough_block":
            cat = "unreachable_by_evidence"  # valid code, no evidence
        elif cat == "short_code":
            cat = "unreachable_by_evidence"
        elif cat == "unknown_code":
            cat = "speculative_or_data"

        # .pdata-absent classification: functions with .pdata are "expected" to be found
        if in_pdata:
            cat = f"pdata_entry"  # should have been found by pdata scanner
        elif near_ef and abs(near_ef[1]) <= 8:
            cat = "inside_existing_body"  # too close to existing func entry

        categories[cat] += 1
        detail.append((addr, name, sec, cat))

    # Print summary
    total = len(adjusted_missing)
    print(f"{'Category':<30s} {'Count':>6s} {'%':>8s}")
    print("-" * 46)
    for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
        pct = cnt / total * 100 if total else 0
        print(f"{cat:<30s} {cnt:>6d} {pct:>7.1f}%")
    print("-" * 46)
    print(f"{'TOTAL':<30s} {total:>6d} {100.0:>7.1f}%")
    print()

    # Show sample for each category
    seen_cats = set()
    print("=" * 70)
    print("SAMPLES BY CATEGORY")
    print("=" * 70)
    for addr, name, sec_name2, cat in detail:
        if cat not in seen_cats:
            seen_cats.add(cat)
            raw = read_bytes_at(BINARY, addr, 16)
            hex_str = ' '.join(f'{b:02x}' for b in raw) if raw else "NO DATA"
            print(f"\n{cat}:")
            print(f"  0x{addr:x} {name}")
            try:
                sec_clean = sec_name2.encode('ascii', errors='ignore').decode('ascii')[:16]
            except:
                sec_clean = "???"
            print(f"  Section: {sec_clean}  Bytes: {hex_str}")
            try:
                insns = list(md.disasm(raw, addr, count=3))
                for insn in insns[:3]:
                    ops = insn.op_str if insn.op_str else ""
                    print(f"    {insn.mnemonic:10s} {ops}")
            except:
                pass

if __name__ == '__main__':
    main()
