#!/usr/bin/env python3
"""
investigate_missing.py
Classify missing functions (Ghidra-only) to understand why Enigma doesn't find them.

Usage:
    python investigate_missing.py --binary <path> --enigma-csv <path> --ghidra-csv <path> [--output <path>]
"""

import sys, io, struct, csv, re, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
except ImportError:
    print("capstone not available. Install: pip install capstone")
    sys.exit(1)


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
        f.read(2)
        num_sections = read_word(f)
        f.read(12)
        sizeof_opt = read_word(f)
        f.read(2)
        opt_start = f.tell()
        magic = read_word(f)
        is_pe32plus = (magic == 0x20b)
        if is_pe32plus:
            f.seek(opt_start + 24)
            image_base = read_qword(f)
        else:
            f.seek(opt_start + 28)
            image_base = read_dword(f)
        dd_offset = opt_start + (112 if is_pe32plus else 96)
        f.seek(dd_offset)
        for idx in range(16):
            rva = read_dword(f)
            sz = read_dword(f)
            data_dirs_rva[idx] = rva
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
        if '.pdata' in sections:
            psec = sections['.pdata']
            f.seek(psec['raw_ptr'])
            pdata_size = min(psec['raw_size'], psec['vs'])
            for i in range(0, pdata_size, 12):
                raw = f.read(12)
                if len(raw) < 12:
                    break
                brva, erva, _ = struct.unpack('<III', raw)
                if brva == 0:
                    continue
                begin = image_base + brva
                end = image_base + (erva & 0x7fffffff)
                pdata_entries.append({'begin': begin, 'end': end})
        export_rva = data_dirs_rva.get(0, 0)
        if export_rva and sections:
            for sname, sec in sections.items():
                if not isinstance(sname, str):
                    continue
                if sec['va'] <= export_rva < sec['va'] + sec['vs']:
                    export_fo = sec['raw_ptr'] + (export_rva - sec['va'])
                    f.seek(export_fo)
                    f.read(8)
                    f.read(4)
                    f.read(4)
                    num_funcs = read_dword(f)
                    read_dword(f)
                    addr_of_funcs = read_dword(f)
                    for sname2, sec2 in sections.items():
                        if not isinstance(sname2, str):
                            continue
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


def addr_section(addr, sections, image_base):
    rva = addr - image_base
    for name, sec in sections.items():
        if not isinstance(name, str):
            continue
        if sec['va'] <= rva < sec['va'] + sec['vs']:
            return name
    return "???"


def rva_to_file_offset(sections, rva):
    for name, sec in sections.items():
        if not isinstance(name, str):
            continue
        if sec['va'] <= rva < sec['va'] + sec['vs']:
            raw_off = sec['raw_ptr'] + (rva - sec['va'])
            return raw_off
    return None


def is_table_fp(addr, missing_set):
    sorted_missing = sorted(missing_set)
    try:
        idx = sorted_missing.index(addr)
    except ValueError:
        return False
    for stride in [16, 32, 48]:
        cnt = 1
        j = idx - 1
        while j >= 0 and sorted_missing[idx] - sorted_missing[j] == stride * (idx - j):
            cnt += 1
            j -= 1
        j = idx + 1
        while j < len(sorted_missing) and sorted_missing[j] - sorted_missing[idx] == stride * (j - idx):
            cnt += 1
            j += 1
        if cnt >= 3:
            return True
    return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Classify missing functions')
    parser.add_argument('--binary', required=True, help='Path to PE binary')
    parser.add_argument('--enigma-csv', required=True, help='Enigma CSV')
    parser.add_argument('--ghidra-csv', required=True, help='Ghidra CSV')
    parser.add_argument('--output', default=None, help='Output CSV path')
    parser.add_argument('--no-filter-table-fps', action='store_true',
                        help='Do not filter 16/32/48-byte stride table FPs')
    args = parser.parse_args()

    # Load CSVs
    enigma_funcs = {}
    ghidra_funcs = {}
    with open(args.enigma_csv, 'r') as f:
        next(f, None)
        for row in csv.reader(f):
            if not row:
                continue
            try:
                addr = int(row[0].strip(), 16)
                enigma_funcs[addr] = row[-1].strip()
            except ValueError:
                pass
    with open(args.ghidra_csv, 'r') as f:
        next(f, None)
        for row in csv.reader(f):
            if not row:
                continue
            try:
                addr = int(row[0].strip(), 16)
                ghidra_funcs[addr] = row[-1].strip()
            except ValueError:
                pass

    enigma_addrs = set(enigma_funcs.keys())
    ghidra_addrs = set(ghidra_funcs.keys())
    missing = sorted(ghidra_addrs - enigma_addrs)

    # Filter table FPs
    all_missing_set = set(missing)
    if not args.no_filter_table_fps:
        missing = sorted(a for a in missing if not is_table_fp(a, all_missing_set))

    print(f"Enigma functions: {len(enigma_funcs)}")
    print(f"Ghidra functions: {len(ghidra_funcs)}")
    print(f"Raw missing (Ghidra-only): {len(ghidra_addrs - enigma_addrs)}")
    print(f"Adjusted missing (after table-FP filter): {len(missing)}")
    print()

    # Parse PE
    print("Parsing PE binary...")
    sections, image_base, pdata_entries, export_addrs = parse_pe(args.binary)
    pdata_begins = set(e['begin'] for e in pdata_entries)

    # Read binary into memory
    print("Reading binary data...")
    with open(args.binary, 'rb') as f:
        binary_data = f.read()

    # Pre-scan .text for E8 callers
    print("Scanning .text for CALL rel32 targets...")
    text_callers = Counter()
    if '.text' in sections:
        tsec = sections['.text']
        text_off = tsec['raw_ptr']
        text_size = min(tsec['raw_size'], tsec['vs'])
        text_data = binary_data[text_off:text_off + text_size]
        for off in range(len(text_data) - 5):
            if text_data[off] == 0xE8:
                rel = struct.unpack('<i', text_data[off + 1:off + 5])[0]
                src = image_base + tsec['va'] + off
                tgt = src + 5 + rel
                text_callers[tgt] += 1

    # Pre-scan .rdata for 8-byte pointers targeting missing addresses
    print("Scanning .rdata for pointers to missing addresses...")
    rdata_ptrs = set()
    if '.rdata' in sections:
        rsec = sections['.rdata']
        rdata_off = rsec['raw_ptr']
        rdata_size = min(rsec['raw_size'], rsec['vs'])
        rdata_data = binary_data[rdata_off:rdata_off + rdata_size]
        for off in range(0, len(rdata_data) - 8, 8):
            ptr = struct.unpack('<Q', rdata_data[off:off + 8])[0]
            if ptr in all_missing_set:
                rdata_ptrs.add(ptr)

    # Build nearest Enigma function distance
    sorted_enigma = sorted(enigma_addrs)
    missing_set = set(missing)

    # Capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"Classifying {len(missing)} missing functions...")

    categories = Counter()
    rows = []
    for addr in missing:
        name = ghidra_funcs.get(addr, "???")
        sec_name = addr_section(addr, sections, image_base)
        in_pdata = addr in pdata_begins
        is_export = addr in export_addrs
        has_caller = text_callers.get(addr, 0) > 0
        caller_count = text_callers.get(addr, 0)
        in_rdata = addr in rdata_ptrs

        # Distance to nearest Enigma function
        near_dist = sys.maxsize
        for ea in sorted_enigma:
            d = abs(addr - ea)
            if d < near_dist:
                near_dist = d

        # Read bytes and disassemble
        rva = addr - image_base
        raw_off = rva_to_file_offset(sections, rva)
        if raw_off is not None and raw_off < len(binary_data):
            raw = binary_data[raw_off:raw_off + 16]
        else:
            raw = b''

        if not raw or len(raw) == 0:
            cat = "no_data"
        elif raw[0] == 0x00:
            cat = "zero_padding"
        elif raw[0] == 0xCC:
            cat = "int3_padding"
        elif raw[0] == 0x90:
            cat = "nop_padding"
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
                    elif len(insns) >= 3 and all(m not in ('ret', 'jmp', 'call') for m in mnemonics):
                        cat = "fallthrough_block"
                    elif len(insns) >= 1:
                        cat = "short_code"
                    else:
                        cat = "unknown_code"
                else:
                    cat = "no_decode"
            except Exception:
                cat = "decode_error"

        # Remap to standard categories
        if cat in ("no_data", "zero_padding", "int3_padding", "nop_padding", "no_decode", "decode_error", "unknown_code"):
            cat = "speculative_or_data"
        elif cat == "trivial_ret_stub":
            cat = "tail_call_wrapper"
        elif cat == "tail_call_wrapper":
            cat = "tail_call_wrapper"
        elif cat == "contains_call":
            cat = "unreachable_code"
        elif cat == "fallthrough_block":
            cat = "unreachable_by_evidence"
        elif cat == "short_code":
            cat = "unreachable_by_evidence"
        elif cat == "ret_sequence":
            cat = "unreachable_by_evidence"

        # Overrides: structural evidence takes precedence
        if in_pdata:
            cat = "pdata_entry"
        elif is_export:
            cat = "export_entry"
        elif near_dist <= 8:
            cat = "inside_existing_body"
        elif has_caller and cat in ("tail_call_wrapper", "speculative_or_data"):
            cat = "unreachable_by_evidence"

        categories[cat] += 1
        rows.append({
            'addr': addr,
            'name': name,
            'section': sec_name,
            'category': cat,
            'near_enigma_dist': near_dist,
            'in_pdata': in_pdata,
            'is_export': is_export,
            'caller_count': caller_count,
            'in_rdata': in_rdata,
            'first_byte': raw[0] if raw else None,
        })

    # Write CSV
    out_path = args.output or f"investigate_missing_{os.path.basename(args.binary)}.csv"
    with open(out_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['address', 'name', 'section', 'category', 'near_enigma_dist',
                     'in_pdata', 'is_export', 'caller_count', 'in_rdata', 'first_byte_hex'])
        for r in rows:
            fb = f"0x{r['first_byte']:02x}" if r['first_byte'] is not None else 'N/A'
            w.writerow([
                f"0x{r['addr']:x}", r['name'], r['section'], r['category'],
                r['near_enigma_dist'], int(r['in_pdata']), int(r['is_export']),
                r['caller_count'], int(r['in_rdata']), fb
            ])
    print(f"Output CSV: {out_path}")

    # Summary
    total = len(rows)
    print()
    print("=" * 80)
    print(f"MISSING FUNCTION CLASSIFICATION  ({os.path.basename(args.binary)})")
    print("=" * 80)
    print(f"{'Category':<30s} {'Count':>6s} {'%':>8s}")
    print("-" * 46)
    for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"{cat:<30s} {cnt:>6d} {cnt / total * 100:>7.1f}%")
    print("-" * 46)
    print(f"{'TOTAL':<30s} {total:>6d} {100.0:>7.1f}%")
    print()

    # Samples per category
    seen_cats = set()
    print("=" * 80)
    print("SAMPLES BY CATEGORY")
    print("=" * 80)
    for r in rows:
        cat = r['category']
        if cat not in seen_cats:
            seen_cats.add(cat)
            rva = r['addr'] - image_base
            raw_off = rva_to_file_offset(sections, rva)
            hex_str = ""
            if raw_off is not None and raw_off < len(binary_data):
                sz = min(16, len(binary_data) - raw_off)
                hex_str = ' '.join(f'{binary_data[raw_off + i]:02x}' for i in range(sz))
            print(f"\n{cat}:")
            print(f"  0x{r['addr']:x} {r['name']}")
            sec_clean = r['section'][:16] if isinstance(r['section'], str) else "???"
            print(f"  Section: {sec_clean}  Dist={r['near_enigma_dist']}B  "
                  f"Pdata={int(r['in_pdata'])}  Export={int(r['is_export'])}  "
                  f"Callers={r['caller_count']}")
            print(f"  Bytes: {hex_str}")
            if hex_str and not hex_str.startswith("00") and not hex_str.startswith("cc"):
                try:
                    raw_off2 = rva_to_file_offset(sections, rva)
                    if raw_off2 is not None:
                        raw2 = binary_data[raw_off2:raw_off2 + 16]
                        insns = list(md.disasm(raw2, r['addr'], count=3))
                        for insn in insns[:3]:
                            ops = insn.op_str if insn.op_str else ""
                            print(f"    {insn.mnemonic:10s} {ops}")
                except Exception:
                    pass


if __name__ == '__main__':
    main()
