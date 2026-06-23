#!/usr/bin/env python3
"""
classify_extras.py
Classify extra functions (Enigma-only) by prefix and extract per-address attributes
to determine which function-start sources produce false positives.

Usage:
    python classify_extras.py --binary <path> --enigma-csv <path> --ghidra-csv <path> [--output <path>]
"""

import sys, io, struct, csv, re, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from collections import Counter

prefix_pat = re.compile(r'^(func_\w+)_0x')


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
    return sections, image_base, pdata_entries


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
            max_avail = sec['raw_ptr'] + min(sec['raw_size'], sec['vs']) - raw_off
            return raw_off, max_avail
    return None, 0


def extract_prefix(name):
    m = prefix_pat.match(name)
    return m.group(1) if m else 'other'


def classify_first_byte(b):
    if b is None:
        return 'N/A'
    if b == 0x00:
        return '0x00 (zero_pad)'
    if b == 0xCC:
        return '0xCC (int3)'
    if b == 0x55:
        return '0x55 (push_rbp)'
    if b == 0xE9:
        return '0xE9 (jmp_far)'
    if b == 0xEB:
        return '0xEB (jmp_short)'
    if b == 0xE8:
        return '0xE8 (call)'
    if b == 0xC3:
        return '0xC3 (ret)'
    if b == 0x90:
        return '0x90 (nop)'
    if 0x48 <= b <= 0x4F:
        return f'0x{b:02x} (rex)'
    if 0x50 <= b <= 0x5F:
        return f'0x{b:02x} (push_reg)'
    return f'0x{b:02x}'


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Classify extra functions')
    parser.add_argument('--binary', required=True, help='Path to PE binary')
    parser.add_argument('--enigma-csv', required=True, help='Enigma CSV')
    parser.add_argument('--ghidra-csv', required=True, help='Ghidra CSV')
    parser.add_argument('--output', default=None, help='Output CSV path')
    args = parser.parse_args()

    # Load CSVs
    enigma_funcs = {}
    with open(args.enigma_csv, 'r') as f:
        next(f, None)
        for row in csv.reader(f):
            if not row:
                continue
            try:
                addr = int(row[0].strip(), 16)
                name = row[-1].strip()
                enigma_funcs[addr] = name
            except ValueError:
                pass

    ghidra_addrs = set()
    with open(args.ghidra_csv, 'r') as f:
        next(f, None)
        for row in csv.reader(f):
            if not row:
                continue
            try:
                ghidra_addrs.add(int(row[0].strip(), 16))
            except ValueError:
                pass

    extra_addrs = sorted(set(enigma_funcs.keys()) - ghidra_addrs)
    all_enigma_addrs = sorted(enigma_funcs.keys())

    print(f"Enigma functions: {len(enigma_funcs)}")
    print(f"Ghidra functions: {len(ghidra_addrs)}")
    print(f"Extra functions: {len(extra_addrs)}")
    print()

    # Parse PE
    print("Parsing PE binary...")
    sections, image_base, pdata_entries = parse_pe(args.binary)
    pdata_begins = set(e['begin'] for e in pdata_entries)

    # Read entire binary into memory
    print("Reading binary data...")
    with open(args.binary, 'rb') as f:
        binary_data = f.read()

    # Pre-scan .text for E8 CALL rel32
    print("Scanning .text for CALL rel32 targets...")
    caller_counter = Counter()
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
                caller_counter[tgt] += 1

    # Build next-function index (size = next_enigma - addr)
    next_func_addr = {}
    for i, addr in enumerate(all_enigma_addrs):
        if i + 1 < len(all_enigma_addrs):
            next_func_addr[addr] = all_enigma_addrs[i + 1]
        else:
            next_func_addr[addr] = None

    # Classify each extra
    rows = []
    for addr in extra_addrs:
        name = enigma_funcs[addr]
        prefix = extract_prefix(name)
        sec_name = addr_section(addr, sections, image_base)
        in_pdata = addr in pdata_begins

        rva = addr - image_base
        raw_off, max_avail = rva_to_file_offset(sections, rva)
        if raw_off is not None and raw_off < len(binary_data):
            first_byte = binary_data[raw_off]
        else:
            first_byte = None

        caller_count = caller_counter.get(addr, 0)

        next_addr = next_func_addr.get(addr)
        size = (next_addr - addr) if next_addr is not None else 0

        rows.append({
            'addr': addr,
            'name': name,
            'prefix': prefix,
            'section': sec_name,
            'size': size,
            'in_pdata': in_pdata,
            'caller_count': caller_count,
            'first_byte': first_byte,
        })

    # Write CSV
    out_path = args.output or f"classify_extras_{os.path.basename(args.binary)}.csv"
    with open(out_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['address', 'name', 'prefix', 'section', 'size',
                     'in_pdata', 'caller_count', 'first_byte_hex'])
        for r in rows:
            fb = f"0x{r['first_byte']:02x}" if r['first_byte'] is not None else 'N/A'
            w.writerow([
                f"0x{r['addr']:x}", r['name'], r['prefix'], r['section'],
                r['size'], int(r['in_pdata']), r['caller_count'], fb
            ])
    print(f"Output CSV: {out_path}")

    # Summary table
    groups = {}
    for r in rows:
        groups.setdefault(r['prefix'], []).append(r)

    print()
    print("=" * 100)
    print(f"SUMMARY BY PREFIX  ({os.path.basename(args.binary)})")
    print("=" * 100)
    header = f"{'Prefix':<18s} {'Count':>6s} {'SizeAvg':>8s} {'SizeP50':>8s} {'SizeTotal':>10s} {'%Pdata':>7s} {'%Callers':>8s}"
    print(header)
    print("-" * 68)
    for prefix in sorted(groups.keys()):
        g = groups[prefix]
        cnt = len(g)
        sizes = sorted(r['size'] for r in g)
        avg_sz = sum(sizes) / cnt if cnt else 0
        median_sz = sizes[cnt // 2] if cnt else 0
        total_sz = sum(sizes)
        pdata_cnt = sum(1 for r in g if r['in_pdata'])
        caller_cnt = sum(1 for r in g if r['caller_count'] > 0)
        print(f"{prefix:<18s} {cnt:>6d} {avg_sz:>7.1f} {median_sz:>7d}  {total_sz:>7d}B  "
              f"{pdata_cnt / cnt * 100:>5.1f}% {caller_cnt / cnt * 100:>6.1f}%")
    print("-" * 68)
    all_sizes = sorted(r['size'] for r in rows)
    t_cnt = len(rows)
    t_avg = sum(all_sizes) / t_cnt if t_cnt else 0
    t_med = all_sizes[t_cnt // 2] if t_cnt else 0
    t_total = sum(all_sizes)
    t_pdata = sum(1 for r in rows if r['in_pdata'])
    t_callers = sum(1 for r in rows if r['caller_count'] > 0)
    print(f"{'TOTAL':<18s} {t_cnt:>6d} {t_avg:>7.1f} {t_med:>7d}  {t_total:>7d}B  "
          f"{t_pdata / t_cnt * 100:>5.1f}% {t_callers / t_cnt * 100:>6.1f}%")
    print()

    # First-byte breakdown per prefix
    print("=" * 100)
    print("FIRST-BYTE BREAKDOWN PER PREFIX")
    print("=" * 100)
    for prefix in sorted(groups.keys()):
        g = groups[prefix]
        fb_count = Counter()
        for r in g:
            fb = r['first_byte']
            fb_count[classify_first_byte(fb)] += 1
        print(f"\n{prefix} ({len(g)}):")
        for label, cnt in fb_count.most_common():
            print(f"  {label:<24s} {cnt:>4d} ({cnt / len(g) * 100:5.1f}%)")

    # Section breakdown per prefix
    print()
    print("=" * 100)
    print("SECTION BREAKDOWN PER PREFIX")
    print("=" * 100)
    for prefix in sorted(groups.keys()):
        g = groups[prefix]
        sec_count = Counter(r['section'] for r in g)
        print(f"\n{prefix} ({len(g)}):")
        for label, cnt in sec_count.most_common():
            print(f"  {label:<24s} {cnt:>4d} ({cnt / len(g) * 100:5.1f}%)")


if __name__ == '__main__':
    main()
