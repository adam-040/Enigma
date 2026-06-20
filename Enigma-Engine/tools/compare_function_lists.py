#!/usr/bin/env python3
"""
compare_function_lists.py
Compare Enigma and Ghidra function lists to find extra/missing functions.

Usage:
    python compare_function_lists.py <enigma_csv> <ghidra_csv> [--verbose]

Input format (CSV): address,type,name  (Enigma) or address,name (Ghidra)
where address is hex format like 0x140001008.

Output:
    - Total functions in each
    - Matching functions (by address)
    - Extra functions (in Enigma, not in Ghidra)
    - Missing functions (in Ghidra, not in Enigma)
    - Detailed list if --verbose
"""

import sys
import csv
import argparse

def parse_csv(path, has_type=False):
    """Parse CSV file into dict of address -> (name, type)"""
    result = {}
    with open(path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if not row:
                continue
            addr_str = row[0].strip()
            name = row[-1].strip() if len(row) > 1 else ""
            ftype = row[1].strip() if has_type and len(row) > 2 else ""
            try:
                addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
            except ValueError:
                print(f"Warning: skipping invalid address '{addr_str}'", file=sys.stderr)
                continue
            result[addr] = (name, ftype)
    return result


def main():
    parser = argparse.ArgumentParser(description='Compare Enigma vs Ghidra function lists')
    parser.add_argument('enigma_csv', help='Enigma CSV output from enigma_dump_functions --ghidra-compat')
    parser.add_argument('ghidra_csv', help='Ghidra CSV output from ghidra_dump_functions.py')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed function lists')
    parser.add_argument('--enigma-has-type', action='store_true',
                        help='Enigma CSV has type column (default: no, just address,name)')
    args = parser.parse_args()

    enigma = parse_csv(args.enigma_csv, has_type=args.enigma_has_type)
    ghidra = parse_csv(args.ghidra_csv, has_type=False)

    enigma_addrs = set(enigma.keys())
    ghidra_addrs = set(ghidra.keys())

    matching = enigma_addrs & ghidra_addrs
    extra = enigma_addrs - ghidra_addrs
    missing = ghidra_addrs - enigma_addrs

    # Detect data-table false positives in Ghidra (16/32/48-byte strides)
    table_fps = set()
    sorted_missing = sorted(missing)
    for stride in [16, 32, 48]:
        i = 0
        while i < len(sorted_missing):
            seq = [sorted_missing[i]]
            j = i + 1
            while j < len(sorted_missing) and (sorted_missing[j] - seq[-1]) == stride:
                seq.append(sorted_missing[j])
                j += 1
            if len(seq) >= 3:
                table_fps.update(seq)
            i = j if j > i + 1 else i + 1

    adjusted_missing = missing - table_fps

    print("=" * 60)
    print(f"COMPARISON: {args.enigma_csv} vs {args.ghidra_csv}")
    print("=" * 60)
    print(f"Enigma total functions: {len(enigma)}")
    print(f"Ghidra total functions: {len(ghidra)}")
    print(f"Matching (same address): {len(matching)}")
    print(f"Extra (Enigma only):    {len(extra)}")
    print(f"Missing (Ghidra only):  {len(missing)}")
    if table_fps:
        print(f"  (adjusted: {len(adjusted_missing)} after excluding {len(table_fps)} table FPs)")
    print()

    if args.verbose:
        if extra:
            print(f"--- EXTRA FUNCTIONS (Enigma only, {len(extra)}) ---")
            for addr in sorted(extra):
                name, ftype = enigma[addr]
                print(f"  0x{addr:x} {ftype:10s} {name}")
            print()

        if missing:
            print(f"--- MISSING FUNCTIONS (Ghidra only, {len(missing)}) ---")
            for addr in sorted(missing):
                name = ghidra[addr][0]
                tag = " [TABLE-FP]" if addr in table_fps else ""
                print(f"  0x{addr:x} {name}{tag}")
            print()

    # Summary classification of extra/missing
    if extra and args.enigma_has_type:
        type_counts = {}
        for addr in extra:
            _, ftype = enigma[addr]
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        if type_counts:
            print("Extra breakdown by type:")
            for t in sorted(type_counts.keys()):
                print(f"  {t}: {type_counts[t]}")


if __name__ == '__main__':
    main()
