"""Compare Enigma function naming output against Ghidra CSV."""
import csv
import sys
import os


def load_csv(path):
    entries = {}
    with open(path, 'r', encoding='utf-8-sig') as f:
        for row in csv.reader(f):
            if not row or len(row) < 2:
                continue
            if row[0].startswith('[') or row[0] == 'address':
                continue
            addr = row[0].strip()
            name = row[-1].strip()
            entries[addr] = name
    return entries


def main():
    ghidra_path = os.path.join(os.path.dirname(__file__), '..', 'test_binaries', 'ghidra_notepad.csv')
    enigma_path = os.path.join(os.path.dirname(__file__), '..', 'test_binaries', 'enigma_current_baseline.csv')

    if len(sys.argv) >= 2:
        enigma_path = sys.argv[1]

    ghidra = load_csv(ghidra_path)
    enigma = load_csv(enigma_path)

    matched = 0
    correct_among_named = 0
    wrong_among_named = 0
    ghidra_named = 0
    missing_named = 0

    print("=== Gaps: Ghidra named but Enigma has FUN_ ===")
    for addr in sorted(ghidra.keys()):
        gname = ghidra[addr]
        is_named = not gname.startswith('FUN_')
        if is_named:
            ghidra_named += 1

        if addr in enigma:
            ename = enigma[addr]
            matched += 1
            if is_named:
                if gname == ename:
                    correct_among_named += 1
                else:
                    wrong_among_named += 1
                    print(f"  {addr}: Ghidra='{gname}' Enigma='{ename}'")
        elif is_named:
            missing_named += 1
            print(f"  {addr}: Ghidra='{gname}' Enigma=(MISSING)")

    extra = sum(1 for a in enigma if a not in ghidra)

    print(f"\n=== Summary ===")
    print(f"Ghidra total:        {len(ghidra)}")
    print(f"Enigma total:        {len(enigma)}")
    print(f"Matched (by addr):   {matched}")
    print(f"Ghidra-named:        {ghidra_named}")
    print(f"Named correct:       {correct_among_named}")
    print(f"Named wrong:         {wrong_among_named}")
    print(f"Named missing:       {missing_named}")
    print(f"Missing (Ghidra):    {len(ghidra) - matched}")
    print(f"Extra (Enigma):      {extra}")

    if correct_among_named == ghidra_named:
        print("\n[PASS] All Ghidra-named functions correctly reproduced!")
    else:
        print(f"\n[FAIL] {ghidra_named - correct_among_named} Ghidra-named functions not correctly named in Enigma")


if __name__ == '__main__':
    main()
