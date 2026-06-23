#!/usr/bin/env python3
"""Check if a specific address is in .pdata of a PE binary."""
import sys, struct

def main():
    target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x180017448
    binary = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\stress\kernel32.dll"

    with open(binary, 'rb') as f:
        f.seek(0x3C)
        e_lfanew = struct.unpack('<I', f.read(4))[0]
        f.seek(e_lfanew)
        sig = f.read(4)
        assert sig == b'PE\x00\x00', "Not PE"
        f.read(2)
        num_sections = struct.unpack('<H', f.read(2))[0]
        f.read(12)
        sizeof_opt = struct.unpack('<H', f.read(2))[0]
        f.read(2)
        opt_start = f.tell()
        magic = struct.unpack('<H', f.read(2))[0]
        is_pe32plus = (magic == 0x20b)
        if is_pe32plus:
            f.seek(opt_start + 24)
            image_base = struct.unpack('<Q', f.read(8))[0]
        else:
            f.seek(opt_start + 28)
            image_base = struct.unpack('<I', f.read(4))[0]
        sec_table = opt_start + sizeof_opt
        f.seek(sec_table)
        sections = {}
        for i in range(num_sections):
            name_raw = f.read(8)
            name = name_raw.rstrip(b'\x00').decode('ascii', errors='ignore')
            vs = struct.unpack('<I', f.read(4))[0]
            va = struct.unpack('<I', f.read(4))[0]
            raw_size = struct.unpack('<I', f.read(4))[0]
            raw_ptr = struct.unpack('<I', f.read(4))[0]
            f.read(16)
            sections[name] = {'va': va, 'vs': vs, 'raw_size': raw_size, 'raw_ptr': raw_ptr}

        target_rva = target - image_base
        print(f"Target: 0x{target:x}")
        print(f"Image base: 0x{image_base:x}")
        print(f"Target RVA: 0x{target_rva:x}")

        # Check if in .pdata
        psec = sections.get('.pdata')
        if not psec:
            print("No .pdata section found!")
            return

        f.seek(psec['raw_ptr'])
        pdata_size = min(psec['raw_size'], psec['vs'])
        found = False
        for i in range(0, pdata_size, 12):
            raw = f.read(12)
            if len(raw) < 12:
                break
            brva, erva, urva = struct.unpack('<III', raw)
            if brva == 0:
                continue
            if image_base + brva == target:
                found = True
                print(f"FOUND at .pdata offset {i}")
                print(f"  Begin RVA: 0x{brva:x}")
                print(f"  End RVA:   0x{erva:x}")
                print(f"  Unwind:    0x{urva:x}")
                break
            if abs(image_base + brva - target) < 0x200:
                pass  # nearby check below

        if not found:
            print("NOT FOUND in .pdata")
            # Show entries near target
            f.seek(psec['raw_ptr'])
            nearby = []
            for i in range(0, pdata_size, 12):
                raw = f.read(12)
                if len(raw) < 12:
                    break
                brva, erva, urva = struct.unpack('<III', raw)
                if brva == 0:
                    continue
                begin = image_base + brva
                if abs(begin - target) < 0x200:
                    nearby.append((begin, brva, erva))
            if nearby:
                for b, br, er in sorted(nearby, key=lambda x: abs(x[0] - target)):
                    print(f"  Nearby: 0x{b:x} (RVA 0x{br:x} end=0x{er:x})")

        # Also check which section the address is in
        for name, sec in sections.items():
            if not isinstance(name, str):
                continue
            if sec['va'] <= target_rva < sec['va'] + sec['vs']:
                print(f"Section: {name}")
                break

if __name__ == '__main__':
    main()
