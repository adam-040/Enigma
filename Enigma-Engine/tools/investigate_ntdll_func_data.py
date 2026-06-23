#!/usr/bin/env python3
"""Investigate ntdll func_data survivors — classify them as genuine vs false."""

import csv
import struct
import sys
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries")
NTDLL_BIN = BASE / "stress" / "ntdll.dll"
ENIGMA_CSV = BASE / "enigma_ntdll_noisefix.csv"
GHIDRA_CSV = BASE / "ghidra_ntdll.csv"

# Load PE header information
def load_pe(path):
    with open(path, 'rb') as f:
        dos_hdr = f.read(64)
        if dos_hdr[:2] != b'MZ':
            return None, []
        e_lfanew = struct.unpack_from('<I', dos_hdr, 0x3C)[0]
        f.seek(e_lfanew)
        nt_hdr = f.read(24)
        if nt_hdr[:4] != b'PE\x00\x00':
            return None, []
        num_sections = struct.unpack_from('<H', nt_hdr, 6)[0]
        opt_hdr_size = struct.unpack_from('<H', nt_hdr, 20)[0]
        f.seek(e_lfanew + 24)
        opt_hdr = f.read(opt_hdr_size)
        magic = struct.unpack('<H', opt_hdr[:2])[0]
        if magic == 0x10B:  # PE32
            image_base = struct.unpack('<I', opt_hdr[28:32])[0]
        else:  # PE32+ (0x20B)
            image_base = struct.unpack('<Q', opt_hdr[24:32])[0]
        f.seek(e_lfanew + 24 + opt_hdr_size)
        sections = []
        for _ in range(num_sections):
            raw = f.read(40)
            name = raw[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', raw[8:12])[0]
            vaddr = struct.unpack('<I', raw[12:16])[0]
            rsize = struct.unpack('<I', raw[16:20])[0]
            roff = struct.unpack('<I', raw[20:24])[0]
            sections.append({'name': name, 'vaddr': vaddr, 'vsize': vsize, 'roff': roff, 'rsize': rsize})
        return image_base, sections

image_base, sections = load_pe(NTDLL_BIN)

def rva_to_offset(rva):
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return rva - s['vaddr'] + s['roff']
    return None

def read_bytes(path, offset, size=16):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(size)

# Load Ghidra
ghidra = set()
with open(GHIDRA_CSV) as f:
    reader = csv.DictReader(f)
    for row in reader:
        ghidra.add(int(row['address'], 16))

# Load Enigma
def load_enigma(path):
    result = {}
    with open(path, encoding='utf-8', errors='ignore') as f:
        header_found = False
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('address,type,name'):
                header_found = True
                continue
            if not header_found:
                continue
            parts = line.split(',')
            addr = int(parts[0], 16)
            name = parts[2] if len(parts) > 2 else ''
            result[addr] = name
    return result

enigma = load_enigma(ENIGMA_CSV)

# Load PE sections
image_base, sections = load_pe(NTDLL_BIN)
print(f"NTDLL ImageBase: 0x{image_base:X}")
print(f"NTDLL sections: {[s['name'] for s in sections]}")

# Find func_data extras only
func_data_addrs = [(a, n) for a, n in enigma.items() if a not in ghidra and n.startswith('func_data_')]
print(f"\nTotal func_data extras: {len(func_data_addrs)}")

# Analyze first bytes of each
from collections import Counter as CC
first_byte_counts = CC()
all_bytes_sample = []

for addr, name in func_data_addrs:
    offset = rva_to_offset(addr - image_base)
    if offset is None:
        continue
    data = read_bytes(NTDLL_BIN, offset, 16)
    if not data:
        continue
    fb = data[0]
    first_byte_counts[fb] += 1
    all_bytes_sample.append((addr, data))

print(f"\nFirst-byte distribution for {len(func_data_addrs)} func_data entries:")
print(f"{'Byte':>8} {'Count':>8} {'%':>8}")
print("-" * 28)
for b, count in sorted(first_byte_counts.most_common()):
    desc = {
        0x00: '00 (null)', 0xFF: 'FF (r/m)', 0xCC: 'CC (int3)',
        0xE9: 'E9 (jmp)', 0xEB: 'EB (short jmp)',
        0xC3: 'C3 (ret)', 0x48: '48 (REX.W)',
        0x8B: '8B (mov)', 0x4C: '4C (REX.W,R)',
        0x44: '44 (REX.R)', 0x40: '40 (REX)',
        0x85: '85 (test)', 0x33: '33 (xor)',
        0x89: '89 (mov)', 0x0F: '0F (2-byte opcode)',
        0x66: '66 (op-size)', 0x65: '65 (gs)',
        0x64: '64 (fs)', 0x74: '74 (jz)',
        0x75: '75 (jnz)', 0x83: '83 (arith)',
        0xB0: 'B0 (mov imm8)', 0x32: '32 (xor r/m)',
        0x38: '38 (cmp)', 0x39: '39 (cmp)',
        0x3B: '3B (cmp)', 0x3C: '3C (cmp al)',
        0x3D: '3D (cmp eax)', 0x41: '41 (REX.B)',
        0x42: '42 (REX.X)', 0x43: '43 (REX.XB)',
        0x45: '45 (REX.RB)', 0x46: '46 (REX.RX)',
        0x47: '47 (REX.RXB)', 0x49: '49 (REX.WB)',
        0x4A: '4A (REX.WX)', 0x4B: '4B (REX.WXB)',
        0x4D: '4D (REX.WRB)', 0x4E: '4E (REX.WRX)',
        0x4F: '4F (REX.WRXB)',
        0x50: '50 (push rax)', 0x51: '51 (push rcx)',
        0x52: '52 (push rdx)', 0x53: '53 (push rbx)',
        0x54: '54 (push rsp)', 0x55: '55 (push rbp)',
        0x56: '56 (push rsi)', 0x57: '57 (push rdi)',
        0x68: '68 (push imm)', 0x6A: '6A (push imm8)',
        0x80: '80 (arith)', 0x84: '84 (test)',
        0x86: '86 (xchg)', 0x87: '87 (xchg)',
        0x88: '88 (mov)', 0x8A: '8A (mov)',
        0x8D: '8D (lea)', 0x90: '90 (nop)',
        0xA0: 'A0 (mov al)', 0xA1: 'A1 (mov eax)',
        0xA8: 'A8 (test al)', 0xAA: 'AA (stosb)',
        0xB2: 'B2 (mov dl)', 0xBA: 'BA (mov edx)',
        0xBB: 'BB (mov ebx)', 0xBC: 'BC (mov esp)',
        0xBD: 'BD (mov ebp)', 0xBE: 'BE (mov esi)',
        0xBF: 'BF (mov edi)', 0xC2: 'C2 (ret near)',
        0xC6: 'C6 (mov byte)', 0xC7: 'C7 (mov dword)',
        0xD1: 'D1 (shift)', 0xD3: 'D3 (shift)',
        0xE8: 'E8 (call)', 0xEC: 'EC (in)',
        0xF2: 'F2 (repne)', 0xF3: 'F3 (repe)',
        0xF6: 'F6 (test/not)', 0xF7: 'F7 (test/not)',
        0xFE: 'FE (inc/dec)',
    }.get(b, '')
    label = f"0x{b:02X} ({desc})" if desc else f"0x{b:02X}"
    print(f"{label:>24} {count:>8} {count/len(func_data_addrs)*100:>7.1f}%")

# Categorize by plausibility as code
print(f"\n--- Plausibility assessment ---")
print(f"{'Category':<30} {'Count':>6} {'%':>8}")
print("-" * 46)

# Classification
zero_or_null = 0  # 0x00, 0xCC — likely data
pattern_coincidence = 0  # JMP (0xE9, 0xEB), RET (0xC3) — could be data at function end
unlikely_code = 0  # prefix bytes like REX sitting alone
plausible_code = 0  # normal instruction starts: mov, push, xor, test, lea, cmp, etc.

rejected_bytes = {0x00, 0xCC}  # DataSectionFunctionScanner rejects these anyway
boundary_bytes = {0xCC, 0xC3, 0xE9, 0xEB}  # isAtFunctionBoundary() accepts

for addr, name in func_data_addrs:
    offset = rva_to_offset(addr - image_base)
    if offset is None:
        continue
    data = read_bytes(NTDLL_BIN, offset, 16)
    if not data:
        continue
    fb = data[0]
    
    # Determine which category
    if fb in {0x00, 0xCC}:
        # Rejected by the noise fix filter — shouldn't exist, but checking
        category = "rejected_by_fix (00/CC)"
    elif fb in {0xE9, 0xEB, 0xC3}:
        # JMP/RET — could be boundary byte pattern match
        # Check the surrounding bytes to see if this is at end of function
        prev_byte = None
        if offset > 0:
            prev_data = read_bytes(NTDLL_BIN, offset - 1, 1)
            if prev_data:
                prev_byte = prev_data[0]
        if prev_byte in {0xCC, 0xC3}:
            category = "at_alignment_gap (after CC/C3)"
        else:
            category = "func_body_start (JMP/RET first)"
    elif fb in {0xFF, 0xF6, 0xF7, 0x80, 0xFE}:
        # ModR/M following — x86-64: FF/15, FF/25 are common at function starts (call/jmp [rip+...])
        # But as a bare first byte with no fixed decode, could be code
        if fb == 0xFF and len(data) > 1:
            modrm = data[1]
            reg = (modrm >> 3) & 7
            if reg in {2, 4, 6}:  # CALL/JMP/PUSH via reg field
                category = "indirect_call_jmp (FF/reg)"
            else:
                category = "modrm_instr (FF)"
        else:
            category = "modrm_instr (FF/F6/F7/80/FE)"
    elif fb in {0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x66, 0x64, 0x65, 0xF2, 0xF3}:
        # Prefix bytes — indicates actual instruction follows, plausible code
        category = "prefix_byte (REX/seg/rep)"
    elif fb in {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x68, 0x6A}:
        # Push instructions — common at function starts
        category = "push_instruction"
    elif fb in {0x8B, 0x89, 0x88, 0x8A, 0xC6, 0xC7}:
        # Mov instructions
        category = "mov_instruction"
    elif fb in {0x33, 0x31, 0x85, 0x84, 0x86, 0x87}:
        # XOR, TEST, XCHG
        category = "logic_instruction"
    elif fb in {0xE8}:
        category = "call_instruction"
    elif fb in {0x0F}:
        # Two-byte opcode — check second byte
        if len(data) > 1:
            second = data[1]
            if second == 0x1F:  # NOP
                category = "nop_multi_byte (0F 1F)"
            elif second == 0xB6 or second == 0xB7:  # MOVZX
                category = "movzx (0F B6/B7)"
            elif second == 0xBE or second == 0xBF:  # MOVSX
                category = "movsx (0F BE/BF)"
            elif second == 0x84:  # JE/JZ
                category = "jcc_2byte (0F 84)"
            elif second == 0x85:  # JNE/JNZ
                category = "jcc_2byte (0F 85)"
            elif second == 0x05:  # syscall
                category = "syscall (0F 05)"
            else:
                category = f"two_byte_opcode (0F {second:02X})"
        else:
            category = "two_byte_opcode (0F ??)"
    elif fb in {0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F,
                0x70, 0x71, 0x72, 0x73, 0x76, 0x77,
                0x78, 0x79, 0x7A, 0x7B}:
        # Conditional jumps
        category = "jcc_instruction"
    elif fb in {0x3C, 0x3D, 0x38, 0x39, 0x3A, 0x3B, 0x83}:
        # CMP instructions
        category = "cmp_instruction"
    elif fb in {0xB0, 0xB2, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
                0xB1, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9}:
        # MOV r, imm8/B0-BF variants
        category = "mov_imm_register"
    elif fb in {0xA0, 0xA1, 0xA8, 0xAA}:
        category = "accumulator_instruction"
    elif fb in {0xD1, 0xD3}:
        category = "shift_instruction"
    elif fb in {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97}:
        # NOP, XCHG
        category = "nop_or_xchg"
    elif fb in {0xC2}:
        category = "ret_immediate (C2)"
    elif fb in {0xEC}:
        category = "io_instruction"
    elif fb in {0x1A, 0x1B}:
        category = "sbb_instruction"
    else:
        category = f"other (0x{fb:02X})"
    
    if fb in rejected_bytes:
        zero_or_null += 1
    elif fb in {0xE9, 0xEB, 0xC3}:
        pattern_coincidence += 1
    elif fb in {0xFF, 0xF6, 0xF7, 0x80, 0xFE}:
        unlikely_code += 1
    else:
        plausible_code += 1

total_checked = zero_or_null + pattern_coincidence + unlikely_code + plausible_code

for label, count in [
    ("Plausible function prologue", plausible_code),
    ("Pattern coincidence (JMP/RET)", pattern_coincidence),
    ("ModRM-first-byte (FF/F6/etc)", unlikely_code),
    ("Rejected byte (00/CC)", zero_or_null),
]:
    print(f"{label:<30} {count:>6} {count/total_checked*100:>7.1f}%")

print(f"\n--- Detailed first-byte breakdown (top 40) ---")
print(f"{'Byte':>24} {'Count':>6} {'%':>7}")
print("-" * 40)
for b, count in sorted(first_byte_counts.most_common(40)):
    desc = {
        0x00: 'null', 0xCC: 'int3', 0xE9: 'rel jmp', 0xEB: 'short jmp',
        0xC3: 'ret', 0x48: 'REX.W', 0x8B: 'mov', 0x4C: 'REX.WR',
        0x44: 'REX.R', 0x40: 'REX', 0x85: 'test', 0x33: 'xor',
        0x89: 'mov', 0x0F: '2byte op', 0x66: 'op size',
        0x65: 'gs', 0x64: 'fs', 0x74: 'jz', 0x75: 'jnz',
        0x83: 'arith', 0xC7: 'mov dword',
    }.get(b, '')
    label = f"0x{b:02X} {desc}" if desc else f"0x{b:02X}"
    print(f"{label:>24} {count:>6} {count/total_checked*100:>6.1f}%")

# Print examples
print(f"\n--- Example entries (every 30th) ---")
for i in range(0, len(func_data_addrs), 30):
    addr, name = func_data_addrs[i]
    rva = addr - image_base
    offset = rva_to_offset(rva)
    data = read_bytes(NTDLL_BIN, offset, 16)
    hex_bytes = ' '.join(f'{b:02X}' for b in data[:8])
    prev_ok = ""
    if offset >= 1:
        prev = read_bytes(NTDLL_BIN, offset - 1, 1)
        if prev and prev[0] in {0xCC, 0xC3, 0xE9, 0xEB, 0x00, 0x90}:
            prev_ok = f" (preceded by 0x{prev[0]:02X})"
    print(f"  0x{addr:08X} {hex_bytes}{prev_ok}")
