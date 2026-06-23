#!/usr/bin/env python3
"""
Phase 4: Stratified sample validation.
Selects random functions per category, disassembles with Capstone,
and compares against Ghidra. Outputs HTML report.
"""

import csv
import random
import struct
import html
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

random.seed(42)

# Paths
CLASSIFY_CSV = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\classify_kernel32.csv")
GHIDRA_CSV = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\ghidra_kernel32.csv")
ENIGMA_CSV = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\enigma_kernel32_fixed3.csv")
KERNEL32_DLL = Path(r"C:\Windows\System32\kernel32.dll")

SAMPLES_PER_CATEGORY = 5

# Load Ghidra address set
ghidra_addrs = set()
ghidra_names = {}
with open(GHIDRA_CSV, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        addr = int(row['address'], 16)
        ghidra_addrs.add(addr)
        ghidra_names[addr] = row['name']

print(f"Loaded {len(ghidra_addrs)} Ghidra functions")

# Load Enigma functions (no header CSV)
enigma_addrs = set()
enigma_names = {}
with open(ENIGMA_CSV, newline='') as f:
    for line in f:
        line = line.strip()
        if line:
            parts = line.split(',')
            if len(parts) >= 1:
                addr = int(parts[0], 16)
                enigma_addrs.add(addr)
                enigma_names[addr] = parts[1] if len(parts) > 1 else ''
print(f"Loaded {len(enigma_addrs)} Enigma functions")

# Load classify CSV and group by prefix
categories = {}
classify_info = {}
with open(CLASSIFY_CSV, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        addr = int(row['address'], 16)
        prefix = row['prefix']
        if prefix not in categories:
            categories[prefix] = []
        categories[prefix].append(addr)
        classify_info[addr] = {
            'name': row['name'],
            'prefix': prefix,
            'section': row['section'],
            'size': int(row['size']),
            'in_pdata': int(row['in_pdata']),
            'caller_count': int(row['caller_count']),
            'first_byte_hex': row['first_byte_hex'],
        }

# Print category sizes
target_order = ['func_pdata', 'func_data', 'func_jmp', 'func_call', 'func_start']
for cat in target_order:
    if cat in categories:
        print(f"{cat}: {len(categories[cat])} functions")

# Load kernel32 DLL
with open(KERNEL32_DLL, 'rb') as f:
    dll_bytes = f.read()

# ---------- PE Parse ----------
def read_u16(data, off): return struct.unpack_from('<H', data, off)[0]
def read_u32(data, off): return struct.unpack_from('<I', data, off)[0]
def read_u64(data, off): return struct.unpack_from('<Q', data, off)[0]

e_lfanew = read_u32(dll_bytes, 0x3C)
assert dll_bytes[e_lfanew:e_lfanew+4] == b'PE\x00\x00', "No PE sig"

num_sections = read_u16(dll_bytes, e_lfanew + 6)
sizeof_opt_hdr = read_u16(dll_bytes, e_lfanew + 20)
sections_offset = e_lfanew + 24 + sizeof_opt_hdr

# Detect PE32+ (Magic 0x20B) vs PE32 (Magic 0x10B)
opt_hdr = e_lfanew + 24
magic = read_u16(dll_bytes, opt_hdr)
is_pe32plus = (magic == 0x20B)
# ImageBase: PE32+ at opt_hdr+24 (8 bytes), PE32 at opt_hdr+28 (4 bytes)
if is_pe32plus:
    image_base = read_u64(dll_bytes, opt_hdr + 24)
else:
    image_base = read_u32(dll_bytes, opt_hdr + 28)
print(f"ImageBase: 0x{image_base:016X}")

# Find .text section
text_va = None
text_raw_ptr = None
text_raw_size = None
for i in range(num_sections):
    sec_off = sections_offset + i * 40
    sec_name = dll_bytes[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    if sec_name == '.text':
        text_va = read_u32(dll_bytes, sec_off + 12)
        text_raw_ptr = read_u32(dll_bytes, sec_off + 20)
        text_raw_size = read_u32(dll_bytes, sec_off + 16)
        break

assert text_va is not None, "No .text section found"
print(f".text: VA=0x{text_va:08X}, RawPtr=0x{text_raw_ptr:08X}, RawSize=0x{text_raw_size:X}")

# Function to convert VA to file offset
def va_to_offset(va):
    rva = va - image_base
    if text_va <= rva < text_va + text_raw_size:
        return text_raw_ptr + (rva - text_va)
    return None

# Initialize Capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

# Disassemble a function
def disassemble_func(va, size):
    file_off = va_to_offset(va)
    if file_off is None or file_off + size > len(dll_bytes):
        return None, f"Cannot read bytes at VA 0x{va:X} (file_off={file_off})"
    code = dll_bytes[file_off:file_off+size]
    instrs = []
    try:
        for insn in md.disasm(code, va):
            instrs.append({
                'addr': insn.address,
                'size': insn.size,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.bytes.hex(),
            })
    except Exception as e:
        return None, f"Disassembly error: {e}"
    return instrs, None

# Select stratified samples
samples = []
for cat in target_order:
    if cat not in categories:
        continue
    pool = [a for a in categories[cat] if a in enigma_addrs]
    if len(pool) > SAMPLES_PER_CATEGORY:
        chosen = random.sample(pool, SAMPLES_PER_CATEGORY)
    else:
        chosen = pool[:]
    for addr in chosen:
        info = classify_info[addr]
        size = info['size']
        if size <= 0:
            size = 64
        if size > 512:
            size = 256
        samples.append({
            'address': addr,
            'va': f"0x{addr:X}",
            'name': info['name'],
            'prefix': info['prefix'],
            'size': info['size'],
            'in_pdata': info['in_pdata'],
            'caller_count': info['caller_count'],
            'first_byte': info['first_byte_hex'],
            'disasm_size': size,
            'in_ghidra': addr in ghidra_addrs,
            'ghidra_name': ghidra_names.get(addr, 'N/A'),
        })

print(f"\nSelected {len(samples)} samples for analysis")

# Disassemble all samples
for s in samples:
    instrs, err = disassemble_func(s['address'], s['disasm_size'])
    if err:
        s['error'] = err
        s['instructions'] = []
        s['first_three'] = []
        s['last_three'] = []
    else:
        s['error'] = None
        s['instructions'] = instrs
        s['ending_mnemonic'] = instrs[-1]['mnemonic'] if instrs else 'N/A'
        s['instr_count'] = len(instrs)
        valid_ends = {'ret', 'retn', 'retf', 'iret', 'int3', 'jmp'}
        s['valid_ending'] = s['ending_mnemonic'] in valid_ends
    s['has_rets'] = any(i['mnemonic'] in {'ret', 'retn', 'retf'} for i in s.get('instructions', []))

# Generate HTML report
def escape(s):
    return html.escape(str(s))

def instr_class(mnemonic):
    m = mnemonic.lower()
    if m in ('ret','retn','retf'): return 'ret'
    if m == 'int3': return 'int3'
    if m == 'jmp': return 'jmp'
    if m == 'call': return 'call'
    if m in ('je','jne','jg','jl','jge','jle','ja','jb','jae','jbe','js','jns','jo','jno','jp','jnp'): return 'jcc'
    return 'other'

html_parts = []
html_parts.append(f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>Phase 4 - Stratified Sample Validation</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; color: #222; }}
h1 {{ color: #333; border-bottom: 2px solid #666; padding-bottom: 8px; }}
h2 {{ color: #444; margin-top: 32px; background: #e0e0e0; padding: 6px 12px; border-radius: 4px; }}
.summary {{ background: #fff; padding: 16px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.2); margin: 12px 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }}
th, td {{ border: 1px solid #ccc; padding: 5px 10px; text-align: left; font-size: 13px; }}
th {{ background: #ddd; font-weight: 600; }}
tr:nth-child(even) {{ background: #fafafa; }}
.section-card {{ background: #fff; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.15); margin: 16px 0; padding: 12px; }}
.instr-table td {{ font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; padding: 2px 8px; }}
.va-col {{ color: #888; }}
.bytes-col {{ color: #666; }}
.mnemonic {{ font-weight: 600; }}
.ending-bad {{ background: #fff0f0; }}
.ending-good {{ background: #f0fff0; }}
.tag-ghidra {{ background: #d4edda; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
.tag-extra {{ background: #fff3cd; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
.instr-ret {{ color: #c7254e; }}
.instr-int3 {{ color: #999; }}
.instr-jmp {{ color: #8a6d3b; }}
.instr-call {{ color: #31708f; }}
.instr-jcc {{ color: #3c763d; }}
.error {{ color: #a94442; background: #f2dede; padding: 8px; border-radius: 4px; }}
.badge {{ display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 11px; font-weight: 600; margin: 1px; }}
.badge-pdata {{ background: #cce5ff; color: #004085; }}
.badge-data {{ background: #e2e3e5; color: #383d41; }}
.badge-jmp {{ background: #fff3cd; color: #856404; }}
.badge-call {{ background: #d4edda; color: #155724; }}
.badge-start {{ background: #f8d7da; color: #721c24; }}
</style></head><body>
<h1>Phase 4 — Stratified Sample Validation</h1>
<p>Comparing Enigma extra functions vs Ghidra for kernel32.dll</p>
<div class='summary'>
""")

total_ghidra = sum(1 for s in samples if s['in_ghidra'])
total_valid = sum(1 for s in samples if s.get('valid_ending'))
total_invalid = sum(1 for s in samples if not s.get('valid_ending'))
has_ret_count = sum(1 for s in samples if s.get('has_rets'))

html_parts.append(f"""
<p><b>Total samples:</b> {len(samples)} | <b>In Ghidra:</b> {total_ghidra}/{len(samples)} | 
<b>Valid ending:</b> {total_valid} | <b>Invalid ending:</b> {total_invalid} | <b>Has RET:</b> {has_ret_count}</p>
</div>
""")

# Summary table
html_parts.append("<h2>Sample Overview</h2>")
html_parts.append("<table><tr><th>VA</th><th>Name</th><th>Category</th><th>Size</th><th>.pdata</th><th>Callers</th><th>In Ghidra</th><th>Ghidra Name</th><th>Instrs</th><th>Ends With</th><th>Has RET</th></tr>")
for s in samples:
    badge_class = f"badge-{s['prefix'].replace('func_', '')}"
    ghidra_tag = f"<span class='tag-ghidra'>Yes</span>" if s['in_ghidra'] else f"<span class='tag-extra'>Extra</span>"
    valid_class = "" if s.get('valid_ending') else " style='background:#fff0f0'"
    html_parts.append(f"<tr{valid_class}><td>{s['va']}</td><td>{escape(s['name'])}</td><td><span class='badge {badge_class}'>{escape(s['prefix'])}</span></td><td>{s['size']}</td><td>{s['in_pdata']}</td><td>{s['caller_count']}</td><td>{ghidra_tag}</td><td>{escape(s.get('ghidra_name',''))}</td><td>{s.get('instr_count','?')}</td><td>{escape(s.get('ending_mnemonic','?'))}</td><td>{'Yes' if s.get('has_rets') else 'No'}</td></tr>")
html_parts.append("</table>")

# Detailed sections per category
for cat in target_order:
    cat_samples = [s for s in samples if s['prefix'] == cat]
    if not cat_samples:
        continue
    badge_class = f"badge-{cat.replace('func_', '')}"
    html_parts.append(f"<h2><span class='badge {badge_class}'>{cat}</span> — {len(cat_samples)} samples</h2>")
    
    for s in cat_samples:
        valid_class = "" if s.get('valid_ending') else " ending-bad"
        html_parts.append(f"<div class='section-card{valid_class}'>")
        html_parts.append(f"<h3>{s['va']} — {escape(s['name'])} <small>(size={s['size']}, callers={s['caller_count']}, .pdata={s['in_pdata']})</small></h3>")
        
        if s['in_ghidra']:
            html_parts.append(f"<p><span class='tag-ghidra'>IN GHIDRA</span> as <b>{escape(s['ghidra_name'])}</b> — this function is in Ghidra but mis-classified as an 'extra'.</p>")
        
        if s.get('error'):
            html_parts.append(f"<div class='error'>{escape(s['error'])}</div>")
        elif s.get('instructions'):
            instrs = s['instructions']
            html_parts.append(f"<p>Total: {len(instrs)} instructions</p>")
            html_parts.append("<table class='instr-table'><tr><th>#</th><th>Addr</th><th>Bytes</th><th>Mnemonic</th><th>Operands</th></tr>")
            
            show_all = len(instrs) <= 25
            for idx, i in enumerate(instrs):
                if not show_all and idx >= 10 and idx < len(instrs) - 5:
                    if idx == 10:
                        html_parts.append(f"<tr><td colspan='5' style='text-align:center;color:#999;'>... {len(instrs)-15} instructions omitted ...</td></tr>")
                    continue
                ic = instr_class(i['mnemonic'])
                html_parts.append(f"<tr><td>{idx+1}</td><td class='va-col'>0x{i['addr']:X}</td><td class='bytes-col'>{i['bytes']}</td><td class='mnemonic instr-{ic}'>{escape(i['mnemonic'])}</td><td>{escape(i['op_str'])}</td></tr>")
            html_parts.append("</table>")
            
            issues = []
            if not s.get('valid_ending'):
                issues.append(f"Does not end with a valid terminal (ends with {s.get('ending_mnemonic', '?')})")
            if not s.get('has_rets'):
                issues.append("No RET instruction found in body")
            
            if issues:
                html_parts.append("<p style='color:#a94442;'><b>Issues:</b></p><ul>")
                for iss in issues:
                    html_parts.append(f"<li>{escape(iss)}</li>")
                html_parts.append("</ul>")
            else:
                html_parts.append("<p style='color:#3c763d;'><b>Verdict:</b> Likely VALID function (terminates correctly)</p>")
        else:
            html_parts.append("<p class='error'>No instructions</p>")
        
        html_parts.append("</div>")

html_parts.append("</body></html>")

report_path = Path(r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\phase4_report.html")
with open(report_path, 'w') as f:
    f.write('\n'.join(html_parts))

print(f"\nReport written to {report_path}")
print(f"Total samples: {len(samples)}")
