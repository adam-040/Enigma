#!/usr/bin/env python3
"""
phase_b_experiment.py — Phase B aggressive recovery measurement tool.
Read-only analysis of shell32 to determine how many of the remaining 714
Ghidra functions could be recovered via aggressive heuristics.
Uses the same confidence framework as AggressiveRecoveryAnalyzer.
"""
import sys, io, struct, csv
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BINARY = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\shell32_test.dll"
REMAINING_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\remaining_714.csv"
ENIGMA_FINAL = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\enigma_shell32_final.csv"
GHIDRA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\ghidra_shell32_test.csv"
OUT_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\phase_b_experiment_results.csv"

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    CAPSTONE_OK = True
except ImportError:
    print("capstone required: pip install capstone")
    CAPSTONE_OK = False

# ============================================================
# Scoring system (mirrors AggressiveRecoveryAnalyzer)
# ============================================================
SCORE_PDATA_ENTRY = 100
SCORE_EXPORT_TABLE = 100
SCORE_IMPORT_THUNK = 90
SCORE_MULTIPLE_CALL_REFS = 80
SCORE_RDATA_8BYTE_PTR = 75
SCORE_SINGLE_CALL_REF = 60
SCORE_4BYTE_RVA_RDATA = 50
SCORE_VTABLE_RUN = 70
SCORE_VALID_RET_ENDING = 30
SCORE_VALID_INT3_ENDING = 25
SCORE_VALID_JMP_ENDING = 20
SCORE_EXECUTABLE_BYTES_ONLY = 10
SCORE_PENALTY_OVERLAP = -50
SCORE_PENALTY_TRUNCATION = -30

def classify_level(total):
    if total >= 80: return "HIGH"
    if total >= 40: return "MEDIUM"
    if total >= 10: return "LOW"
    return "SPECULATIVE"

def score_candidate(instr_count, last_mnem, has_call_refs, has_data_refs,
                    in_pdata, in_export, in_vtable_run, nearest_dist):
    score = 0
    if in_pdata: score += SCORE_PDATA_ENTRY
    if in_export: score += SCORE_EXPORT_TABLE
    if has_call_refs: score += SCORE_SINGLE_CALL_REF
    if has_data_refs: score += SCORE_RDATA_8BYTE_PTR
    if in_vtable_run: score += SCORE_VTABLE_RUN
    if last_mnem in ('ret', 'retn'):
        score += SCORE_VALID_RET_ENDING
    elif last_mnem == 'int3':
        score += SCORE_VALID_INT3_ENDING
    elif last_mnem == 'jmp':
        score += SCORE_VALID_JMP_ENDING
    elif last_mnem in ('call', 'je', 'jne', 'jg', 'jl', 'jge', 'jle',
                       'ja', 'jb', 'jae', 'jbe', 'js', 'jns'):
        score += SCORE_PENALTY_TRUNCATION
    if nearest_dist <= 64 and score > SCORE_EXECUTABLE_BYTES_ONLY:
        score += 5
    if score == 0:
        score = SCORE_EXECUTABLE_BYTES_ONLY
    return max(0, score)

# ============================================================
# PE parsing
# ============================================================
def rw(f): return struct.unpack('<H', f.read(2))[0]
def rd(f): return struct.unpack('<I', f.read(4))[0]
def rq(f): return struct.unpack('<Q', f.read(8))[0]

def parse_pe(path):
    sections = {}; image_base = 0; pdata = []; export_addrs = set()
    with open(path, 'rb') as f:
        f.seek(0x3C); e_lfanew = rd(f); f.seek(e_lfanew); assert f.read(4)==b'PE\x00\x00'
        f.read(2); ns = rw(f); f.read(12); opt_sz = rw(f); f.read(2)
        opt_start = f.tell(); magic = rw(f); is64 = magic==0x20b
        if is64: f.seek(opt_start+24); image_base = rq(f)
        else: f.seek(opt_start+28); image_base = rd(f)
        dd_off = opt_start+(112 if is64 else 96); f.seek(dd_off)
        data_dirs = [rd(f) for _ in range(16)]
        f.seek(opt_start+opt_sz)
        for _ in range(ns):
            name = f.read(8).rstrip(b'\x00').decode('ascii',errors='ignore')
            vs=rd(f); va=rd(f); rs=rd(f); rp=rd(f); f.read(16)
            sections[name]={'va':va,'vs':vs,'raw_size':rs,'raw_ptr':rp}
        if '.pdata' in sections:
            ps=sections['.pdata']; f.seek(ps['raw_ptr'])
            for i in range(0, min(ps['raw_size'],ps['vs']), 12):
                d=f.read(12)
                if len(d)<12: break
                b,e,u=struct.unpack('<III',d)
                if b: pdata.append({'begin':image_base+b,'end':image_base+(e&0x7fffffff)})
        er=data_dirs[0]
        if er and sections:
            for sn,sc in sections.items():
                if sc['va']<=er<sc['va']+sc['vs']:
                    f.seek(sc['raw_ptr']+(er-sc['va'])); f.read(12)
                    rd(f); nr=rd(f); af=rd(f)
                    for sn2,sc2 in sections.items():
                        if sc2['va']<=af<sc2['va']+sc2['vs']:
                            f.seek(sc2['raw_ptr']+(af-sc2['va']))
                            for _ in range(nr):
                                fva=rd(f)
                                if fva: export_addrs.add(image_base+fva)
                            break
                    break
    return sections, image_base, pdata, export_addrs

def read_raw_bytes(path, addr, size):
    s, ib, _, _ = parse_pe(path)
    rva = addr - ib
    with open(path, 'rb') as f:
        for sn, sc in s.items():
            if sc['va'] <= rva < sc['va'] + sc['vs']:
                off = sc['raw_ptr'] + (rva - sc['va'])
                if sc.get('raw_size'):
                    mx = sc['raw_ptr'] + sc['raw_size'] - off
                    if mx <= 0: return b''
                    size = min(size, mx)
                f.seek(off); return f.read(size)
    return b''

def sec_of(addr, sections, ib):
    rva = addr - ib
    for n, s in sections.items():
        if s['va'] <= rva < s['va'] + s['vs']:
            return n
    return None

# ============================================================
# Main experiment
# ============================================================
print("=" * 70)
print("PHASE B — AGGRESSIVE RECOVERY EXPERIMENT")
print("=" * 70)

sections, image_base, pdata, export_addrs = parse_pe(BINARY)
print(f"\nImage Base: 0x{image_base:x}")
print(f"PDATA entries: {len(pdata)}")
print(f"Export addresses: {len(export_addrs)}")

# Load remaining 714
remaining = []
with open(REMAINING_CSV, encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        row['addr_int'] = int(row['addr'], 0)
        remaining.append(row)

print(f"\nRemaining 714 Ghidra functions loaded: {len(remaining)}")

# Load Enigma final functions (Phase A baseline)
enigma_funcs = set()
with open(ENIGMA_FINAL, encoding='utf-8') as f:
    for row in csv.reader(f):
        if not row: continue
        try: enigma_funcs.add(int(row[0].strip(), 16))
        except: pass

print(f"Enigma Phase A functions loaded: {len(enigma_funcs)}")

# Load Ghidra functions
ghidra_funcs = set()
with open(GHIDRA_CSV, encoding='utf-8') as f:
    for row in csv.reader(f):
        if not row: continue
        try: ghidra_funcs.add(int(row[0].strip(), 16))
        except: pass

print(f"Ghidra functions loaded: {len(ghidra_funcs)}")

# ============================================================
# Experiment 1: Score the remaining 714 with confidence framework
# ============================================================
print("\n" + "=" * 70)
print("EXPERIMENT 1: Confidence scoring of remaining 714")
print("=" * 70)

pdata_addrs = {p['begin'] for p in pdata}
pdata_range = [(p['begin'], p['end']) for p in pdata]

# Build sorted Enigma function list for proximity
enigma_sorted = sorted(enigma_funcs)

results = []
confidence_dist = Counter()

for r in remaining:
    addr = r['addr_int']
    instr_count = int(r['instr_count'])
    first_mnem = r['first_mnem']
    last_mnem = r['last_mnem']
    nearest_dist = int(r['nearest_dist'])
    in_call_refs = int(r['in_call_refs'])
    in_rdata_refs = int(r['in_rdata_refs'])
    in_pdata = int(r['in_pdata'])
    in_export = int(r['in_export'])
    in_vtable_run = int(r['in_vtable_run'])
    category = r['category']

    has_call_refs = in_call_refs > 0
    has_data_refs = in_rdata_refs > 0 or in_vtable_run > 0

    score = score_candidate(instr_count, last_mnem, has_call_refs, has_data_refs,
                            in_pdata, in_export, in_vtable_run, nearest_dist)
    level = classify_level(score)
    confidence_dist[level] += 1

    results.append({
        'addr': addr,
        'name': r['name'],
        'category': category,
        'score': score,
        'level': level,
        'instr_count': instr_count,
        'first_mnem': first_mnem,
        'last_mnem': last_mnem,
        'nearest_dist': nearest_dist,
        'has_call_refs': has_call_refs,
        'has_data_refs': has_data_refs,
        'in_pdata': in_pdata,
        'in_export': in_export,
        'in_vtable_run': in_vtable_run,
    })

print("\nConfidence distribution across all 714:")
for level in ['HIGH', 'MEDIUM', 'LOW', 'SPECULATIVE']:
    c = confidence_dist.get(level, 0)
    print(f"  {level:15s}: {c:4d} ({c*100/len(results):.1f}%)")

# ============================================================
# Experiment 2: Aggressive recoverability by cluster
# ============================================================
print("\n" + "=" * 70)
print("EXPERIMENT 2: Recoverability by cluster")
print("=" * 70)

# VTABLE_DISPATCH — already 100% recovered in Phase A
# GHIDRA_SPECULATIVE — the orphans
# ADJUSTOR_THUNK — deterministic but zero refs

clusters = Counter(r['category'] for r in results)
print(f"\nCluster breakdown:")
for cat, cnt in clusters.most_common():
    cats = [r for r in results if r['category'] == cat]
    high = sum(1 for r in cats if r['level'] == 'HIGH')
    med = sum(1 for r in cats if r['level'] == 'MEDIUM')
    low = sum(1 for r in cats if r['level'] == 'LOW')
    spec = sum(1 for r in cats if r['level'] == 'SPECULATIVE')
    print(f"  {cat:25s}: {cnt:4d} total — HIGH={high} MED={med} LOW={low} SPEC={spec}")

# GHIDRA_SPECULATIVE cluster
speculative = [r for r in results if r['category'] == 'GHIDRA_SPECULATIVE']
print(f"\nGHIDRA_SPECULATIVE functions: {len(speculative)}")

# Sub-cluster by end mnemonic
end_mnem = Counter(r['last_mnem'] for r in speculative)
print(f"  End mnemonic distribution:")
for m, c in end_mnem.most_common():
    print(f"    {m:>8s}: {c:3d}")

# Ends in RET/INT3 (complete functions)
complete = [r for r in speculative if r['last_mnem'] in ('ret', 'retn', 'int3')]
print(f"  Complete orphans (ends RET/INT3): {len(complete)}")
print(f"    - These are valid function bodies, just orphaned")
print(f"    - Confidence: LOW (orphan island, no refs)")
print(f"    - Recovery via AggressiveRecoveryAnalyzer: possible")

# Score these
for r in complete[:5]:
    print(f"    0x{r['addr']:x} instr={r['instr_count']} score={r['score']} ({r['level']})")

# Ends in JMP (tail call wrappers)
jmp_end = [r for r in speculative if r['last_mnem'] == 'jmp']
print(f"\n  Tail-call orphans (ends JMP): {len(jmp_end)}")
print(f"    - These could be adjustor thunks or wrappers")
print(f"    - Confidence: LOW (no refs, but valid tail call)")
for r in jmp_end[:3]:
    print(f"    0x{r['addr']:x} first={r['first_mnem']} score={r['score']} ({r['level']})")

# Mid-function truncations
truncated = [r for r in speculative if r['last_mnem'] not in ('ret', 'retn', 'int3', 'jmp')]
print(f"\n  Mid-function truncations: {len(truncated)}")
print(f"    - These are Ghidra over-fragments, NOT recoverable")
for r in truncated[:5]:
    print(f"    0x{r['addr']:x} last={r['last_mnem']} instr={r['instr_count']}")

# ============================================================
# Experiment 3: Tiny helper scanning
# ============================================================
print("\n" + "=" * 70)
print("EXPERIMENT 3: Tiny helper candidates (remaining 714)")
print("=" * 70)

tiny = [r for r in speculative if r['instr_count'] <= 4 and r['last_mnem'] in ('ret', 'retn')]
print(f"  TINY_HELPER candidates (<=4 instr, ends RET): {len(tiny)}")
for r in tiny[:5]:
    print(f"    0x{r['addr']:x} instr={r['instr_count']} first={r['first_mnem']} score={r['score']}")

# ============================================================
# Experiment 4: Ceiling estimation
# ============================================================
print("\n" + "=" * 70)
print("EXPERIMENT 4: Ceiling analysis")
print("=" * 70)

# Total Ghidra functions
total_ghidra = len(ghidra_funcs)
print(f"  Total Ghidra functions: {total_ghidra}")

# Phase A matched
phase_a_matched = len(enigma_funcs & ghidra_funcs)
print(f"  Phase A matched:        {phase_a_matched}")
print(f"  Phase A recall:         {phase_a_matched/total_ghidra*100:.2f}%")

# Remaining not in Enigma
remaining_not_in_enigma = [r for r in results if r['addr'] not in enigma_funcs]
print(f"  Remaining not in Phase A: {len(remaining_not_in_enigma)}")

# Recoverable with aggressive mode
# Only LOW+ candidates can be safely recovered (score >= 10)
recoverable_low = [r for r in remaining_not_in_enigma if r['score'] >= 10]
recoverable_high = [r for r in remaining_not_in_enigma if r['score'] >= 40]
recoverable_tiny = [r for r in remaining_not_in_enigma if r['score'] >= 10 and r['instr_count'] <= 4 and r['last_mnem'] in ('ret', 'retn')]

print(f"\n  LOW+ candidates (score >= 10):  {len(recoverable_low)}")
print(f"  MEDIUM+ candidates (score >= 40): {len(recoverable_high)}")
print(f"  TINY_HELPER in LOW+: {len(recoverable_tiny)}")

# Ceiling: Phase A + aggressive recovery
aggressive_recall = (phase_a_matched + len(recoverable_low)) / total_ghidra * 100
print(f"\n  Ceiling recall (Phase A + LOW+): {aggressive_recall:.2f}%")
print(f"  Ceiling gain: +{aggressive_recall - (phase_a_matched/total_ghidra*100):.2f}%")

# Only complete orphans (safe)
complete_orphans = [r for r in remaining_not_in_enigma if r['score'] >= 10 and r['last_mnem'] in ('ret', 'retn', 'int3')]
safe_recall = (phase_a_matched + len(complete_orphans)) / total_ghidra * 100
print(f"\n  Safe recall (Phase A + complete orphans only): {safe_recall:.2f}%")
print(f"  Safe gain: +{safe_recall - (phase_a_matched/total_ghidra*100):.2f}%")

# ============================================================
# Write results CSV
# ============================================================
fieldnames = ['addr', 'name', 'category', 'score', 'level', 'instr_count',
              'first_mnem', 'last_mnem', 'nearest_dist',
              'has_call_refs', 'has_data_refs', 'in_pdata', 'in_export',
              'in_vtable_run']
with open(OUT_CSV, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in sorted(results, key=lambda x: -x['score']):
        writer.writerow({k: r[k] for k in fieldnames})

print(f"\n" + "=" * 70)
print(f"Results written to: {OUT_CSV}")
print("=" * 70)

# ============================================================
# Experiment 5: Executable gap analysis (simplified)
# ============================================================
print("\n" + "=" * 70)
print("EXPERIMENT 5: Executable gap CALL target analysis")
print("=" * 70)

text_sec = sections.get('.text', {})
if text_sec:
    raw_data = read_raw_bytes(BINARY, image_base + text_sec['va'], min(text_sec['raw_size'], text_sec['vs']))
    text_start = image_base + text_sec['va']
    text_end = text_start + text_sec['vs']
    en_in_text = sorted(f for f in enigma_funcs if text_start <= f <= text_end)
    print(f"  .text: {text_start:x}-{text_end:x}, raw bytes: {len(raw_data)}, Enigma funcs: {len(en_in_text)}")

    # Count remaining 714 that are CALL targets in gaps
    call_tgts = set()
    for r in results:
        if r['addr'] not in enigma_funcs and r['score'] >= 10:
            # Check if this is near a gap boundary
            idx = next((i for i, f in enumerate(en_in_text) if f >= r['addr']), None)
            if idx is not None and idx > 0:
                prev = en_in_text[idx - 1]
                gap = r['addr'] - prev
                if gap <= 256:
                    call_tgts.add(r['addr'])
                    if gap <= 128:
                        pass  # Already covered by Phase A window
    
    gap_by_window = Counter()
    for r in results:
        if r['addr'] in call_tgts:
            idx = next((i for i, f in enumerate(en_in_text) if f >= r['addr']), None)
            if idx is not None and idx > 0:
                gap = r['addr'] - en_in_text[idx - 1]
                gap_by_window[gap] += 1
    
    print(f"  Remaining 714 functions within 256 bytes of prior Enigma function:")
    for threshold in [32, 64, 128, 256]:
        cnt = sum(1 for r in results if r['addr'] not in enigma_funcs and 
                  any(0 < r['addr'] - en_in_text[i-1] <= threshold 
                      for i in range(1, len(en_in_text)) if en_in_text[i-1] < r['addr'] <= en_in_text[i]))
        print(f"    Gap <= {threshold:3d}: {cnt}")
