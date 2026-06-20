#!/usr/bin/env python3
"""
forensic_714.py — Phase 1.5 Forensic Audit of remaining shell32 functions.
Read-only analysis. Does NOT modify any production code.
"""
import sys, io, struct, csv, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("capstone required: pip install capstone"); sys.exit(1)

BINARY = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\shell32_test.dll"
GHIDRA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\ghidra_shell32_test.csv"
ENIGMA_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\enigma_shell32.csv"
OUT_CSV = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build-cmake\remaining_714.csv"

def rw(f): return struct.unpack('<H', f.read(2))[0]
def rd(f): return struct.unpack('<I', f.read(4))[0]
def rq(f): return struct.unpack('<Q', f.read(8))[0]

def parse_pe(path):
    sections = {}; image_base = 0; pdata = []; export_addrs = set()
    data_dirs = [0]*16
    with open(path, 'rb') as f:
        f.seek(0x3C); e_lfanew = rd(f); f.seek(e_lfanew); assert f.read(4)==b'PE\x00\x00'
        f.read(2); ns = rw(f); f.read(12); opt_sz = rw(f); f.read(2)
        opt_start = f.tell(); magic = rw(f); is64 = magic==0x20b
        if is64: f.seek(opt_start+24); image_base = rq(f)
        else: f.seek(opt_start+28); image_base = rd(f)
        dd_off = opt_start+(112 if is64 else 96); f.seek(dd_off)
        for i in range(16): data_dirs[i]=rd(f); rd(f)
        f.seek(opt_start+opt_sz)
        for _ in range(ns):
            name = f.read(8).rstrip(b'\x00').decode('ascii',errors='ignore')
            vs=rd(f); va=rd(f); rs=rd(f); rp=rd(f); f.read(16)
            sections[name]={'va':va,'vs':vs,'raw_size':rs,'raw_ptr':rp}
        if '.pdata' in sections:
            ps=sections['.pdata']; f.seek(ps['raw_ptr'])
            for i in range(0,min(ps['raw_size'],ps['vs']),12):
                d=f.read(12); assert len(d)==12
                b,e,u=struct.unpack('<III',d)
                if b: pdata.append({'begin':image_base+b,'end':image_base+(e&0x7fffffff)})
        er=data_dirs[0]
        if er and sections:
            for sn,sc in sections.items():
                if not isinstance(sn,str): continue
                if sc['va']<=er<sc['va']+sc['vs']:
                    f.seek(sc['raw_ptr']+(er-sc['va'])); f.read(12)
                    rd(f); nr=rd(f); af=rd(f)
                    for sn2,sc2 in sections.items():
                        if not isinstance(sn2,str): continue
                        if sc2['va']<=af<sc2['va']+sc2['vs']:
                            f.seek(sc2['raw_ptr']+(af-sc2['va']))
                            for _ in range(nr):
                                fva=rd(f)
                                if fva: export_addrs.add(image_base+fva)
                            break
                    break
    return sections, image_base, pdata, export_addrs

def read_bytes(path, addr, size):
    s,ib,_,_ = parse_pe(path); rva=addr-ib
    with open(path,'rb') as f:
        for sn,sc in s.items():
            if not isinstance(sn,str): continue
            if sc['va']<=rva<sc['va']+sc['vs']:
                off=sc['raw_ptr']+(rva-sc['va'])
                if sc['raw_size']:
                    mx=sc['raw_ptr']+sc['raw_size']-off
                    if mx<=0: return b''
                    size=min(size,mx)
                f.seek(off); return f.read(size)
    return b''

def sec_of(addr, sections, ib):
    rva=addr-ib
    for n,s in sections.items():
        if not isinstance(n,str): continue
        if s['va']<=rva<s['va']+s['vs']: return n
    return '???'

def is_tfp(addr, ms):
    sm=sorted(ms)
    try: idx=sm.index(addr)
    except: return False
    for st in [16,32,48]:
        c=1; j=idx-1
        while j>=0 and sm[idx]-sm[j]==st*(idx-j): c+=1; j-=1
        j=idx+1
        while j<len(sm) and sm[j]-sm[idx]==st*(j-idx): c+=1; j+=1
        if c>=3: return True
    return False

def scan_text_calls(text_data, text_va, image_base, targets):
    found={}
    for off in range(len(text_data)-5):
        if text_data[off]==0xE8:
            rel=struct.unpack('<i',text_data[off+1:off+5])[0]
            src=image_base+text_va+off; tgt=src+5+rel
            if tgt in targets:
                found.setdefault(tgt,[]).append(off)
    return found

def scan_rdata_refs(rdata_data, rdata_va, image_base, targets):
    found={}
    for off in range(0,len(rdata_data)-8,8):
        ptr=struct.unpack('<Q',rdata_data[off:off+8])[0]
        if ptr in targets:
            found.setdefault(ptr,[]).append(off)
    return found

def outgoing_refs(insns):
    refs=set()
    for i in insns:
        try:
            for op in i.operands:
                if op.type==1:  # OP_IMM
                    refs.add(op.imm)
        except:
            pass
    return refs

def main():
    sections, ib, pdata, export_addrs = parse_pe(BINARY)
    print("=== FORENSIC AUDIT OF REMAINING 714 SHELL32 FUNCTIONS ===")
    print(f"ImageBase: 0x{ib:x}")

    gh = {}; gh_names = {}
    with open(GHIDRA_CSV) as f:
        next(f)
        for row in csv.reader(f):
            if not row: continue
            try: a=int(row[0].strip(),16); gh[a]=True; gh_names[a]=row[-1].strip()
            except: pass
    en = {}
    with open(ENIGMA_CSV) as f:
        for row in csv.reader(f):
            if not row: continue
            try: a=int(row[0].strip(),16); en[a]=row[1].strip()
            except: pass

    missing_raw=sorted(set(gh)-set(en))
    all_missing=set(missing_raw)
    adjusted=[a for a in missing_raw if not is_tfp(a,all_missing)]
    print(f"Ghidra: {len(gh)}  Enigma: {len(en)}")
    print(f"Raw missing: {len(missing_raw)}  Adjusted: {len(adjusted)}")

    tsec=sections['.text']; text_start=ib+tsec['va']; text_end=ib+tsec['va']+tsec['vs']
    with open(BINARY,'rb') as f: f.seek(tsec['raw_ptr']); text_data=f.read(min(tsec['raw_size'],tsec['vs']))
    rsec=sections['.rdata']
    with open(BINARY,'rb') as f: f.seek(rsec['raw_ptr']); rdata_data=f.read(min(rsec['raw_size'],rsec['vs']))

    adj_set=set(adjusted)
    text_calls=scan_text_calls(text_data,tsec['va'],ib,adj_set)
    rdata_refs=scan_rdata_refs(rdata_data,rsec['va'],ib,adj_set)
    pdata_begins=set(e['begin'] for e in pdata)

    md=Cs(CS_ARCH_X86,CS_MODE_64)
    rows=[]

    for addr in adjusted:
        name=gh_names.get(addr,"???")
        sec=sec_of(addr,sections,ib)
        raw=read_bytes(BINARY,addr,64)

        fb_type="valid_code"
        if not raw: fb_type="no_data"
        elif raw[0]==0x00: fb_type="zero_byte"
        elif raw[0]==0xCC: fb_type="int3"
        elif raw[0]==0xC3: fb_type="ret_opcode"
        elif raw[0]==0xE9: fb_type="jmp_opcode"
        elif raw[0]==0xEB: fb_type="short_jmp"

        insns=[]
        if raw and len(raw)>=1:
            try: insns=list(md.disasm(raw,addr,count=10))
            except: pass
        instr_count=len(insns)
        first_mnem=insns[0].mnemonic if insns else ""
        last_mnem=insns[-1].mnemonic if insns else ""

        # Check REX-prefix: if first byte is 0x48 or 0x4C etc.
        prefix_rex=raw[0] in (0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
                             0x4A,0x4B,0x4C,0x4D,0x4E,0x4F) if raw else False
        first_bytes=" ".join(f"{b:02x}" for b in raw[:16]) if raw else ""

        # Distances
        if en:
            nearest_enigma=min(en.keys(), key=lambda e:abs(addr-e))
            nearest_dist=abs(addr-nearest_enigma)
        else:
            nearest_enigma=0; nearest_dist=999999

        # Overlap: how many other missing Ghidra funcs are within 32 bytes
        nearby_missing=sum(1 for a in adjusted if a!=addr and abs(addr-a)<=32)

        in_call=len(text_calls.get(addr,[]))
        in_rdata=len(rdata_refs.get(addr,[]))
        in_pdata=1 if addr in pdata_begins else 0
        in_export=1 if addr in export_addrs else 0
        orefs=outgoing_refs(insns)

        # Vtable run detection
        in_vtable_run=0
        for off in range(0,len(rdata_data)-8,8):
            ptr=struct.unpack('<Q',rdata_data[off:off+8])[0]
            if ptr==addr:
                run_count=1
                j=off-8
                while j>=0:
                    p2=struct.unpack('<Q',rdata_data[j:j+8])[0]
                    if text_start<=p2<text_end: run_count+=1; j-=8
                    else: break
                j=off+8
                while j+8<=len(rdata_data):
                    p2=struct.unpack('<Q',rdata_data[j:j+8])[0]
                    if text_start<=p2<text_end: run_count+=1; j+=8
                    else: break
                if run_count>=3: in_vtable_run=1
                break

        # === CLASSIFICATION ===
        # A — VTABLE_DISPATCH
        if in_rdata>0 and (in_vtable_run>0 or in_call>0):
            pcat="VTABLE_DISPATCH"
        elif in_rdata>0:
            pcat="VTABLE_DISPATCH"
        # B — ADJUSTOR_THUNK
        elif instr_count>=2 and last_mnem in ('jmp',) and any(
            ins.mnemonic in ('add','sub','lea') for ins in insns[:2]):
            pcat="ADJUSTOR_THUNK"
        # C — TAILCALL_WRAPPER
        elif instr_count<=5 and last_mnem in ('jmp',):
            pcat="TAILCALL_WRAPPER"
        # D — TINY_HELPER (short, ends in ret, no refs)
        elif instr_count<=4 and last_mnem in ('ret','retn') and in_call==0 and in_rdata==0:
            pcat="TINY_HELPER"
        # E — GHIDRA_SPECULATIVE
        elif in_call==0 and in_rdata==0 and in_pdata==0 and in_export==0:
            if fb_type in ("zero_byte","int3","no_data","ret_opcode","short_jmp","jmp_opcode"):
                pcat="GHIDRA_SPECULATIVE"
            elif instr_count==0:
                pcat="GHIDRA_SPECULATIVE"
            elif instr_count<=2 and last_mnem not in ('ret','retn','jmp'):
                pcat="GHIDRA_SPECULATIVE"
            elif instr_count==1 and first_mnem in ('nop','int3','ud2'):
                pcat="GHIDRA_SPECULATIVE"
            else:
                pcat="GHIDRA_SPECULATIVE"
        # F — OVERLAP_CONFLICT
        elif nearest_dist<=8:
            pcat="OVERLAP_CONFLICT"
        # G — TRULY_UNEXPLAINED
        else:
            pcat="TRULY_UNEXPLAINED"

        rows.append({
            'addr':addr,'name':name,'section':sec,
            'first_bytes':first_bytes,'instr_count':instr_count,
            'first_mnem':first_mnem,'last_mnem':last_mnem,
            'nearest_enigma':nearest_enigma,'nearest_dist':nearest_dist,
            'nearby_missing':nearby_missing,
            'in_call_refs':in_call,'in_rdata_refs':in_rdata,
            'in_pdata':in_pdata,'in_export':in_export,
            'outgoing_refs':len(orefs),
            'in_vtable_run':in_vtable_run,
            'category':pcat
        })

    # Write CSV
    fields=['addr','name','section','first_bytes','instr_count','first_mnem','last_mnem',
            'nearest_enigma','nearest_dist','nearby_missing',
            'in_call_refs','in_rdata_refs','in_pdata','in_export',
            'outgoing_refs','in_vtable_run','category']
    with open(OUT_CSV,'w',newline='') as f:
        w=csv.writer(f); w.writerow(fields)
        for r in rows:
            w.writerow([r[f] for f in fields])
    print(f"Wrote {OUT_CSV} ({len(rows)} rows)")

    # Summary
    cats=Counter(r['category'] for r in rows)
    print(f"\n{'Category':<25s} {'Count':>6s} {'%':>8s}")
    print("-"*41)
    for c,n in sorted(cats.items(),key=lambda x:-x[1]):
        print(f"{c:<25s} {n:>6d} {n*100/len(rows):>7.1f}%")
    print("-"*41)
    print(f"{'TOTAL':<25s} {len(rows):>6d} {100.0:>7.1f}%")

    # Three examples per category
    seen=set()
    print(f"\n{'='*70}\nTHREE EXAMPLES PER CATEGORY\n{'='*70}")
    for r in rows:
        if r['category'] not in seen:
            seen.add(r['category'])
            print(f"\n--- {r['category']} ---")
            exs=[x for x in rows if x['category']==r['category']][:3]
            for x in exs:
                print(f"  Addr: 0x{x['addr']:x} {x['name']}")
                print(f"  Sec: {x['section']}  Instr: {x['instr_count']}  First: {x['first_mnem']}  Last: {x['last_mnem']}")
                print(f"  First bytes: {x['first_bytes']}")
                print(f"  Nearest Enigma: 0x{x['nearest_enigma']:x} (dist={x['nearest_dist']})")
                print(f"  Near missing: {x['nearby_missing']}")
                print(f"  Ref: CALL={x['in_call_refs']} RDATA={x['in_rdata_refs']} PDATA={x['in_pdata']} EXP={x['in_export']}")
                print(f"  Vtable run: {x['in_vtable_run']}  Outgoing: {x['outgoing_refs']}")
                print()

    # Overlap analysis
    overlaps=[r for r in rows if r['category']=='OVERLAP_CONFLICT']
    print(f"{'='*70}\nOVERLAP ANALYSIS\n{'='*70}")
    print(f"Overlap count: {len(overlaps)} ({len(overlaps)*100/len(rows):.1f}% of 714)")
    if overlaps:
        avg=sum(r['nearest_dist'] for r in overlaps)/len(overlaps)
        print(f"Average distance to Enigma entry: {avg:.1f} bytes")
        for r in overlaps[:5]:
            efunc=en.get(r['nearest_enigma'],'?')
            print(f"  0x{r['addr']:x} -> Enigma 0x{r['nearest_enigma']:x} ({efunc}) dist={r['nearest_dist']}")
        if len(overlaps)>5: print(f"  ... and {len(overlaps)-5} more")

    # Speculation analysis
    spec=[r for r in rows if r['category']=='GHIDRA_SPECULATIVE']
    print(f"\n{'='*70}\nSPECULATION ANALYSIS\n{'='*70}")
    print(f"Ghidra speculative count: {len(spec)} ({len(spec)*100/len(rows):.1f}% of 714)")
    safe=0; risky=0; unacceptable=0
    for r in spec:
        fb=r['first_bytes']
        if fb.startswith("00") or fb.startswith("cc ") or fb.startswith("cc "):
            unacceptable+=1
        elif r['instr_count']==0:
            unacceptable+=1
        elif r['instr_count']<=2:
            risky+=1
        else:
            safe+=1
    # Refined: check by actual first byte
    safe=0; risky=0; unacceptable=0
    for r in spec:
        raw=read_bytes(BINARY,r['addr'],1)
        if not raw or raw[0]==0x00:
            unacceptable+=1
        elif raw[0]==0xCC:
            unacceptable+=1
        elif r['instr_count']==0:
            unacceptable+=1
        elif r['instr_count']<=2:
            risky+=1
        else:
            safe+=1
    print(f"  SAFE: {safe} (valid code, no refs — would be recovered if referenced)")
    print(f"  RISKY: {risky} (valid but very short — speculative recovery risk)")
    print(f"  UNACCEPTABLE: {unacceptable} (data or padding — Ghidra likely wrong)")

    # Recoverability
    print(f"\n{'='*70}\nRECOVERABILITY ANALYSIS\n{'='*70}")
    # We know which categories have which degree of determinism
    vtable_count=sum(1 for r in rows if r['category']=='VTABLE_DISPATCH' and r['in_rdata_refs']>0)
    only_rdata_no_call=sum(1 for r in rows if r['category']=='VTABLE_DISPATCH' and r['in_call_refs']==0 and r['in_rdata_refs']>0)
    est_gain=only_rdata_no_call  # these are VTABLE_DISPATCH with only .rdata refs
    print(f"  VTABLE_DISPATCH (total: {cats.get('VTABLE_DISPATCH',0)}):")
    print(f"    Have .rdata refs: {vtable_count}")
    print(f"    No CALL refs (data-pointer only): ~{only_rdata_no_call}")
    print(f"    Estimated recovery: {max(0, min(only_rdata_no_call, vtable_count))}")
    risky_count=sum(1 for r in rows if r['category']=='TAILCALL_WRAPPER' or r['category']=='ADJUSTOR_THUNK')
    print(f"  ADJUSTOR_THUNK + TAILCALL_WRAPPER: {cats.get('ADJUSTOR_THUNK',0)+cats.get('TAILCALL_WRAPPER',0)}")
    print(f"  Estimated recovery (with ref-based relax): {risky_count//2}")
    print(f"  TINY_HELPER: {cats.get('TINY_HELPER',0)} — not recoverable (no refs)")

    # Theoretical ceiling
    current_match=30212; current_total=30993
    spec_unacceptable=unacceptable
    everything_else=len(rows)-spec_unacceptable
    print(f"\n{'='*70}\nTHEORETICAL CEILING\n{'='*70}")
    print(f"  Current matching:            {current_match:>5d}/{current_total} = {current_match/current_total*100:.1f}%")
    print(f"  Deterministic ceiling:       {current_match+only_rdata_no_call:>5d}/{current_total} = {(current_match+only_rdata_no_call)/current_total*100:.1f}%")
    print(f"  Low-risk heuristic:          {current_match+only_rdata_no_call+risky_count//2:>5d}/{current_total} = {(current_match+only_rdata_no_call+risky_count//2)/current_total*100:.1f}%")
    print(f"  Absolute ceiling (no spec):  {current_match+everything_else:>5d}/{current_total} = {(current_match+everything_else)/current_total*100:.1f}%")
    print(f"  Genuine Ghidra speculations: {spec_unacceptable} ({spec_unacceptable/current_total*100:.1f}% of Ghidra ref)")

if __name__=='__main__':
    main()
