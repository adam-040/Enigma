# Phase 4 — Stratified Sample Validation Summary

**Binary:** kernel32.dll  
**Samples:** 25 (5 per category)  
**Method:** Capstone x86-64 disassembly with Ghidra cross-reference

## Results by Category

### func_pdata (5 samples) — ALL VALID
- 5/5 backed by `.pdata` table entries
- No RET instructions (tail-call via JMP to other functions)
- Pattern: `mov ecx/edx/r8d, X` → `call` → `nop`/`int3` → `jmp target`
- **Verdict:** Legitimate functions. Ghidra merges them into larger containing functions for its UI — Enigma's split is correct and more precise.

### func_data (5 samples) — 1 VALID, 4 FALSE POSITIVES
- 0x180060C01: Has `add rsp,0x28 / ret / int3...` — genuine function
- 0x180004558: Ends with `.byte 0x0f` (Capstone decode failure) — data-in-.text at 0x180004645
- 0x1800056E8: Ends with `.byte 0x0f` — data-in-.text at 0x180005760
- 0x180050008: Single `.byte 0x1e` — clearly not code
- 0x180060F09: Similar decode failure
- **Verdict:** Most are data bytes misidentified as code. ~20% genuine.

### func_jmp (5 samples) — ALL VALID
- All are `e9 xx xx xx xx / cc` (JMP rel32 + INT3)
- These are hot-patch thunks / export forwards from kernel32 to kernelbase
- Pattern: 5-byte JMP at entry, zero callers (direct export)
- **Verdict:** Legitimate thunk functions. Ghidra doesn't split these.

### func_call (5 samples) — ALL VALID
- All have CALL references (by construction) 
- All contain RET + INT3 padding — proper function structure
- Sizes 8-356 bytes, average ~40 instructions
- **Verdict:** Genuine functions. Ghidra merges them into larger parent bodies.

### func_start (5 samples) — 4 VALID, 1 MARGINAL
- 0x1800767A6: `xor eax,eax / ret / int3...` — classic nullsub (valid)
- 0x1800182D1: `push rbp / mov rbp,rsp / ... / ret` — full prologue/epilogue (valid)
- 0x18006014B: `xor eax,eax / int3 / ...` — 12 instructions ending in int3 (valid)
- 0x18004CCF1: `xor eax,eax / int3` pad — no RET, likely a coincidental XOR pattern match
- 0x1800075ED: 18 instructions ending in int3, has RET (valid)
- **Verdict:** Mostly valid. XOR-pattern start detection may catch some non-code.

## Overall
- **72% genuine functions** (18/25 — pdata, jmp, call, most start)
- **28% false positives** (7/25 — mostly func_data)
- All pdata/jmp/call samples are legitimate code positions
- func_data is the main FP category (~80% data, not code)
- func_start has ~20% FP rate (XOR pattern coincidences)

## Report
Full HTML report with per-function disassembly:  
`Enigma-Engine/test_binaries/phase4_report.html`
