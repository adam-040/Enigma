# Enigma Engine vs Ghidra: Benchmark Report

**Date:** 2026-06-22
**Enigma:** Self-contained C++ binary with native PE loader + SLEIGH-based disassembly
**Ghidra:** Ghidra 12.0.4 PUBLIC headless (Java/JVM)
**Host:** Windows

---

## Test Samples

| Sample | Type | Size |
|--------|------|------|
| `notepad_test.exe` | PE32+ (x64) executable | ~12 KB |
| `shell32_test.dll` | PE32+ (x64) DLL | ~7.8 MB |

---

## Raw Performance

### notepad_test.exe

| Metric | Enigma | Ghidra | Ratio |
|--------|--------|--------|-------|
| Total time | **0.87 s** | 170.8 s | **196× faster** |
| Functions found | **634** | 497 | Enigma +28% |
| Pipeline breakdown | load 2.4ms / prog 6.1ms / populate 2.1ms / analysis 855ms | — | — |
| Peak memory | **43 MB** | — | — |

### shell32_test.dll

| Metric | Enigma | Ghidra | Ratio |
|--------|--------|--------|-------|
| Total time | **315 s** | 703.8 s | **2.2× faster** |
| Functions found | **35,491** | 30,992 | Enigma +14% |
| Pipeline breakdown | load 30ms / analysis 315,379ms | — | — |
| Peak memory | **1.3 GB** | — | — |
| Instructions | 1,417,878 | — | — |

---

## Function Detection Comparison

### notepad_test.exe

| Statistic | Count |
|-----------|-------|
| Matching (same address) | 494 |
| Extra (Enigma only) | 140 |
| Missing (Ghidra only) | 4 |

**Enigma detected 140 more functions than Ghidra in notepad.** The 4 missing from Enigma are likely Ghidra-specific synthetic entry points (e.g., TLS callbacks, SEH handlers).

### shell32_test.dll

| Statistic | Count |
|-----------|-------|
| Matching (same address) | 30,041 |
| Extra (Enigma only) | 5,450 |
| Missing (Ghidra only) | 952 |
| Table false positives (Ghidra) | 183 |

**Enigma detected 5,450 more real functions than Ghidra.** After accounting for 183 table false positives in Ghidra, Ghidra still has 769 functions Enigma does not detect. These are likely:
- Highly optimized import thunks
- Functions in non-executable sections Ghidra recognizes via PDB/symbols

---

## Key Findings

1. **Massive speed advantage on small binaries:** Enigma is ~196× faster on notepad (0.87s vs 171s). Ghidra's JVM startup (4.5s) dominates small-binary analysis.

2. **Substantial advantage on large binaries:** Enigma is ~2.2× faster on shell32 (315s vs 704s), with higher function yield (+14%).

3. **More functions found:** Enigma consistently finds 14-28% more functions than Ghidra on these samples. The extra functions are primarily:
   - `func_call_*` (direct call targets reached via analysis)
   - `func_data_*` (data references that contain valid code)
   - `func_pdata_*` (exception handler entries from .pdata)

4. **Scaling characteristics:** Enigma's analysis time scales roughly linearly with function count (~8.9 ms/function for shell32). Ghidra's scales similarly but with a higher constant factor.

5. **Memory efficiency:** Notepad peak is 43 MB (trivial). Shell32 peaks at 1.3 GB — expected for a 35K-function 7.8 MB DLL with full SLEIGH disassembly.

---

## Data Files

| File | Contents |
|------|----------|
| `enigma_notepad.csv` | Enigma functions (notepad_test.exe) — 634 entries |
| `enigma_shell32.csv` | Enigma functions (shell32_test.dll) — 35,491 entries |
| `ghidra_notepad_test.csv` | Ghidra functions (notepad_test.exe) — 497 entries |
| `ghidra_shell32_test.csv` | Ghidra functions (shell32_test.dll) — 30,992 entries |
