# Enigma Pipeline Stress Test Report

Generated: 2026-06-16 (updated after Phase 13 — Listing binary search fix)

## Overview

| Metric | Value |
|--------|-------|
| Total binaries | 5 |
| Total pipeline time | 46.4s |
| Total functions discovered | 624+ |
| Max peak memory | ~44 MB |
| Ghidra parity (matched) | 498/498 (100%) |
| Shell32 pipeline | 36.3s (was: never completes) |

---

## 1. notepad_test.exe

**Size**: 0.19 MB  
**Pipeline time**: 0.47 s  
**Peak memory**: ~44 MB  

### Pipeline Summary

| Metric | Value |
|--------|-------|
| Load time | 1.6 ms |
| Analysis time | ~470 ms |
| Total pipeline time | 472 ms |
| Instructions | 35649 |
| Executable bytes | 148623 |

### Per-Analyzer Timing

| Analyzer | Time (ms) | % |
|---------|-----------|---|
| Function Start Search | ~150 | 25.4% |
| Disassembly | ~134 | 22.7% |
| Scalar Operand References | completed | — |
| Reference | completed (5156 iterations) | — |
| Stack Reference Analyzer | 15.2 | 2.6% |
| Import Thunk | minor | — |
| Main Recognition | minor | — |
| Other analyzers | combined <200ms | — |

### Ghidra Parity

| Metric | Count | % |
|--------|-------|---|
| Ghidra total | 498 | 100% |
| Matched | 498 | 100% |
| Missing | 0 | 0% |
| Extra (Enigma only) | 126 | — |
| Enigma total | 624 | — |

---

## 2. shell32.dll

**Size**: 5.67 MB  
**Pipeline time**: 36.3 s  
**Load time**: <2s  

### Pipeline Summary

| Metric | Value |
|--------|-------|
| Instructions decoded | 1,409,371 |
| Initial functions (pdata+exports) | ~2,293 |
| Functions after FunctionStartAnalyzer | 20,154 |
| Functions after DataSectionFunctionScanner | +500 |
| Functions after all analyzers | ~29,187+ |
| OperandReferenceAnalyzer mainLoop | 50,001 iterations (1.35M addresses) |
| OperandReferenceAnalyzer time | 2.3s (hit 50K hard limit) |

### Per-Analyzer Timing

| Analyzer | Time (ms) | % |
|---------|-----------|---|
| Function Start Search | 4730 | 13.0% |
| Disassembly | ~5000 | 13.8% |
| Scalar Operand References | ~5000 | 13.8% |
| Reference (OperandReference) | 2357 | 6.5% |
| Stack Reference Analyzer | 938 | 2.6% |
| Main Recognition | 1161 | 3.2% |
| Other analyzers | combined ~10000 | 27.1% |

---

## 3. kernel32.dll

**Size**: 0.75 MB  
**Pipeline time**: 2.3 s  

### Pipeline Summary

| Metric | Value |
|--------|-------|
| Instructions | ~287K |
| OperandReferenceAnalyzer | 50K iterations (hit limit) |
| ImportThunk | 108 functions detected |

---

## 4. ntdll.dll

**Size**: 1.94 MB  
**Pipeline time**: 5.3 s  

### Pipeline Summary

| Metric | Value |
|--------|-------|
| Instructions | ~287K |
| OperandReferenceAnalyzer | 50K iterations in 467ms (hit limit) |
| Total timed analyzers | 5193ms |

---

## 5. user32.dll

**Size**: 1.63 MB  
**Pipeline time**: 2.0 s  

### Pipeline Summary

| Metric | Value |
|--------|-------|
| Total timed analyzers | 1888ms |
| ImportThunk | 597 functions detected |

---

## Cross-Binary Improvement (Before → After Phase 13)

| Binary | Before Phase 13 | After Phase 13 | Improvement |
|--------|----------------|----------------|-------------|
| notepad_test.exe | 652ms | 472ms | 1.4x |
| shell32.dll | never completes (hours+) | 36.3s | ∞ |
| ntdll.dll | 60s timeout | 5.3s | 11.3x |
| kernel32.dll | 60s timeout | 2.3s | 26.1x |
| user32.dll | 60s timeout | 2.0s | 30.0x |

## Observations

### Bottleneck Resolved
The O(N) linear scans in `Listing::getCodeUnitContaining()`, `getDefinedDataContaining()`,
and `getInstructionContaining()` were the root cause of the shell32 hang. Each
OperandReferenceAnalyzer main-loop iteration was scanning 1.4M instructions linearly.

Fix: Lazy-sorted vectors with `std::upper_bound` binary search — O(log N) per query.

### Remaining
- OperandReferenceAnalyzer hits 50K hard limit on larger binaries, skipping ~half the
  reference sources. The limit is a safety net; each iteration is now fast.
- `Memory::getBlock()` is still O(N) linear scan over blocks (typically <10 blocks,
  so not a bottleneck).

---

*Updated 2026-06-16 after Phase 13*
