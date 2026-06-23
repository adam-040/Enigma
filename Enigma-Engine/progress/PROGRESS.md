# Noise-Reduction Progress

## Objective
Eliminate false-positive function entries in Enigma Engine's function detection pipeline, validated against Ghidra on real Windows system binaries.

## Fixes

| # | Fix | File(s) | Impact |
|---|-----|---------|--------|
| A | `isAtFunctionBoundary()` accepts only terminator bytes (`0xCC`/`0xC3`/`0xE9`/`0xEB`) | `DataSectionFunctionScannerAnalyzer.cpp` | Eliminated bulk of `func_data` false positives from alignment NOPs and zero-padding |
| B | `isPlausibleFunctionPrologue()` rejects `0x00`/`0xFF`/`0xCC` | `DataSectionFunctionScannerAnalyzer.cpp` | Blocks non-instruction bytes from being treated as function starts |
| C | Phase 2 `.rdata` scan capped at `MAX_FOUND` | `DataSectionFunctionScannerAnalyzer.cpp` | Prevents COM/C++ vtable over-scan |
| D | First-byte + boundary validation | `FunctionStartDataPostAnalyzer.cpp` | Prevents data-ref functions at invalid addresses |
| E | Multi-byte NOP (`0F 1F`) rejection | `DataSectionFunctionScannerAnalyzer.cpp`, `FunctionStartDataPostAnalyzer.cpp` | 95% of ntdll `func_data` were alignment NOPs |
| F | REX-prefix XOR-zero rejection (`45 33 ...`) | `FunctionStartAnalyzer.cpp` | Mid-instruction XOR matches in multi-instr prologue detector |

## Results

| Binary | Before | After | Reduction |
|--------|--------|-------|-----------|
| kernel32 | 3,584 funcs | **2,814** | −770 |
| ntdll | 6,447 funcs | **5,918** | −529 |
| user32 | 3,076 funcs | **3,048** | −28 |

### Extras vs Ghidra

| Binary | Extras | func_data | func_start | func_pdata |
|--------|--------|-----------|------------|------------|
| kernel32 | 495 | **3 (0.6%)** | 51 (10%) | 316 (64%) |
| ntdll | 1,614 | **22 (1.4%)** | 161 (10%) | 1,172 (73%) |
| user32 | 697 | **5 (0.7%)** | 78 (11%) | 476 (68%) |

Noise category (`func_data`) reduced from ~50% of extras to ≤1.4%.
