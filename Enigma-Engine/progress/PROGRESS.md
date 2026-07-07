# Enigma Engine Progress

Single-line-per-event changelog of significant changes.

## 2026-07-07 — Automatic Naming Convention Overhaul

- `AutoNaming.h` created — central `name(prefix, addr)` / `nameVal(prefix, val)` formatter
- `SymbolUtilities.{h,cpp}`: prefixes updated — `FUN_`→`func_`, `DAT_`→`data_`, `LAB_`→`label_`, `SUB_`→`func_`, `UNK_`→`unk_`, `EXT_`→`ext_`, `OFF_`→`off_`, `Ordinal_`→`ord_`
- `FunctionManager.cpp`, `DecompInterface.cpp`: `FUN_` → `func_`, `FUN_ENTRY` → `entry`
- 12 discovery/analyzer files: all `sub_`, `func_start_`, `func_call_`, `func_gap_`, `func_data_`, `func_sweep_`, `thunk_`, `data_func_`, `exception_func_` unified to `func_0xADDR` / `thunk_0xADDR`
- `database.cc::buildVariableName`: 7 naming paths rewritten — `unaff_0x`, `local_0x`, `ptr_0x`, `arg_`, `param_`, `out_`, `v_`
- `varmap.cc::ScopeLocal::buildVariableName`: `auStack_`/`uStack_` → `local_0x`
- `printc.cc` (4 functions): `RAM0x...`→`ptr_0x...`, `code_r0x...`→`code_0x...`, `Ram0x...`→`ptr_0x...`, `function_`→`func_`
- `enigma_decompile_full.cpp`: removed `FUN_ENTRY`→`entry` post-processing
- `AnalysisBridge.cpp`, `FidAnalyzer.cpp`, `MainRecognitionAnalyzer.cpp`: prefix checks updated
- `tests/test_compile.cpp`: 14 W74.SymUtil prefix expectations updated
- `tests/test_batch_x.cpp`: `"FUN_"` → `"func_0x"`
- `tests/test_cli_regression.py`: 9 regex patterns updated
- `tests/corpus/expected/*.c`: all 16 regenerated — output sizes dropped ~10%
- All 52/52 tests pass (100%)

## 2026-07-?? — Noise-Reduction Phase

- `DataSectionFunctionScannerAnalyzer.cpp`: `isAtFunctionBoundary()` accepts only `0xCC`/`0xC3`/`0xE9`/`0xEB`; `isPlausibleFunctionPrologue()` rejects `0x00`/`0xFF`/`0xCC`; Phase 2 .rdata scan capped at `MAX_FOUND`
- `FunctionStartDataPostAnalyzer.cpp`: first-byte + boundary validation for data-ref functions
- `FunctionStartAnalyzer.cpp`: multi-byte NOP (`0F 1F`) and REX-prefix XOR-zero (`45 33 C0/C9/D2/DB`) rejection
- Results: kernel32 extras 993→495, ntdll 2143→1614, user32 725→697; `func_data` extras ≤1.4% of all extras
- `AggressiveRecoveryAnalyzer.cpp` inspected — .pdata scoring is hint-only, no action needed

## Earlier

- Stress-test pipeline: all 10 system DLLs audited (function/instruction counts, timing, peak memory)
- 4 .pdata ordering/splitting fixes in `FunctionStartAnalyzer.cpp`
- Ghidra comparison baseline established for kernel32, ntdll, user32
- Tooling: `classify_extras.py`, `investigate_missing.py`, `compare_function_lists.py`, `check_pdata.py`, `phase4_sampling.py`, `phase5_funcstart.py`, `phase5c_preceding.py`
- TypeDatabase: abstract base + WindowsTypeDatabase (~3200 signatures across 20+ DLL sections) + Linux/MacOS stubs + factory
- Call-site type annotation in `enigma_decompile_full.cpp` (notepad 53 types, shell32 298 types)
- Project cleanup: removed `tmp/`, `root build/`, `duplicate include/`, `builds/` (1.28 GB), temp files, logs, CSVs, `.bak` backups
- ADS dock layout: Explorer/Disassembly/Decompiler/Hex/Console; FetchContent + static build
- Full-window proportional drop zones (25% per edge, center tabs); compass arrows hidden; drag threshold 4×
- View menu toggles for Disassembly/Decompiler/Hex with sync on close
- Console: title bar hidden via `HideSingleWidgetTitleBar`
- Explorer tree: A-Z sort, address column monospace, tooltips, filter box
- `CutterSeekable` navigation sync: HexView/DisassemblyView/DecompilerView all implement seek/click/highlight
- `seekAll()` hub in MainWindow with history (navigateTo/onNavigateBack)
