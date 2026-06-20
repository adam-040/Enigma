# AGENTS.md

Compact guidance for OpenCode sessions working in this repository.

## What this project is

Enigma Engine is a Java-free, Ghidra-compatible C++17 decompiler/RE framework
with a Qt Widgets desktop GUI. Three parallel paths live in `Enigma-Engine/`:

- **Official product (first version)**: `enigma_decompile_full` — wraps the
  original Ghidra C++ decompiler under `Enigma-Engine/decompiler/` (built as the
  `decompiler` static lib, namespace `ghidra_decompiler`) and adds PE/ELF/Mach-O
  auto-detection, SLEIGH-driven disassembly, and `PrintC` output.
- **Experimental / supporting**: the Enigma-native pipeline in
  `src/pcode/EnigmaPipeline.cpp` + `src/pcode/PcodeCapstoneMapper.cpp` +
  `src/core/Disassembler.cpp`. Uses Capstone for disassembly and a hand-written
  mnemonic→pcode mapper (x86/ARM/MIPS/PPC only).
- **Qt6 GUI**: `enigma_gui` target in `src/gui/` uses
  Qt-Advanced-Docking-System (ADS) for a multi-pane workspace with
  Disassembly, Decompiler, Hex, and Explorer views. Navigation sync via
  `CutterSeekable` interface — all views highlight/scroll to the same
  address on seek.

> **No-AI constraint**: do not introduce AI/LLM features until the official
> first-version decompiler fully matches the C++ Ghidra behavior. See
> `Enigma-Engine/PLAN/PROGRESS.md` for current phase status.

## Layout (high signal only)

```
Enigma-Engine/
  include/ghidra/    public C++ headers (namespace ghidra)
  src/               implementation (subdirs: core, gui, pcode, types, ...)
  src/gui/           Qt6 GUI views — MainWindow, HexView, DisassemblyView, DecompilerView, ConsoleWidget, FunctionExplorer
  decompiler/        original Ghidra C++ decompiler (read-only reference base)
  sleigh/            compiled .sla specs (resolved via ENIGMA_SLEIGH_DIR)
  tests/             41 CTest suites (custom TEST macro, no GTest)
  tools/             enigma_decompile.cpp, enigma_decompile_full.cpp
  PLAN/              PROGRESS.md, RULES.md, DEPENDENCY_BLOCKERS.md, ...
  CMakeLists.txt     single root, GLOB_RECURSE for src/ and include/ghidra/
```

`ghidra-source code/` (workspace root) is **read-only** Java reference for
porting; do not modify.

## Build & test

Working dir for all commands: `Enigma-Engine/`.

- Configure (one time, or after CMakeLists changes):
  `cmake -S . -B build-cmake -G Ninja`
- Build everything: `cmake --build build-cmake`
- Build a single target: `cmake --build build-cmake --target enigma_engine`
  (or `enigma_gui`, `enigma_test_pipeline`, `enigma_decompile_full`, ...)
- Run all tests: `cd build-cmake && ctest --output-on-failure`
- Run one suite: `ctest -R enigma_test_pipeline --output-on-failure`
- Run the CLI directly:
  `build-cmake/enigma_decompile_full.exe -h`
  `build-cmake/enigma_decompile_full.exe -base 1000 -entry 1000 ../simple.bin`

Both `build/` and `build-cmake/` may exist. The CLI regression test
(`tests/test_cli_regression.py`) checks `build/` first, then `build-cmake/`.
Standardize on `build-cmake/` (Ninja) unless you have a reason otherwise.

**Add a new source file**: just drop it under `src/` or `include/ghidra/`. The
root `CMakeLists.txt` uses `file(GLOB_RECURSE ... CONFIGURE_DEPENDS)` so
Ninja auto-detects new files on the next build — do not edit `CMakeLists.txt`
just to register files.

## Required toolchain

CMake >= 3.16, Ninja (for backend) or MSYS Makefiles (for GUI), MinGW64 g++
(15.2.0), MSYS2. CMake `find_*` calls in `CMakeLists.txt` look under
`$ENV{MSYSTEM_PREFIX}` (set by MSYS2) and `MSYS2_MINGW64_ROOT`. If you see
`FATAL_ERROR: Capstone was not found`, set the env var or pass
`-DMSYS2_MINGW64_ROOT=/path/to/msys64/mingw64`.

Required libs: **Capstone** (disassembly), **LMDB** (index cache),
**zlib** (linked transitively by the decompiler), **Python3** (CLI regression),
**Qt6** (Widgets, Core, Gui — `mingw-w64-x86_64-qt6-base` via pacman).
**Qt-Advanced-Docking-System** (ADS) v4.5.0 fetched automatically from GitHub
via CMake FetchContent (`BUILD_STATIC=ON`, `BUILD_EXAMPLES=OFF`).

## Test framework (no GTest)

Each test file has its own:

```cpp
static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)
// ... main returns (passed == total) ? 0 : 1;
```

The 41 registered CTest suites (see `CMakeLists.txt` for the full list).

## Code usage — main path vs. test-only

The main decompilation tool (`enigma_decompile_full.cpp`) uses the original
`ghidra_decompiler::Architecture` from `decompiler/architecture.hh` directly
(via `SleighArchitecture` → `RawBinaryArchitecture` → `SimpleBinaryArch`).

The following `include/ghidra/*.h` + `src/**/*.cpp` files are **standalone
wrappers used only by test suites or the experimental native pipeline
(enigma_decompile.cpp)**. They are NOT wired into the main decompilation path:

```
include/ghidra/Architecture.h    src/pcode/Architecture.cpp   # test_compile.cpp only
include/ghidra/Sleigh.h          src/pcode/Sleigh.cpp         # test_compile + pipeline tests
include/ghidra/Sleigh*.h         src/pcode/Sleigh*.cpp        # various SLEIGH wrappers
src/types/*.cpp                                               # 250+ type wrappers (test-only)
src/core/*Analyzer.cpp                                        # 132 analyzers (test-only)
src/storage/*                                                 # 5 storage phases (test-only)
src/symbol/*, src/program/*, src/listing/*                    # model wrappers (test-only)
```

Do not import these files into tool code — always use `ghidra_decompiler::`
classes from `decompiler/*.hh` instead.

## Where to make changes

### CLI flags (enigma_decompile_full)
- `-max-func <N>` — Limit total decompiled functions (default: 20, was unlimited).
- `-no-crt` — Disable CRT/library function boundary filtering. By default, known
  CRT functions (prefixes: `__mingw_`, `__do_global_`, `__gcc_`, `_Unwind_`,
  `__security_`, `_pei386_`, etc.) are decompiled for callee discovery but their
  bodies are not output. Use `-no-crt` to see all functions.
- `-base`, `-entry`, `-o`, `-time` — Standard flags (see `-h` for full list).

### Output improvements (all in `tools/enigma_decompile_full.cpp`)
1. **Warning suppression**: `/* WARNING: ... */` comments are stripped from output.
2. **CRT boundary**: BFS decompiles known CRT functions for one-level callee
   discovery but excludes them from output and maxFuncs counting.
3. **Main recognition**: Non-CRT functions discovered through CRT boundary are
   candidates for renaming to `main()`.
4. **String content**: `(char *)0xHEX` patterns are resolved to C string literals.
5. **Thunk cleanup**: Import thunks (single-call wrappers) removed from output.
6. **`_` globals warning**: "Globals starting with '_' overlap..." stripped.

- **v0.1-backend frozen**: No breaking API changes without justification. New features go in tool layer or as optional extensions — don't change public header signatures in `include/ghidra/*.h` without review. See `PLAN/PROGRESS.md` for the full closure checklist.
- **New Ghidra class port**: read the original Java in `ghidra-source code/`
  and the matching `.cc`/`.hh` in `Enigma-Engine/decompiler/`, then mirror it
  under `include/ghidra/*.h` + `src/.../*.cpp`. One class = one header + one
  source. Wrap everything in `namespace ghidra {}`. Use `#pragma once`.
  Java→C++ translation conventions (ownership, exceptions, collections) are
  documented in `Enigma-Engine/PLAN/RULES.md`.
- **New data type**: header in `include/ghidra/*DataType.h`, impl in
  `src/types/*DataType.cpp`. The `PcodeOp` opcodes are defined in
  `include/ghidra/PcodeOp.h` as `static constexpr int` (e.g. `INT_2COMP`,
  `INT_NEGATE`, `INT_XOR`, `INT_SDIV` — easy to guess wrong).
- **New pcode instruction mapping**: add to `buildX86Handlers()` /
  `buildARMHandlers()` / `buildMIPSHandlers()` / `buildPPCHandlers()` in
  `src/pcode/PcodeCapstoneMapper.cpp`. Memory operands must be detected
  via `isMemoryOperand(string)` which only checks for `[`. `mapStore` already
  picks the correct address vs value based on which operand has `[`.
- **New analyzer**: register it the same way as the 132 existing ones in
  `src/core/`. Check `PLAN/DEPENDENCY_BLOCKERS.md` first — many analyzers
  are blocked on missing infrastructure (DWARF, DecompInterface,
  DataTypeArchive, etc.) and cannot be completed without porting those.
- **Update status**: edit `Enigma-Engine/PLAN/PROGRESS.md` after any meaningful
  change set. It is the single source of truth for what is done / next.

## GUI architecture

```
src/gui/               Qt6 views + main window
src/include/gui/       GUI interfaces (CutterSeekable.h)
CMakeLists.txt         enigma_gui target (FetchContent ADS, link Qt6::Widgets + ads::qtadvanceddocking-qt6)
```

### Widget hierarchy
- **MainWindow** (QMainWindow): owns `ads::CDockManager`, menu bar, toggle actions, seek hub, and the shared `SelectionManager`
  - **Explorer** (FunctionExplorer, Left dock): QTreeView with bold categories, monospace addresses, filter + clear
- **DisassemblyFieldView** (Center dock): custom `QAbstractScrollArea` (`FieldView` subclass) with cell-grid rendering, token-model syntax coloring, glyph-height blinking caret, and field-level selection
- **DecompilerView** (Right dock, tab 1): `CodePlainTextEdit` (QPlainTextEdit) with CppHighlighter; word-level selection + occurrence highlight
- **HexView** (Right dock, tab 2): custom `QAbstractScrollArea` painting offset/hex/ASCII; highlights the byte range of the currently selected instruction
  - **ConsoleWidget** (Bottom dock): QPlainTextEdit, title bar hidden via `HideSingleWidgetTitleBar`

### Shared editor theme (`EditorTheme`)
- `src/gui/EditorTheme.h/.cpp` is the single source of truth for font family (`JetBrains Mono`), size (10 pt), weights (Normal 400 / Medium 500), cell metrics, line spacing (1.35), and token colors.
- All text views (`FieldView`, `CodePlainTextEdit`, `HexView`) read font and spacing from `EditorTheme`.

### Navigation sync (`CutterSeekable`)
- Pure virtual interface in `src/include/gui/CutterSeekable.h` (no QObject base)
- Methods: `seek(Address)`, `currentAddress()`, `setSyncState(bool)`, `syncState()`
- Each view emits its own `seekRequested(Address)` signal for navigation (double-click / Ctrl+click)
- MainWindow `seekAll(addr)` iterates synced views and calls `seek()`; `onAddressSeeked()` adds history + forwards to `seekAll()`

### Unified selection model (`SelectionManager`)
- `SelectionState` carries the selected instruction address, byte-range end, token text, and token kind.
- `SelectionManager` lives in `MainWindow`; every view has `setSelectionManager()` and an `applySelection(const SelectionState&)` slot.
- Selecting a token in any view resolves the containing instruction range and broadcasts it; all views update their highlight to the same address and token.
- Disassembly highlights the selected field (primary selection) plus occurrences; Decompiler highlights the matching line; Hex highlights the full instruction byte range with the caret on the first byte.

#### Cross-view selection — critical ordering & address-resolution rules

1. **`DecompilerView::applySelection` — `setTextCursor` before `updateOccurrenceHighlight`.**  
   `setTextCursor` triggers `cursorPositionChanged` → `highlightCurrentLine` → `setExtraSelections({lineHighlight})`, which wipes any extras set before it. Always move the cursor **first**, then call `updateOccurrenceHighlight` which sets both the line highlight and occurrence highlights in a single `setExtraSelections` call.

2. **`DecompilerView::lineForAddress` — nearest-containing-line, not exact match.**  
   `Document::lineForAddress` uses `std::upper_bound` (last address ≤ target). `DecompilerView::lineForAddress` formerly required exact match (`lineAddrMap_[i] == addr`), causing most cross-view selections to miss the decompiler line. Now uses linear scan returning the last entry ≤ addr.

3. **`CodePlainTextEdit::mousePressEvent` — never select words on click.**  
   The base class previously called `cursor.select(QTextCursor::WordUnderCursor)` on every left click, which broke click-drag text selection (copy/paste). Now delegates to `QPlainTextEdit::mousePressEvent` without modification. Word text is still extracted by `DecompilerView::mousePressEvent` using a **temporary** `wordCursor` copy without modifying the editor's cursor.

4. **`FieldView::mouseReleaseEvent` — always push to `SelectionManager` on click.**  
   Even when `tokenAt` returns null (click on whitespace/gap), the line address is pushed to `SelectionManager` so all views scroll to the same line. Click on a token calls `selectTokenAt` which creates a full `SelectionState` with `tokenText`, `tokenKind`, and the instruction address range.

5. **Hover cursor for clickable addresses.**  
   - `FieldView::mouseMoveEvent`: hand cursor (`Qt::PointingHandCursor`) when hovering over tokens with `refTarget != 0` or kind `Function`/`Label`/`Address`; arrow cursor otherwise. Mouse tracking enabled on viewport.
   - `DecompilerView::mouseMoveEvent`: hand cursor when `extractAddress(word)` returns non-zero; arrow cursor otherwise.

6. **`SelectionManager::select` deduplicates via `operator==`.**  
   `SelectionState::operator==` compares all fields including `originView`. `applySelectionToAllViews` sets `originView = nullptr` so the broadcast state differs from the originating view's state and is always applied.

### ADS source patches (persist in build tree)
- `_deps/qtadvanceddocking-src/src/DockOverlay.cpp` — `cursorLocation()` rewritten to full-window proportional drop zones (25%/25%/25%/25%/center)
- `_deps/qtadvanceddocking-src/src/DockManager.cpp` — `startDragDistance()` multiplier 1.5→4 (~40px before undock)
- Survive `cmake --build` rebuilds; reverted by CMake re-configure (FetchContent re-fetch)

### QSS policy
- No global QSS, no QPalette
- Only targeted QSS: `QSplitter::handle` (1px solid), border removal on dock widgets, ads--CDockOverlayCross icon color transparency
- Do NOT touch `ads--CDockDropIndicator` or other internal ADS classes

## Conventions (do not fight these)

- **Minimize comments.** Only comments that explain *why* or non-obvious
  behavior. No file-header banners, no per-function docstrings.
- **C++17**, no extensions, no C++20 features.
- **Compiler warnings suppressed** by `enigma_apply_warning_policy` in
  `CMakeLists.txt`: `-Wno-unused-parameter -Wno-overloaded-virtual -Wno-reorder`.
  New warnings outside this set will surface — do not add more suppressions
  silently, fix the cause.
- **Java memory model → C++**: `new X` you own → `std::unique_ptr<X>`;
  passed in and stored → `T*`; shared ownership → `std::shared_ptr<T>`.
  GC-managed collections become `std::vector<std::unique_ptr<T>>` or
  `std::unordered_map`/`std::map` depending on order.
- **Errors**: extend `std::exception` / `std::runtime_error` (mirroring
  `UsrException`, `CancelledException`, etc.). No checked-exception lists.
- **Every class = one PR / one change set**. Don't bundle unrelated classes.

## Decompiler internals — entry points to know

- `Enigma-Engine/include/ghidra/EnigmaPipeline.h` + `src/pcode/EnigmaPipeline.cpp`
  → top-level pipeline. Calls `Sleigh::oneInstruction()` per address, then
  `FlowInfo::generateOps()` + `generateBlocks()` to split into basic blocks
  and wire up edges, then `Heritage` (SSA), `ActionManager` (optimization),
  `PrintC` (output).
- `Enigma-Engine/src/pcode/Sleigh.cpp` — owns a Capstone handle (`capstoneHandle_`)
  and a `PcodeCapstoneMapper mapper_`. `Sleigh::oneInstruction()` is where
  raw bytes become pcode ops via Capstone + the mapper.
- `Enigma-Engine/src/pcode/PcodeCapstoneMapper.cpp` — ~2850 lines of
  per-architecture handler tables (~550+ handlers). Covers x86/ARM/MIPS/PPC.
- `Enigma-Engine/src/pcode/FlowInfo.cpp` — CFG construction: `splitBasic()`
  (split at terminal pcode ops), `collectEdges()` (BRANCH/CBRANCH/CALL/RETURN
  → edge targets), `connectBasic()` (dedup edges).
- `Enigma-Engine/include/ghidra/Sleigh.h` — `PcodeCapstoneMapper& getMapper()`
  is the public accessor used by callers that want to extend the mapper.

## Critical Java→C++ port pitfalls

- **Uninitialized instance members**: Ghidra Java `int` / `bool` fields default to
  0 / false. In C++ these are garbage unless initialized. Every `int4 localcount`
  in `coreaction.hh` (ActionInferTypes, ActionSegmentize, ActionConstantPtr) was
  uninitialized and caused ~70% of runs to skip all type propagation (fixed W~AM).
  Always check that C++ constructors initialize every member that Java would
  auto-zero.

## Things that will silently bite

- `decompiler/CMakeLists.txt` excludes `bfd_arch.cc`, `consolemain.cc`,
  `sleighexample.cc`, etc. and builds the rest as a static lib `decompiler`
  in namespace `ghidra_decompiler`. If you see a link error about missing
  symbols from the decompiler, the exclusion list may have grown; check
  `DECOMPILER_EXCLUDES`.
- `enigma_decompile_full` is built with
  `target_include_directories(... SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/decompiler)`
  so it sees the original Ghidra headers. New tools that use the SLEIGH
  internals need the same line.
- The `Sleigh::hasFallthrough()`, `isCallInstruction()`, etc. currently
  return hard-coded values (often `false` / `true` unconditionally). CFG
  edges are built from pcode opcodes in `FlowInfo::collectEdges()`, not from
  these virtuals, so changes to them are low-impact unless you also rework
  `FlowInfo`.
- Tests are not hermetic: `enigma_test_pipeline` writes `test_pipeline_binary.bin`
  into the current working directory and `std::remove`s it. Run tests from
  `build-cmake/` or a scratch dir if you care.
- `ENIGMA_SLEIGH_DIR` is baked in at compile time as a `target_compile_definitions`
  value. The default is `${CMAKE_CURRENT_SOURCE_DIR}/sleigh`. If you relocate
  `sleigh/`, re-configure with `-DENIGMA_SLEIGH_DIR=...`.

## `.opencode/`

This directory contains the OpenCode config:
- `agent/*.md` — 7 subagent definitions (analyzer, decompiler, disassembler,
  program-db, loader, ui, reviewer) used by the `task` tool.
- `package.json` — pulls in `@opencode-ai/plugin`.

These are repo-local conventions; honor the per-subagent scope rules when
dispatching tasks.

## Quick orientation checklist for new sessions

1. Read `Enigma-Engine/PLAN/PROGRESS.md` (current status, what's next).
2. Read `Enigma-Engine/PLAN/RULES.md` (architecture + Java→C++ translation
   rules + critical "do not edit" list).
3. Skim `Enigma-Engine/PLAN/DEPENDENCY_BLOCKERS.md` if you are about to
   touch any analyzer.
4. Build + run tests once to confirm the baseline: 7/7 suites, 3028/3028
   subtests pass.
5. Build + run tests once to confirm the baseline: 9/9 suites, 3134/3134
   subtests pass.
6. Build + run tests once to confirm the baseline: 12/12 suites, 3288/3288
   subtests pass (post W138 Batch E).
7. Build + run tests once to confirm the baseline: 13/13 suites, 3362/3362
   subtests pass (post W141 Batch H).
8. Build + run tests once to confirm the baseline: 14/14 suites, 3421/3421
   subtests pass (post W142 Batch I).
9. Build + run tests once to confirm the baseline: 15/15 suites, 3496/3496
   subtests pass (post W143 Batch J).
10. Build + run tests once to confirm the baseline: 16/16 suites, 3652/3652
    subtests pass (post W144 Batch K).
11. Build + run tests once to confirm the baseline: 17/17 suites, 3726/3726
    subtests pass (post W145 Batch L).
12. Build + run tests once to confirm the baseline: 17/17 suites, 3726/3726 subtests pass (post W145 Batch L).
13. Build + run tests once to confirm the baseline: 17/17 suites, 3726/3726 subtests pass (post W146 Batch M — model.symbol + model.listing sweep completed; scope corrected from ~111 files to ~17 actual files).
14. Build + run tests once to confirm the baseline: 18/18 suites, 3773/3773 subtests pass (post W~N Batch N — InjectContext completion, InjectPayload subtypes, ELEM_CONTEXT, 47 new tests).
15. Build + run tests once to confirm the baseline: 19/19 suites, 3810/3810 subtests pass (post W~O Batch O — CompilerSpec expansion + BasicCompilerSpec + 35 new tests).
16. Build + run tests once to confirm the baseline: 20/20 suites, 3872/3872 subtests pass (post W~P Batch P — BadDataType, MissingBuiltInDataType, MetaDataType, AbstractPointerTypedefBuiltIn, PointerTypedef, PointerTypedefBuilder, DataTypeInstance + 62 new tests).
17. Build + run tests once to confirm the baseline: 21/21 suites, 3911/3911 subtests pass (post W~Q Batch Q — StandAloneDataTypeManager, 39 tests).
18. Build + run tests once to confirm the baseline: 22/22 suites, 3959/3959 subtests pass (post W~R Batch R — BitGroup, EnumValuePartitioner, ReadOnlyDataTypeComponent, BuiltInDataTypeManager, 48 tests).
19. Build + run tests once to confirm the baseline: 23/23 suites, 3983/3983 subtests pass (post W~S Batch S — LEB128 utility, AbstractLeb128DataType, SignedLeb128DataType, UnsignedLeb128DataType, TerminatedStringDataType, TerminatedUnicode32DataType, StructuredDynamicDataType/IndexedDynamicDataType completion, 58 tests).
20. Build + run tests once to confirm the baseline: 25/25 suites, 4237/4237 subtests pass (post W~T Batch T — 219 tests for Structure/Union/Enum/Typedef/Composite/CompositeAlignmentHelper; model.data full audit confirmed all classes already fully implemented in prior batches; test_batch_t.cpp created).
21. Build + run tests once to confirm the baseline: 26/26 suites, 4420/4420 subtests pass (post W~U Batch U — SourceArchiveImpl.cpp ported (3 ctors, 9 overrides, 2 setters), test_batch_u.cpp with 183 tests covering SourceArchiveImpl + DataTypeConflictHandler (5 handlers + empty struct/union resolution) + DataTypePath + ParameterDefinitionImpl + FunctionDefinitionDataType + ArrayDataType + DataTypeImpl via TestDataTypeImpl subclass).
22. Build + run tests once to confirm the baseline: 27/27 suites, 4498/4498 subtests pass (post W~V Batch V — DataTypeWriter ported (header + cpp, ~360 lines, two-pass cycle breaking via inProgress_/forwardDeclared_/defined_/pending* sets, handles struct/union/enum/typedef/pointer/array/function-pointer/bitfield/dynamic), test_batch_v.cpp with 78 tests; DataTypeTransferable=AWT and FileDataTypeManager=PackedDB skipped per existing policy).
23. Build + run tests once to confirm the baseline: 28/28 suites, 4645/4645 subtests pass (post W~W Batch W — DataTypeUtilities + DataTypeNameComparator + DataTypeComparator + DataTypeObjectComparator + DataTypeManagerChangeListenerAdapter + DataTypeManagerChangeListenerHandler ported (DataTypeUtilities uses std::regex `\.conflict([_]?[0-9]+)?$` for conflict suffix matching, fixed FunctionSignatureImpl::clone() to deep-copy arguments via new ParameterDefinitionImpl to avoid double-free); audited already-fully-implemented: FunctionSignatureImpl, GenericCallingConvention (header-only), DataTypeManagerImpl (16 built-ins, add/remove/clear/lookup), DataTypeManagerChangeListener (14-method interface); test_batch_w.cpp with 147 tests).
24. Build + run tests once to confirm the baseline: 30/30 suites, 5260/5260 subtests pass (post W~Y Batch Y — comprehensive test coverage for PropertyMapManagerImpl + IntRangeMapImpl + AddressSetPropertyMapImpl + AddressSet + AddressIterator + ManagerDB lifecycle. tests/test_batch_y.cpp with 179 subtests. **Bug fixes**: (1) implemented missing `AddressSet::operator==` in src/address/AddressSet.cpp (was declared in header but never defined — caused link errors when used). (2) rewrote `AddressSet::xorSet` from broken keep-not-fully-contained-in-intersection algorithm to `union - intersection` semantics. Tests cover AddressSetPropertyMap add/set/remove/getAddressSet/getAddresses/getAddressRanges/clear/contains; IntRangeMap getValue/setValue/clearValue/multi-range/negative/overwrite; PropertyMapManager create+get+delete+recreate; ManagerDB setProgram/programReady/revision/clearCache/invalidateCache/deleteAddressRange/moveAddressRange/NO_MANAGER=-1; AddressSet basic/range ctor/min-max/clear/union/intersect/subtract/xor/equality/hasSameAddresses/count/print/toList/getRangeContaining/firstLastRange/findFirstAddressInCommon/intersects/contains/intersectRange/addressCountBefore/deleteRange/removeRange/addRange; AddressIterator default/with_vec/reset/current/empty; AddressSetRangeIterator forward iteration; AddressSetView interface.).
25. Build + run tests once to confirm the baseline: 31/31 suites, 5534/5534 subtests pass (post W~Z Batch Z — comprehensive test coverage for model.listing (CodeUnit, Instruction, Data, Listing) + model.lang (Register, Scalar, FlowOverride) + Reference (Reference interface, MemReferenceImpl) families. tests/test_batch_z.cpp with 274 subtests. **Patterns**: (1) `CodeUnit` is abstract (pure virtual `getLength()` and `toString()`) — test file uses a `TestCodeUnit` concrete subclass in an anonymous namespace to make it testable. (2) `AbstractDataType` is also abstract — can't instantiate a custom UnicodeDataType test subclass without implementing ~12 pure virtuals; tests that need a "unicode"-named DataType use the real `WideChar32DataType` (name="wchar32", fails the `find("unicode")` check) and assert the negative case. (3) `UnionDataType` 2-arg ctor is `(name, dtm)` not `(name, length)` — length is internal `unionLength_` set to 0 at construction. (4) `stringToFlowOverride` takes **lowercase** keys (`branch`/`call`/`callreturn`/`return`/`none`); uppercase returns `NONE`. (5) `Scalar::getSignedValue()` sign-extends based on the high bit of the bit length, not the `isSigned` flag — use values that don't have the high bit set (e.g. `0x7EADBEEF` not `0xDEADBEEF`) to test unsigned positive. (6) `Register::compareTo` requires different `address_` for two unrelated registers to return non-zero; same base + same `leastSigBitInBaseRegister_` returns 0. (7) `RefType::__JUMP` doesn't exist — use `__UNCONDITIONAL_JUMP` (=1) or any of the actual `__*` enum values. (8) `MemReferenceImpl::toString()` format is `<from> -> <to> (<type>)` with no `0x` prefix on hex addresses (Address::toString with minDigits=8 produces `00000100`). (9) `Data::isPointer` checks `getName().find('*') != npos` — `PointerDataType(nullptr, len)` has name "pointer" (no `*`!) so it returns false; you must pass a real referenced type to get the `X *` name. (10) `Data::isStructure`/`isUnion`/`isString` all check substrings of the name — use `StructureDataType("struct X", len)`, `UnionDataType("union X")`, `CharDataType` (name "char") to trigger them.).
26. Build + run tests once to confirm the baseline: 32/32 suites, 5646/5646 subtests pass (post W~AA Batch AA - Undefined1..8DataType, CycleGroup, CustomOrganization, CountedDynamicDataType, RepeatedStringDataType, RelocationResult, RelocationUtil, StringIngest, LinkedByteBuffer, ListLinked, BuiltInDataTypeClassExclusionFilter, NoisyStructureBuilder, InvalidatedListener; 112 subtests in test_batch_aa.cpp; bug fix: LinkedByteBuffer::pad() byteCount increment).
27. For porting work, find the Ghidra source under `ghidra-source code/`
    matching the class header you are porting.
28. Build + run tests once to confirm the baseline: 33/33 suites, 5858/5858
    subtests pass (post W~AB-W~AE Batches AB-AE — all model.* packages at 100%
    ported; enigma_test_batch_ab registered with 212 subtests).
29. Build + run tests once to confirm the baseline: 33/33 suites, 5891/5891
    subtests pass (post W~AF PcodeCapstoneMapper expansion + graph classes
    ported. ~80 new instruction handlers across x86/ARM/MIPS/PPC. New graph
    classes: Vertex, Edge, DirectedGraph, DepthFirstSearch, Dominator.
    test_batch_ab expanded to 245 subtests).
30. Build + run tests once to confirm the baseline: 34/34 suites, 5940/5940
    subtests pass (post W~AG Storage Phase 1 — Repository, SnapshotWriter,
    SnapshotReader, WorkingSnapshot implemented. 4 FlatBuffers schemas with
    `fbschema` namespace. Fixes: `Program::Program()` default constructor added,
    `DefaultMemoryBlock` constructor handles nullptr address space,
    `SnapshotWriter` uses `getCompilerSpecID()` not `getCompilerSpec()`.
    enigma_test_storage_p1 test suite with 49 subtests. 49/49 pass.).
31. Build + run tests once to confirm the baseline: 34/34 suites, 6013/6013
    subtests pass (post W~AH Storage Phase 2 — EventLog undo/redo for 13 event
    types. Event.h with 13 concrete Event subclasses. EventLog.h/EventLog.cpp
    with position-based log, undo/redo/truncation. Bugs fixed: FlatBuffers
    ChangeType enum uses `ChangeType_` prefix not scoped syntax;
    `SymbolTable::removeSymbolSpecial` use-after-free (save name/addr before
    erase); `Address::operator==` null-space false-negative. enigma_test_storage_p2
    test suite with 73 subtests. 73/73 pass.).
32. Build + run tests once to confirm the baseline: 35/35 suites, 6090/6090
    subtests pass (post W~AI Storage Phase 3 — CommitManager + ChangeSet + EventLog
    compaction. CommitManager.h/CommitManager.cpp with createCommit (snapshot +
    changeset.writer), loadCommitMeta, listCommits, loadChangeSet, commitExists.
    EventLog→FlatBuffers ChangeSet conversion with compaction (same-type+same-addr
    merging, self-cancelling events elided). Virtual methods getOldValue/getNewValue/
    getChangeSetName added to Event base class. EventLog.getEvents() accessor added.
    enigma_test_storage_p3 test suite with 77 subtests. 77/77 pass.).
33. Build + run tests once to confirm the baseline: 36/36 suites, 6150/6150
    subtests pass (post W~AJ Storage Phase 4 — BranchManager with create/list/delete/
    switch/getCurrentBranch/getBranchCommit/branchExists. Uses existing project.meta
    FlatBuffers schema (BranchPointer table + current_branch field). Cannot delete
    current branch; cannot create duplicate or empty-named branches; all operations
    validated against invalid repo paths. enigma_test_storage_p4 test suite with 60
    subtests. 60/60 pass.).
34. Build + run tests once to confirm the baseline: 37/37 suites, 6204/6204
    subtests pass (post W~AK Storage Phase 5 — IndexManager LMDB-based index cache.
    LMDB library installed via pacman (mingw-w64-x86_64-lmdb). Single LMDB database
    with key prefixes for symbol name→addr, addr→name, function name→entry, entry→name.
    Supports rebuildFromProgramDB, add/remove/lookup for both symbols and functions,
    clear. enigma_test_storage_p5 test suite with 54 subtests. 54/54 pass.).
35. Build + run tests once to confirm the baseline: 38/38 suites, 6204/6204
    subtests pass (post complete project scan — all 5 storage phases done, 7 major
    sub-projects at 65-90% completion. Storage system (LMDB/FlatBuffers/Branch/Commit)
    replaces Ghidra's ~500-file `database/*` layer entirely. What's next: CLI/corpus
    regression tests, output quality (naming/signatures), ProgramDB integration gaps
    (DecompInterface), Mach-O loader.).
36. Build + run tests once to confirm the baseline: **39/39 suites pass**
    (post corpus-regression + output-quality improvements). Corpus regression:
    `tests/corpus/expected/` holds 6 reference `.bin.c` files (5 raw + PE);
    `test_corpus_regression.py` does exact diff-based comparison; `regenerate_corpus.py`
    rebuilds refs. Output quality: calling conventions (`__fastcall`/`__stdcall`)
    now displayed in function declarations; PE x64 uses `windows` compiler spec
    (`x86-64-win.cspec`) for proper Windows x64 conventions; raw binaries use
    `default` compiler (`x86-64-gcc.cspec`) for GCC conventions. Thunk detection
    uses `beginOpAll()` ± pcode-op iteration (CALL/CALLIND) for correct import
    passthrough detection. `resolveFuncRefs` normalises `function_0x` → `sub_0x`.
    See `Enigma-Engine/tools/enigma_decompile_full.cpp` lines 414-419, 593-611,
    and `Enigma-Engine/sleigh/x86/x86.ldefs` lines 14, 94 for key changes.
37. Build + run tests once to confirm the baseline: **41/41 suites pass**
    (post DecompInterface crash fix + Mach-O loader completion). DecompInterface
    `closeProgram()` crash fixed: double-free of loader resolved (Architecture
    takes ownership via raw pointer, `closeProgram()` zeros without deleting).
    Mach-O loader: strtab length (`sizeof` vs `strlen` for embedded nulls),
    LC_DYSYMTAB field offsets (+56/+60, not +48/+52), `parseMachO32()` DYSYMTAB
    handler added. Import resolution from `__la_symbol_ptr`/`__got` via indirect
    symbol table now works. 41 test suites (39 C++ + 2 Python), ~6400+ aggregate
    subtests, 0 failures. Phase 2d: Native Pipeline next.
38. Build + run tests once to confirm the baseline: **41/41 suites pass**
    (post ASLR non-determinism root-cause fix). Reverted `varmap` to pointer-based
    comparator (safe, no dereference). Added `HighVariable::createIndex` — a
    deterministic creation-order index (modeled after `Varnode::getCreateIndex()`)
    used by `HighEdge::operator<` for stable ordering in
    `map<HighEdge,bool> highedgemap`. Counter resets in `Funcdata::clear()`.
    This replaces the raw `HighVariable*` pointer comparison that made type
    propagation order depend on ASLR layout. All corpus regression tests pass
     deterministically without retries.
39. Build + run tests once to confirm the baseline: **42/42 suites pass**
    (post W~AM uninitialized-localcount fix). Three classes in `coreaction.hh`
    (ActionInferTypes, ActionSegmentize, ActionConstantPtr) had `int4 localcount`
    never initialized in their C++ constructors — garbage in this field caused
    ~70% of runs to hit `if (localcount >= 7)` early-return guard and skip all
    type propagation. Fixed by adding `{ localcount = 0; }` in each constructor.
    All 14 corpus binaries now deterministic across 10+ repeats (previously 5/14
    would flip between two output variants).
40. Build + run tests once to confirm the baseline: **48/48 suites pass**
    (post W~AG Signature System Persistence). Signature system is now a
    first-class component of ProgramDB: per-property source tracking with
    priority chain (USER > DWARF > PDB > KNOWN > IMPORT > UNKNOWN), 80-entry
    known-function signature database analyzer, 6 new Event types for signature
    changes (undo/redo + ChangeSet), branch head auto-advance on commit,
    lossless datatype graph serialization (struct/union/enum/pointer/array/
    typedef). ProgramDB→Snapshot→ProgramDB is structurally lossless for all
    datatype information. 5 new test suites: apply_known_signature (52),
    signature_persistence (70), repository_reload (37), type_roundtrip (33),
    gap_verification (26).
41. Build + run tests once to confirm the baseline: **48/48 suites pass**
    (post W149 Function Discovery Cleanup). Scalar → Reference pipeline restored
    (`CapstoneDisassembler` emits resolved operand scalars, `ProgramDB` duplicate
    address fields removed, reference analyzers re-enabled). Forensic audit vs
    Ghidra on `notepad_test.exe` drove three deterministic analyzer fixes:
    `EntryPointAnalyzer` skips non-executable entry points; `DisassemblyAnalyzer`
    recursive descent stays within executable sections; `FunctionStartAnalyzer`
    rejects candidates reached by normal fallthrough. 380 false positives
    eliminated; final metrics: 405 matching, 72 legitimate extras, 29 missing
    (unreachable compiler helpers). All temporary instrumentation removed.
42. **Phase 3a: TypeDatabase & Call-Site Annotation** — abstract `TypeDatabase` base +
    `WindowsTypeDatabase` (1487-entry), `LinuxTypeDatabase`/`MacOSTypeDatabase` stubs,
    `TypeDatabaseFactory` with platform detection, `AnalysisBridge::bridgeImportSignatures()`
    bridge on scope iteration, `applyTypeDatabaseToCallSpecs()` post-decompilation hook.
    notepad: 53 types applied (was 0), shell32: 298 types applied (was 0). All 48/48 suites pass.
43. **Phase 3b: Qt GUI Workspace** — ADS refactoring (CDockManager replaces QDockWidget/QSplitter),
    CutterSeekable interface + impl in Hex/Disasm/Decompiler views, MainWindow seek hub
    (`seekAll`/`onAddressSeeked`/`navigateTo`/`onNavigateBack`), View menu checkmarks,
    Console title bar hidden, Explorer improvements (sort/monospace/bold/tooltips/clear),
    full-window ADS drop zones, increased drag threshold. Build and run with:
    `cmake -S . -B build-cmake -G "MSYS Makefiles" -DCMAKE_BUILD_TYPE=Debug` then
    `cmake --build build-cmake --target enigma_gui` then
    `./build-cmake/enigma_gui.exe`
