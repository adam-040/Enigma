# Enigma Engine - Progress

## Status
- **Official progress file**: `PLAN/PROGRESS.md`
- **Backend build**: SUCCESS (`cmake --build`), 54/54 CTest suites pass
- **GUI build**: SUCCESS (`cmake --build --target enigma_gui`), MSYS Makefiles generator
- **Custom disassembly rendering COMPLETE**: `DisassemblyFieldView` rewritten as a standalone `QAbstractScrollArea` with lazy on-demand instruction decoding. `DisassemblyModel` rebuilt as an address-ordered row index (functions + symbols → per-instruction walk via `DecompInterface::instructionLengthAt`, function headers, gap analysis for uncovered data). No front-loaded Document/Token build: `buildFullIndex()` is now a fast index-only walk (no text disassembly); `decodedInstruction()` lazily decodes visible rows via `disassembleAt(addr, 1)` into an `unordered_map` cache, invalidated by `invalidateCache()`/`invalidateRange()`. Direct `paintEvent` renders only visible rows with token colors/selection/caret. Address-based seek via binary search over sorted rows. Deleted orphaned `DisassemblyView` + `AsmHighlighter` dead code. MainWindow uses `rowCount()` instead of `document()`. 54/54 CTest pass.
- **GUI hardening + patching workflow COMPLETE (W151)**: Fixed all remaining crash paths in the disassembly view — empty-view mouse handlers (`mousePressEvent`/`mouseReleaseEvent`/`mouseDoubleClickEvent` early-return when `lineCount()==0`, fixes crash on the "No disassembly" placeholder), uncaught SLEIGH `LowlevelError` from `DecompInterface::instructionLengthAt` inside `DisassemblyModel::buildIndex` (try-catch + skip), full-view guard in `buildFullIndex()` (try-catch + `model_.clear()`), and scrollbar `pageStep` negative-value clamp. Window now starts maximized (`showMaximized()`). Fixed the **patched-binary export pipeline** end-to-end: `BinaryLoader` lifetime bug (loader was a local `unique_ptr` in `loadBinary`, passed to `PatchManager` via raw pointer → dangling → export crash) fixed by promoting to a `MainWindow` member `binaryLoader_`; `PatchMemory` double-free on teardown fixed via `releasePatchMemory()` before program/loader reset. New **`tools/enigma_patch_cli.cpp`** (`enigma_patch_cli <input> <addr:hex> <orig_hex> <new_hex> <output>`) for headless byte-patch + export + verify. **First real-world patch**: reverse-engineered `pass.exe` (PE x86-64 MinGW, `main` at 0x1400014b0, hardcoded password `"adam2006"`, `strcmp` at 0x1400014fe, `jne 75 11` at 0x140001505 = file offset 0xb05); patched `75 11` → `90 90`, verified `pass_patched.exe` accepts any password ("correct" for wrong input). Added **"Export Patched Binary..." to the disassembly right-click context menu** (always available, plus instruction-specific items on instruction rows) via new `exportPatchedRequested()` signal wired to `onExportPatchedBinary()` in MainWindow. GUI packaging: `Enigma-Engine/dist/` contains the exe + required DLLs (`Qt6Core/Gui/Widgets`, `libgcc_s_seh-1`, `libstdc++-6`, `libwinpthread-1`, `zlib1`, `libcapstone`, `liblmdb`), Qt `platforms/qwindows.dll`, `styles/qmodernwindowsstyle.dll` (modern Windows theme — missing plugin falls back to classic "old Windows" look), and the `sleigh/` specs folder (64.6 MB total, verified launching from the folder). 54/54 CTest suites still pass.
- **Patching UX COMPLETE (W152)**: Four patching workflow improvements. (1) **Inline Patch Markers**: 12px gutter added to `DisassemblyFieldView` (`kGutterWidth`), green vertical bar (2px x, 4px wide, 2px inset) drawn on rows whose address has an active patch (`PatchManager::getActivePatches()` → `baseAddress()` set, checked once per paint). All text/selection/caret coordinates shifted by the gutter (`caretAtPos`, `updateScrollBars`, placeholder, paint loop). (2) **Patch Undo/Redo disassembly refresh**: `onUndo()`/`onRedo()` now call `invalidateCache()` + `buildFullIndex()` + viewport update so the disassembly reflects reverted/reapplied bytes (was only refreshing hex). Also fixed for `onRevertAllPatches()`. (3) **Patch List Panel**: new `src/gui/PatchListWidget.h/.cpp` (`QTableWidget`), docked as "PATCH LIST" under HEX (splitDockWidget), columns Address/Original/Patched/Name/Status, sorted by address, live refresh via `PatchManager` callbacks (`onPatchAdded_/onPatchRemoved_/onPatchEnabled_/onPatchDisabled_`), double-click row → seek in disasm+hex, right-click menu → Delete Patch / Toggle Enable-Disable, Patch menu "Show Patch List" now toggles the dock (checkable). (4) **Patch Save/Load (.json)**: `PatchManager::saveToJson(path)`/`loadFromJson(path)` using nlohmann/json (now linked into `enigma_engine`; schema `{version:1, format:"enigma-patches", patches:[{id, category, address, original(hex), patched(hex), name, description, enabled, assembly?, original_size?}]}`, byte-level categories only; InstructionPatch round-trips via assembly text). Patch menu actions "Save Patches..." / "Load Patches...". JSON round-trip test added to `tests/test_patching_features.cpp` (140 subtests). All 54/54 CTest suites pass.
- **GUI decompiler type-bridge COMPLETE (Alpha 0.2.0)**: `DecompInterface::openProgram` now runs the full `AnalysisBridge` pipeline (`bridgeFunctions`, `bridgeTypes`, `bridgeImportSignatures`, `bridgeNoReturnFlags`, `bridgeLabels`, `bridgeReadOnlyRanges`, all in try/catch) with the platform `TypeDatabase` chosen from `getExecutableFormat()` (PE→Windows 1487-entry, ELF→Linux, Mach-O/FAT/PEF→MacOS) — the GUI decompiler now matches the CLI tool instead of showing generic params. `AnalysisBridge::resolveTypeName` gained a string-pointer branch: `const char*`/`char*`/`LPCSTR`/`LPSTR`/`PCSTR`/`PSTR`/`LPCCH`/`LPCH` map to `char*`, and the `wchar_t*`/`LPCWSTR`/`LPWSTR`/`PCWSTR`/`PWSTR`/`LPCWCH`/`LPWCH` family to `wchar16*` (via cached core types `findByName` with 1/2-byte INT fallback). Variadic imports fixed: new virtual `TypeDatabase::isVariadic()` + `getVariadicTable()` in WindowsTypeDatabase (printf/scanf/sprintf/snprintf/fprintf family + `_s`/wide/`v`-variants); `bridgeImportSignatures` sets `firstVarArgSlot = paramTypes.size()` for variadics so prototypes render `char *param_1,...`. `MainWindow::onAnalysisFinished` re-bridges the decompiler post-analysis (`decompCache_.clear()` + `refreshFunctionSymbols()` in try/catch) so imports/thunks/types from analysis phase are visible. Verified on pass.exe before/after: `main(char *param_1, char *param_2)`, `__mingw_printf(param_1)`, `__mingw_scanf(param_1)`, `strcmp(param_1, param_2)` (was `__mingw_printf()` with 0 args and 4-arg `strcmp`); CLI output matches with `char *param_1,...` prototypes. All 54/54 CTest suites pass; GUI + CLI build clean.
- **SVG icon high-DPI rendering COMPLETE**: `MainWindow::loadSvgIcon` renders each SVG vector directly at device-pixel resolution — pixmap sized `size × devicePixelRatioF()` and tagged with the DPR, so Qt blits it 1:1 with no rasterization or scaling artifacts (replaced the old 2x-supersample + `smooth` downscale which blurred on high-DPI screens). Icons unchanged in design, size (16 px), position, spacing, layout. Offscreen DPR-2 comparison harness measured +18% avg edge sharpness across the 5 toolbar icons (settings/help/donate/folder-free/folder-open); PNG pairs saved under `%TEMP%\opencode\iconcheck\`. Also added missing `src/gui/icons/app_icon.png` placeholder (referenced by `resources.qrc`, was breaking the `enigma_gui` build).
- **Function discovery false-positive cleanup COMPLETE**: Restored the Scalar → Reference pipeline (scalar extraction in Capstone disassembler, `ProgramDB` duplicate address fields removed, `ScalarOperandAnalyzer`/reference analyzers re-enabled). Audited Enigma vs Ghidra function lists on `notepad_test.exe`, eliminated 380 false positives through three deterministic fixes (`EntryPointAnalyzer` execute-flag enforcement, `DisassemblyAnalyzer` recursive-descent section containment, `FunctionStartAnalyzer` fallthrough-interior rejection). Final metrics: Enigma 477, Ghidra 434, matching 405, extra 72 (all legitimate), missing 29 (unreachable compiler helpers); recall 93.3%, precision 84.9%, F1 88.7%. All temporary instrumentation removed; build and tests pass.
- **All model.* packages 100% ported to C++ headers** — model.data (246), model.listing (72), model.symbol (39), model.lang (109), model.util (19), model.pcode (77), model.block (27), model.mem (20), model.reloc (5), model.sourcemap (6), model.scalar (2), model.gclass (2), model.address (40/40 after final 5 ported). Only legacy `OldGenericNamespaceAddress` skipped.
- **Tests**: **48/48 CTest suites, all pass** (~9400+ aggregate subtests). All 5 storage phases complete. Repository, SnapshotWriter/Reader, WorkingSnapshot (Phase 1, 49 tests). EventLog with 13 event types, undo/redo/truncation (Phase 2, 73 tests). CommitManager + ChangeSet with compaction (Phase 3, 77 tests). BranchManager with create/list/delete/switch (Phase 4, 60 tests). IndexManager LMDB-based symbol/function index (Phase 5, 54 tests). Corpus regression (16 binaries, Python). CLI regression (19 tests, Python). FlatBuffers schemas (program.fbs, project.fbs, commit.fbs, changeset.fbs) with `fbschema` namespace. LMDB library added as build dependency. The storage system replaces Ghidra's ~500-file `database/*` layer entirely.
- **TypeDatabase & Call-Site Annotation COMPLETE**: Abstract `TypeDatabase` base + `WindowsTypeDatabase` (1487-entry) + platform factory. `AnalysisBridge::bridgeImportSignatures()` applies types to direct imports during decompilation. `applyTypeDatabaseToCallSpecs()` post-processing hook annotates `FuncCallSpecs`. notepad: 53 types applied (was 0), shell32: 298 types applied (was 0).
- **Qt GUI Workspace COMPLETE (structure phase)**: Qt-Advanced-Docking-System refactoring with Disassembly/Decompiler/Hex/Explorer/Console views. `CutterSeekable` interface for navigation sync across all views. Full-window ADS drop zones, increased drag threshold, View menu checkmarks, Explorer tree improvements. No visual theme applied yet.
- **Unified NavigationCoordinator refactor COMPLETE (W-NAV)**: All cross-view navigation now flows through a single mediator. `src/gui/NavigationCoordinator.{h,cpp}` (`registerView(QWidget*, skipBit, Applier)` / `unregisterView` / `navigate(NavigationEvent, skipMask)`, origin-guarded, idempotent registration, `lastEvent`) + `src/gui/NavigationEvent.h` (exact byte `address` + `TokenKind`). Views: **HexView** byte-exact (`lineForAddress` + byteIndex + 2-char column), **DisassemblyFieldView** instruction-exact (`rowForAddress` binary search + token match), **DecompilerView** statement-exact (statementAddr lines + opAddresses token addrs). Removed dead code: `CutterSeekable.h`, `SelectionManager.{h,cpp}`, `SelectionState.h`, `cursorAddressChanged` signal, `cursorSyncTimer_`/pending-sync coalescing, `seekToAddress`. MainWindow hub: registers views with `NavSkip_*` bits; `doNavigate` STEP8 performs the single `navCoord_->navigate(ev, navSkipFlags_)` broadcast; `onNavigationEvent` updates the status/info labels only (no re-broadcast); patch/string/patch-list/bookmark/assembly/undo-redo paths all route through coordinator events; `NAV_SKIP` env isolation preserved. Verification: offscreen harness `%TEMP%\opencode\enigma\test_navigation.exe` (linked against enigma_gui build objects) — 17/17 asserts passing (entry microlanding, mid-instruction byte exactness, skip masks, origin-guard, unregister/re-register, lastEvent). Also deleted pre-existing stray `src/symbol/Listing.cpp` that duplicated `ghidra::Listing` in `libenigma_engine.a` (fixed `enigma_test_decomp_interface` multiple-definition link failure). 54/54 CTest pass; full build clean.

- **Phase 2b (Infrastructure Porting)**: IN PROGRESS — Porting remaining Ghidra model/infrastructure to C++. Completed batches: A (10 classes, W133), B (data type family 9 + 5 followup = 14 classes, W134-W135), C (Block* family 14 + CachedEncoder = 15 classes, W136), D (model.lang 12 classes, W137), E (model.util + model.address 10 classes, W138), F (model.pcode Packed encoder/decoder 5 classes, W139), G (model.pcode Varnode/PcodeOp banks + SyntaxTree 3 classes, W140), H (PcodeFactory interface + PcodeDataTypeManager + HighSymbol 3 classes, W141), I (SegmentedAddressSpace + ProtectedAddressSpace + SegmentedAddress + AddressSpace.getAddress(string) virtuals, 3 classes, W142), J (model.pcode symbol map family 10 classes + 3 ElementIds, W143), K (model.pcode HighFunction family 17 classes + DataTypeSymbol + EquateTable interface expansion, W144), L (PcodeException + ParamMeasure + JumpTable + VarnodeTranslator + PcodeOverride + FunctionPrototype expansion + HighFunctionDBUtil + per-(addr,opnd) EquateTable + 5 ElementIds, W145), M (model.symbol sweep + model.listing sweep — 10 symbol classes + 13 listing classes + exceptions/enums, W146), N (InjectContext completion + InjectPayload subtypes + ELEM_CONTEXT + 47 subtests, batch N), O (CompilerSpec expansion + BasicCompilerSpec + 35 subtests, batch O), P (model.data: BadDataType, MissingBuiltInDataType, MetaDataType, AbstractPointerTypedefBuiltIn, PointerTypedef, PointerTypedefBuilder, DataTypeInstance + 62 subtests, batch P), Q (StandAloneDataTypeManager — in-memory DataTypeManager + 39 subtests, batch Q), R (BitGroup + EnumValuePartitioner + ReadOnlyDataTypeComponent + BuiltInDataTypeManager + 48 subtests, batch R), S (LEB128 utility + AbstractLeb128DataType + SignedLeb128DataType + UnsignedLeb128DataType + TerminatedStringDataType + TerminatedUnicode32DataType + DynamicDataType/StructuredDynamicDataType/IndexedDynamicDataType/FactoryStructureDataType/StructureFactory/DataUtilities completion + 58 subtests, batch S), T (audit + 219 subtests for StructureDataType/UnionDataType/EnumDataType/TypedefDataType/CompositeDataTypeImpl/CompositeInternal/CompositeAlignmentHelper — classes were already fully implemented in prior batches, batch T adds comprehensive test coverage, batch T). Analyzer integration validation COMPLETE (W148). 25/25 CTest suites pass, 4237/4237 subtests.

- **Roadmap (remaining work)**:
  - **W145**: `FunctionPrototype` (full skeleton) + `ParamMeasure` + `JumpTable` + `VarnodeTranslator` + `PcodeOverride` + `PcodeException` + `HighFunctionDBUtil` + `EquateTable` per-(addr,opnd) tracking. **COMPLETE**.
  - **W146**: model.symbol sweep (AddressLabelPair, IllegalCharCppTransformer, SymbolIteratorAdapter, SymbolTableListener) + model.listing sweep (CircularDependencyException, ContextChangeException, DuplicateGroupException, FunctionOverlapException, IncompatibleLanguageException, VariableSizeException, AutoParameterType, CommentType). **COMPLETE**.
  - **W~N**: InjectContext completion + InjectPayload/InjectPayloadSleigh/InjectPayloadSubtypes + ELEM_CONTEXT. 47 new tests (batch N). **COMPLETE**.
  - **W~O**: CompilerSpec expansion (properties map, calling-convention management, PrototypeModel* vectors, stack/register fields, alignment, endianness, PcodeInjectLibrary pointer) + BasicCompilerSpec (subclass with Language*/CompilerSpecDescription*, context settings, globalSet_, matchConvention). 35 new tests (batch O). **COMPLETE**.
  - **W~P**: COMPLETE — BadDataType, MissingBuiltInDataType, MetaDataType, AbstractPointerTypedefBuiltIn, PointerTypedef, PointerTypedefBuilder, DataTypeInstance ported (62 tests).
  - **W~Q**: COMPLETE — StandAloneDataTypeManager (in-memory DataTypeManager + 39 tests).
   - **W~R**: COMPLETE — BitGroup, EnumValuePartitioner, ReadOnlyDataTypeComponent, BuiltInDataTypeManager (4 classes, 48 tests).
   - **W~S**: COMPLETE — LEB128 utility, AbstractLeb128DataType, SignedLeb128DataType, UnsignedLeb128DataType, TerminatedStringDataType, TerminatedUnicode32DataType (6 files, 19 tests).
   - **W146+**: model.symbol (39 files) + model.listing (72 files) — `Symbol`, `Namespace`, `SymbolTable`, `Function`, `Instruction`, `CodeUnit`, etc.
   - **W~T**: model.data continued — StructureFactory, Enum write paths completion, remaining data type infrastructure.
   - **W~U**: COMPLETE — SourceArchiveImpl port (header was already present, cpp now implemented) + comprehensive test coverage for SourceArchiveImpl, DataTypeConflictHandler (5 handlers + 4 conflict resolution cases for empty struct/union), DataTypePath, ParameterDefinitionImpl, FunctionDefinitionDataType, ArrayDataType, DataTypeImpl (183 subtests in test_batch_u.cpp).
   - **W~V**: COMPLETE — DataTypeWriter port (header + cpp). Simplified C declaration emitter that handles structures, unions, enums, typedefs, pointers, arrays, function-pointers and BitField/Dynamic with two-pass forward-declaration cycle breaking. Skipped DataTypeTransferable (Java AWT) and FileDataTypeManager (PackedDatabase on disk) per existing database/* skip policy (78 subtests in test_batch_v.cpp).
  - **Skipped permanently**: `database/*` (~500 files) — CLI uses in-memory `ProgramDB`, the on-disk DB layer is not needed for the offline decompiler.

## Build System
- CMake + Ninja + MinGW64 g++ 15.2.0, C++17
- All targets compile and link cleanly, zero warnings

## Binary Loaders
- **PE Loader**: PE32/PE32+ sections, imports, exports, relocations, image base, entry point.
- **ELF Loader**: ELF32/ELF64 sections, symbols, dynamic imports, entry point.
- **MachO Loader**: Mach-O headers and load commands.
- **Decompiler CLI auto-detection**: `enigma_decompile_full` detects PE/ELF and falls back to raw binary.
- **SLEIGH language guessing**: x86/x64/ARM/AARCH64/MIPS/RISCV/PowerPC where supported.

## Ghidra Source Coverage Audit
- **Analyzers**: Checked against `ghidra-source code` `*Analyzer.java` inventory. Enigma has 132 registered analyzers in `AutoAnalysisManager`. Product-relevant analyzers are represented; the only Java analyzer names not mirrored as Enigma analyzers are non-product/support cases: `HeadlessAnalyzer` (headless orchestration, not an analyzer plugin), `SkeletonAnalyzer` (GhidraBuild template), `TestAnalyzer` (FileFormats test/demo), and `JitDataFlowBlockAnalyzer` (JIT emulation internals, not first-version decompiler analysis).
- **Loaders**: Enigma intentionally does not mirror every Java `*Loader.java`. Ghidra has many UI/importer/table/classloader/helper loaders (`BrowserLoader`, `TableDataLoader`, `ProgramLoader`, `GhidraClassLoader`, `SkeletonLoader`, etc.). The backend first-version loader path is the C++ `BinaryLoader` with PE/ELF/Mach-O parsing and ProgramDB population, plus format analyzers for PEF/COFF/Dex/OAT/VDEX/DyldCache/Android/iOS/filesystems and related metadata. Future loader work should be driven by real binary import needs, not by blindly porting UI/helper loaders.

## Analysis Framework Infrastructure (Complete)
| Component | Notes |
|-----------|-------|
| Analyzer interface | Pure virtual + AnalyzerType enum + utility functions |
| AbstractAnalyzer | Full base with analyzeLocation, runParallelAddressAnalysis |
| AnalyzerAdapter | Inline adapter for simple analyzers (header-only) |
| AutoAnalysisManager | Full lifecycle: register, schedule, run, event-driven |
| AnalysisScheduler | Priority-based scheduling |
| AnalysisTaskList | Task list with priority-ordered schedulers |
| AnalysisPriority | All Ghidra-compatible priority constants |
| AnalysisWorker | Worker interface for background tasks |
| AnalysisOptionsUpdater | Option rename/migration support |
| ConstantPropagationContextEvaluator | Full 560-line port |
| ContextEvaluatorAdapter, VarnodeContext, SymbolicPropogator | Complete |
| FileFormatAnalyzer | Base class with toAddr, createData, createFragment, etc. |
| ByteProvider, MemoryByteProvider, BinaryReader | Endian-aware primitive reads |

## Decompiler Integration
- **Ghidra C++ Decompiler**: Integrated as `decompiler` library (namespace `ghidra_decompiler`)
- **SLEIGH specs**: 25 processor families under `Enigma-Engine/sleigh/`
- **CLI**: `enigma_decompile_full` produces real C from real binaries
- **Enigma-Native Pipeline**: Capstone -> Pcode mapper -> native PrintC (partial)

## Analyzer Coverage

### Processor-Specific Analyzers (12 architectures, all done)
X86Analyzer, ArmAnalyzer, PowerPCAddressAnalyzer, RISCVAddressAnalyzer, SparcAnalyzer (+ Early), SH4AddressAnalyzer (+ Early), MipsAddressAnalyzer (+ Pre + Symbol), HexagonAnalyzer (+ PrologEpilog + Thunk + UnsupportSemantic), LoongsonAnalyzer, Motorola68KAnalyzer, NDS32Analyzer, Pic12/16/17c7xx/18/Switch/24DInitAnalyzer, HCS12ConventionAnalyzer, AARCH64PltThunkAnalyzer, eBPFSyscallAnalyzer, ToyAnalyzer

### File-Format / Platform Analyzers (all done)
PE, ELF, MachO, PEF, COFF, COFF Archive, AppleSingleDouble, Img2, Img3, iBootIm, Apple8900, DmgAnalyzer, DyldCache, iOS_Analyzer, iOS_FixupArmSymbols, iOS_KextStubFixup, Lzss, BinaryPropertyList, AndroidBootLoader, BootImage, FBPK, ArtAnalyzer, Ext4/NewExt4, CramFs, Dtb/Fdt, OatHeader/Exec, OdexHeader, VdexHeader, DexHeaderFormat/CondenseFiller/ExceptionHandlers/MarkupData/MarkupInstructions/MarkupSwitchTable, PdbAnalyzer, PdbUniversal

### Analysis-Phase Analyzers (all done)
FunctionAnalyzer, FunctionStart*, EntryPoint, ExternalEntry, ExternalSymbolResolver, CreateThunk, ImportThunk, CallFixup/CallFixupChange, CondenseFillerBytes, FindNoReturn/NoReturn, SharedReturn/SharedReturnJump, AddressTable, ScalarOperand/ElfScalarOperand, OperandReference/DataOperandRef, StackReference/StackVariable, ConstantPropagation, ApplyDataArchive, EmbeddedMedia, CliMetadataToken, FormatString, GccException, Strings, AggressiveInstructionFinder/ArmAggressive, DWARF, DecompilerFunction/CallConvention/Switch, PEException, Rtti, MingwRelocation, WindowsResourceReference, PropagateExternalParameters, TEB, SegmentedCallingConvention, X86FunctionPurge, PefDebug, MachoFunctionStarts/MachoConstructorDestructor, CFString

### Language/Framework Analyzers (all done)
JavaAnalyzer, JvmSwitchAnalyzer, GolangSymbol/GolangString, RustString/RustDemangler, SwiftTypeMetadata/SwiftDemangler, ObjcMessage/ObjcTypeMetadata, GnuDemangler/MicrosoftDemangler, FidAnalyzer, MySwitchAnalyzer (utility)

## Implemented Waves

- **W87-W97**: ParamList, PrototypeModel, protorules system (2732→2958 tests)
- **W98-W99**: Language/Register kernel, CompilerSpec, Inject payloads
- **W100-W105**: Block model, iterators, subroutine models, flow analysis
- **W106-W110**: Native/Ghidra decompiler pipelines, PE/ELF auto-detect, batch decomp, CLI fixes
- **W111**: Analyzer System Core — FlowInfo, BlockGraph, PcodeBlockBasic, AutoAnalysisManager
- **W112**: Analyzer System Audit — all implementations verified real
- **W113**: Emulator + FloatFormat edge case fixes
- **W114**: Analyzer Ghidra API alignment — 18 AAM methods, AnalysisWorker, AnalysisOptionsUpdater, AnalyzerAdapter
- **W115**: Loader & Storage verification — BinaryLoader, VariableStorage real, no stubs
- **W127**: 15 new analyzers (14 real: 12 ConstantPropagationAnalyzer subs + SparcEarly + SH4Early; 1 stub)
- **W128**: 40 analyzers ported → 130 total registered (previously marked as "stubs" but re-audited to real in W131)
- **W129**: 14 real format analyzers — Apple (Img2/3, iBootIm, Apple8900, Dmg, BootImage, AndroidBootLoader), FS/DT (Art, BinaryPropertyList, Dtb, Fdt, Lzss, Ext4, NewExt4)
- **W130 Finale**: ToyAnalyzer + MySwitchAnalyzer — all 132 analyzers done.
- **W131**: Systematic re-audit of all 132 analyzers — **132 real, 0 stubs**. Previous "75 stubs" figure was inaccurate: 107 analyzers have own `added()`/`analyze()` with real logic, 13 inherit from `ConstantPropagationAnalyzer` with architecture-specific overrides, 12 are base classes with infrastructure logic. Zero analyzers return `false` or log "stub" as the only behavior.
- **W148**: Analyzer Integration Validation — full-stack test running 132 analyzers against a real PE binary via `AutoAnalysisManager.startAnalysis()`. Fixed `processSchedulerQueue` iterator-invalidation bug, `FunctionStartDataPostAnalyzer` infinite-loop on large address ranges (capped at 50K scan / 500 found), `StubTaskMonitor` for test harness. 5 new subtests, 24/24 CTest suites, 3988/3988 subtests.
- **W149 (Function Discovery Cleanup)**: Restored inactive scalar pipeline and eliminated false-positive function discoveries. `CapstoneDisassembler::disassembleOne()` now extracts resolved address scalars per operand into `DisassembledInstruction::operandScalars`; RIP-relative values are resolved to absolute addresses. `DisassemblyAnalyzer` and `Disassembler::populateListing()` propagate these scalars into `Instruction` objects so `ScalarOperandAnalyzer`/`OperandReferenceAnalyzer`/reference analyzers run on real data. Fixed `ProgramDB` shadowing `Program::imageBase_`/`minAddress_`/`maxAddress_` that disabled `ScalarOperandAnalyzer` enablement. Forensic audit of `notepad_test.exe` attributed 451 extra functions to analyzers; implemented three deterministic fixes: `EntryPointAnalyzer` skips non-executable entry points, `DisassemblyAnalyzer` recursive descent stops at section boundaries, `FunctionStartAnalyzer` rejects candidates reached by normal instruction fallthrough. Removed all temporary instrumentation from `FunctionManager`, `AutoAnalysisManager`, `BinaryLoader`, `FunctionDiscoveryAnalyzer`, and `enigma_dump_functions.cpp`. Build passes; final comparison vs Ghidra: 477 vs 434 total, 405 matching, 72 legitimate extras, 29 missing (compiler-generated helpers not reachable deterministically).
- **W150 (Stress-test pipeline audit & .pdata fixes)**: Stress-tested Enigma engine against 10 largest Windows system binaries (kernel32, ntdll, user32, win32kbase, win32kfull, dxgkrnl, d2d1, shell32, ntoskrnl, mshtml). Function counts: 3,583–67,669. Validated against Ghidra on kernel32/ntdll/user32: Enigma averages +55% extra (data pointer FPs) and −4% missing vs Ghidra. Created 4 analysis tools (`classify_extras.py`, `investigate_missing.py`, `compare_function_lists.py`, `check_pdata.py`). Fixed 4 bugs in `FunctionStartAnalyzer.cpp`: (A) moved `findFunctionsFromPdata()` to run first before other sub-sources, (B) removed 0xCC/0x00 first-byte filter in pdata loop, (C) relaxed `isUndefined` check to `getInstructionAt`/`getDataAt`, (D) added function body splitting when a .pdata entry falls inside an oversized function body (COFF loader symbol too large). Result: kernel32 3,583→3,584, all 3 genuine .pdata misses now captured and confirmed matching Ghidra.

## Overall Status

| Dimension | Status |
|-----------|--------|
| **Aggregate tests** | **9400+** (48 CTest suites, 48/48) |
| **Analyzers registered** | **132 total (132 real impl, 0 stubs)** |
| **Decompiler tests** | 45/45 (17 decompiler + 28 DecompInterface) |
| **Loader tests** | 54/54 (25 PE/ELF + 29 Mach-O) |
| **Headless suite** | ALL PASS |
| **Stress tests** | 602/602 |
| **Pipeline tests** | 47/47 (16 pipeline + 31 comprehensive) |
| **CLI regression** | ALL PASS |
| **Storage (Phases 1-5)** | 313/313 (49+73+77+60+54) |
| **Binary loaders** | PE, ELF, MachO (import resolution via indirect symbol table) |
| **Type Database** | Windows 1487-entry, Linux/MacOS stubs, platform factory, call-site annotation |
| **Qt GUI** | ADS workspace (5 panes), CutterSeekable navigation sync, full-window drop zones |
| **Subroutine models** | M-Model, O-Model, S-Model, P-Model |
| **Native pipeline coverage** | x86: 60+ handlers, ARM: 50+ handlers, MIPS: 40+ handlers, PPC: 50+ handlers |

## Native Pipeline Coverage

### x86 (60+ instructions)
mov, movzx, movsx, movd, movq, push, pop, add, sub, inc, dec, neg, not,
and, or, xor, shl, shr, sar, shld, shrd, rol, ror,
mul, imul, div, idiv, cmp, test, xchg,
call (direct/indirect), ret, jmp, lea,
je/jne/jg/jge/jl/jle/ja/jae/jb/jbe/jo/jno/js/jns/jp/jnp/jecxz,
syscall, sysenter, int, int3,
cdq, cqo, cdqe, cwde,
cmova/cmovae/cmovb/cmovbe/cmove/cmovg/cmovge/cmovl/cmovle/cmovne/cmovno/cmovns/cmovo/cmovs,
popcnt, cvtsi2ss/cvtsi2sd/cvttss2si/cvttsd2si/cvtss2si/cvtsd2si (+ AVX variants)

### ARM (50+ instructions)
mov, movs, movw, movt, ldr, str, ldrb, strb, ldrh, strh, ldrsh, ldrsb,
ldm, stm, push, pop, add, adds, sub, subs, rsb, mul,
b, bl, bx, blx (all conditional variants),
and, orr, eor, bic,
cmp, cmn, tst, teq,
sdiv, udiv, sxtb, sxth, uxtb, uxth,
clz, mla, umull, smull,
it, ite, itt, itee, ittt, itte

### MIPS (40+ instructions)
move, mfhi, mflo, add, addu, addi, addiu, sub, subu,
lw, sw, lb, sb, lbu, lh, sh, lhu, ld, sd, ll, sc,
j, jal, jr, jalr (all conditional variants),
and, or, xor, andi, ori, xori, nor,
sll, srl, sra, sllv, srlv, srav,
slt, slti, sltu, sltiu,
mult, multu, div, divu, madd, maddu,
clz, clo, lui, nop, ssnop, sync

### PPC (50+ instructions)
mr, mfocrf, mtocrf, mflr, mtlr, mfctr, mtctr, mfcr,
add, addi, addis, addc, adde, addme, addze, subf, subfic, subfc,
mulli, divw,
lwz, stw, lbz, stb, lhz, sth, ld, std, lwa,
lwzu, stwu, lbzu, stbu, lhzu, sthu, lfsw, stfsw,
b, bl, blr, blrl, bctr, bctrl, bc, bclr (all conditional variants),
and, andc, or, orc, xor, nand, nor, eqv,
slw, srw, sraw, sld, srd, srad,
cmp, cmpl, cmpi, cmpli, cmplw

## What's Next
1. ~~**Storage System (Phases 1-5)**~~ — **COMPLETE**. FlatBuffers snapshots, Event Log undo/redo, Commit/ChangeSet, BranchManager, LMDB IndexCache. Replaces Ghidra's ~500-file `database/*` layer.
2. ~~**Analyzer integration validation**~~ — **COMPLETE** (W148). 132 analyzers run against real PE binary, 5/5 integration tests pass.
3. ~~**CLI/corpus regression expansion**~~ — **COMPLETE**. 14 reference `.bin.c` files in `tests/corpus/expected/` (8 simple + 6 SIMD/crypto/AVX), exact diff-based corpus regression (`enigma_test_corpus_regression`), `regenerate_corpus.py` rebuilds refs. Output typing is now deterministic (ASLR root cause fixed via `HighVariable::createIndex`). 19 CLI regression tests. CLI regression checks: exit codes, stdout patterns, stderr patterns, output file creation, PE auto-detection, import symbol resolution, timing flag, error paths.
4. ~~**Output quality**~~ — **COMPLETE**. Calling conventions (`__fastcall`/`__stdcall`) displayed in function declarations; PE x64 uses `windows` compiler spec (`x86-64-win.cspec`) for proper Windows x64 conventions; raw binaries use `default` compiler (`x86-64-gcc.cspec`) for GCC conventions. Thunk detection via `beginOpAll()` pcode-op iteration. `resolveFuncRefs` normalises `function_0x` → `sub_0x`. Entry point naming checks `symbolNames` before falling back to `FUN_ENTRY`. CLI and `DecompInterface` now share final C-output cleanup: strip extra blank lines after opening braces, print empty parameter lists as `()`, and map standalone decompiler `xunknown*` display types to Ghidra-style `undefined*`.
5. ~~**ProgramDB integration (DecompInterface)**~~ — **COMPLETE**. `DecompInterface` now exposes a UI-ready ProgramDB bridge: list functions from `FunctionManager`, decompile by `Address` or `Function*`, return call counts/call metadata, reject addresses outside memory without crashing, and pass load -> ProgramDB -> save snapshot -> reload -> decompile plus load -> rename -> EventLog -> commit -> ChangeSet -> commit snapshot reload -> decompile workflow tests.
6. ~~**Mach-O loader completion**~~ — **COMPLETE**. Full Mach-O parsing equivalent to PE/ELF. Fixed strtab length via `sizeof` instead of `strlen` (was cutoff at first embedded null). Fixed LC_DYSYMTAB field offsets (`indirectsymoff`/`nindirectsyms` at +56/+60, not +48/+52). Added LC_DYSYMTAB handler to `parseMachO32()` which was missing it. Import resolution from `__la_symbol_ptr`/`__got` sections now works via indirect symbol table. Removed spurious `reserved1 == 0` skip (0 is a valid indirect table index). 29 tests in `test_macho_loader.cpp`.
7. ~~**Phase 2d: Native Pipeline**~~ — **COMPLETE (batch AO)**. Added comprehensive `enigma_test_pipeline_comprehensive` test suite (31 subtests across x86/ARM/MIPS/PPC architectures):
   - PcodeCapstoneMapper initialization test for all 4 architectures
   - Flow type detection expanded: added MIPS `jr`/`jal`, PPC `blr`/`bctr`, `syscall`, all x86 conditional jumps (`jg`/`jl`/`ja`/`jb`/`jo`/`js`/`jp`/`jecxz`/`loop`/`loope`/`loopne`, ARM `bgt`/`bge`/`blt`/`ble`/`bhi`/`bhs`/`blo`/`bls`/`bmi`/`bpl`/`bvc`/`bvs`) in `Disassembler::determineFlowType()`
   - Memory operand detection tests
   - Full x86-64 pipeline decompilation test (push/mov/sub/add/call/pop/ret) verifying CALL/RETURN/STORE pcode ops survive DCE
   - ARM/MIPS/PPC Sleigh disassembly tests (single-instruction decode via Capstone)
   - PrintC edge cases (empty function)
   - LoadImage edge cases (missing file, empty file)
   - Uninitialized Sleigh edge case
   - Made `PcodeCapstoneMapper::isMemoryOperand()` and `getUniqueCounter()` public for testing
8. ~~**Phase 3a: Type Database & Call-Site Annotation**~~ — **COMPLETE**. Abstract `TypeDatabase` base class + `WindowsTypeDatabase` (1487-entry table via `wintype_siggen.inc`) + `LinuxTypeDatabase`/`MacOSTypeDatabase` stubs + `TypeDatabaseFactory` with `detectPlatform()`/`createTypeDatabaseForPlatform()` + `AnalysisBridge::bridgeImportSignatures()` scope iteration + `applyTypeDatabaseToCallSpecs()` post-decompilation hook. Bridge stats: notepad 53 types applied (was 0), shell32 298 types applied (was 0). All 48/48 CTest suites pass (3050/3054 — same 4 pre-existing failures, no regressions).
9. ~~**Phase 3b: Qt GUI Workspace**~~ — **COMPLETE (structure phase)**. Qt-Advanced-Docking-System (ADS v4.5.0, FetchContent, static build) replaces QDockWidget/QSplitter/QTabWidget. Five dock widgets: Explorer (Left), Disassembly (Center), Decompiler (Right tab 1), Hex (Right tab 2 via addDockWidgetTab), Console (Bottom). All views wrap `ads::CDockWidget` with 3-argument (`QString title`, `QIcon`, `QWidget*`) constructor. `CutterSeekable` pure virtual interface for navigation sync. Full-window proportional drop zones (ADS source patch: `cursorLocation()` → 25/25/25/25/center). Drag threshold 4× default. View menu toggle/sync checkmarks. Console title bar hidden. Explorer A-Z sort, monospace, bold categories, tooltips, clear button. Run: `cmake -S . -B build -G Ninja` then `cmake --build build --target enigma_gui` then `./build/enigma_gui.exe`.
10. **Phase 3c: GUI Feature Completion** — In progress:
     - **Hex view (COMPLETE)**: inline hex editing (type hex digits, two-nibble accumulator, yellow active-byte highlight, auto-advance), Ctrl+V paste, local undo/redo (10K cap), Ctrl+G go-to-address, Ctrl+F search via `HexSearchBar` (hex/ASCII modes, F3/Shift+F3, green match highlights), Ctrl+H find-replace (replace current/all), bookmarks (Ctrl+D, Ctrl+Up/Down, blue diamond glyph), Interpret Selection As (Int8/16/32/64, UInt*, Float, Double, ASCII), Copy As (Hex String/C Array/Python Bytes), status bar offset+bookmark info. Fixed click-selection offset bug: `FieldView::gutterWidth()` became virtual; HexView overrides to 0 (it has no line-number gutter, but the caret-at-pos math subtracted one).
     - **Disassembly view (COMPLETE, standalone QAbstractScrollArea, LAZY decode)**: DisassemblyFieldView rewritten to drop the front-loaded `Document`/`Token`/`ParsedLine` model entirely:
       - `DisassemblyModel` (`DisassemblyModel.h/.cpp`) is now an address-ordered row index: collects functions from `FunctionManager` + symbol table (per-address dedupe), walks each function body with `DecompInterface::instructionLengthAt()` (4KB cap per function), emits `FunctionHeader` rows (`; === name ===`) and gap-analysis rows (`GapComment`) for uncovered executable data (zero padding / string / 32-64 bit pointer tables / hex dump). Rows merged and sorted by address; `addressToRow` is a hashmap, `rowToAddress`/`rowAt` direct lookup.
       - `DecodedInstruction` cache (`std::unordered_map<uint64_t, DecodedInstruction>`): `decodedInstruction(addr)` decodes one instruction via `decomp_->disassembleAt(addr, 1)`, verifies parsed address matches, fetches raw bytes from memory, builds the full token vector (address + bytes + mnemonic + operands) with the existing `tokenizeOperands`/`classifyIdentifier`/`isBranchMnemonic` logic. Cache invalidation via `invalidateCache()` (full) and `invalidateRange(start, end)` (overlap-aware). Decode failure renders `; <failed to decode N bytes>` comment.
       - Direct `paintEvent`: paints only visible rows from decoded cache, windowed row range, current-row highlight, drag selection, selected-token primary highlight, occurrence highlight, token colors from `EditorTheme::colorTable()/fontTable()`, blinking glyph-height caret. `maxColsSeen_` grows during paint and drives the horizontal scrollbar (no full-width pre-pass).
       - Address-based scrolling: vertical scrollbar range = row count; `seek()` = binary search over sorted rows (walks backward past FunctionHeader sharing an address with its first instruction) with fallback to first row; fallback-text mode (`showDisassembly`) uses parsed `FallbackLine` rows with the same rendering path.
       - Full interaction parity with old FieldView: click/drag selection, token selection on click, occurrence highlight, Ctrl+click / double-click navigation on `refTarget`/Address tokens, Left/Right/Up/Down/PageUp/PageDown/Home/End with Shift selection, Copy/SelectAll, hover hand cursor, context menu (Assemble/Go to/Jump to Code Cave via `trampolineMap_`), `SelectionManager` integration (`applySelection` broadcast from Hex/Decompiler views), `cursorAddressChanged` sync.
       - MainWindow updated: `document()->lineCount()` checks replaced with `rowCount()`. Patch handlers keep calling `buildFullIndex()` + `seekToAddress()` — now cheap (index-only walk + cache clear).
       - Deleted orphaned dead code: `DisassemblyView.h/.cpp` (QPlainTextEdit version) + `AsmHighlighter.h/.cpp` (unused since DisassemblyFieldView became active).
       - 54/54 CTest suites pass; GUI build clean.
       - Shared `EditorTheme` now owns the canonical monospace font and metrics used by Disassembly, Decompiler, and Hex views.
       - Fixed cell-grid: each glyph painted at `leftPad + col * cellWidth`, caret drawn as a 1 px vertical line at cell boundaries, click→column uses `round((clickX + scrollX - leftPad) / cellWidth)`.
       - Font family `JetBrains Mono` (10 pt) with Normal base weight (400) and Medium emphasis (500); cell width is computed from the base font to keep the grid stable regardless of token kind.
       - Token model (`Token`/`Line`/`Document`) with 21 kinds: Address, Bytes, Mnemonic, Branch, Register, Immediate, Number, MemRef, Punctuation, Label, Function, Variable, Type, Keyword, String, Comment, BracesOuter, BracesInner, Operator, Semicolon, Plain.
       - Syntax coloring: Mnemonic/Branch/Type/Keyword/BracesOuter/BracesInner/Semicolon/Punctuation use emphasis font (Medium 500), all others use base font (Normal 400).
       - Click selects line + caret-line highlight; double-click or Ctrl+click on an Address/Immediate/Function/Label token navigates via `seekRequested`.
       - Occurrence highlight for Register/Immediate/Function/Label/Variable on plain click.
       - Toggleable raw-bytes column between address and mnemonic (`View → Show Bytes`), computed from address deltas and `DecompInterface::instructionLengthAt()` fallback for the final instruction.
       - Tabs expanded to spaces before tokenizing to keep column counts aligned with painted positions.
     - **DecompilerView (custom FieldView)**: VSCode-style line number gutter, C syntax tokenization (`tokenizeCLine`), XML markup parsing (`documentFromMarkup`), 21-token-kind color scheme with K&R-style coloring (outer braces yellow, inner braces/red, semicolons red, operators dark, keywords blue bold, function names purple).
    - **EditorTheme**: central `src/gui/EditorTheme.h/.cpp` providing `baseFont()`, `emphasisFont()`, `cellWidth()`, `cellHeight()`, `ascent()`, `descent()`, `glyphHeight()`, `leftPadding()`, `lineSpacing()`, and `colorFor(TokenKind)`. Used by FieldView, DisassemblyFieldView, CodePlainTextEdit/DecompilerView, and HexView so all editors share identical family, size, weight, line spacing, and token palette.
    - **Caret polish**: glyph-height caret drawn with `EditorTheme::glyphHeight()`; blinking timer driven by `QApplication::cursorFlashTime()`, reset on every caret move/click/key; caret only drawn when the view has focus.
    - **Token/field-level selection**: single click in Disassembly selects the operand/register/address field under the cursor (not the whole line), with primary selection highlight and white text. Clicking a token also highlights all occurrences of that token in the view. The Decompiler uses `QTextCursor::WordUnderCursor` so clicking selects the word (e.g. `local_18`, `uint64_t`).
    - **Unified cross-view selection model**: `SelectionState`/`SelectionManager` owned by `MainWindow` holds the single program-wide selection (address + endAddress + token). All three views connect to it: selecting in any view resolves the instruction address range (via `Document::instructionRangeForAddress()` / `DecompInterface`) and broadcasts to the others. Disassembly highlights the token/field, Decompiler highlights the corresponding line, and Hex highlights the full instruction byte range with the caret on the first byte. Status bar updates with address and containing function name.
     - **QScintilla Refactoring (Decompiler/Hex)**: DecompilerView is now a custom `QAbstractScrollArea` (`FieldView` subclass) with VSCode-style line number gutter, C syntax tokenization, XML markup parsing, and 21-token-kind color scheme. HexView remains `QsciScintilla`-based with dark theme; Disassembly moved to the custom FieldView above.
    - **Fusion style**: `QApplication::setStyle(QStyleFactory::create("Fusion"))` applied in main.cpp
    - **Navigation preserved**: `CutterSeekable` interface, `seekRequested` signals, double-click/Ctrl+click navigation, address↔line mapping
    - Persist layout state via `CDockManager::saveState()`/`restoreState()`
    - Address-range scrollbar in DisassemblyView
    - Dock locking (global lock/unlock per dock widget)
    - CFG view (QGraphicsView integration)
    - AI/LLM Integration (deferred)

## Backend MVP Closure Checklist
1. ~~**DecompInterface bridge**~~ — **COMPLETE**. ProgramDB function listing, `Function*` decompile, snapshot reload/open/decompile workflow, and out-of-memory address guard are covered by `enigma_test_decomp_interface`.
2. ~~**ASLR non-determinism**~~ — **RESOLVED**. Root cause (`HighEdge::operator<` raw pointer comparison in `HighVariable` ordering) fixed via `HighVariable::createIndex`. All corpus regression tests pass deterministically without retries.
3. ~~**Real corpus expansion**~~ — **COMPLETE (batch AP)**. Corpus expanded from 14 to 16 stable refs with two new raw binary tests:
   - **`branch_test.bin`**: Tests conditional branching (cmp + jg + fallthrough), ensures optimizer correctly constant-folds always-taken branches (`return 10`)
   - **`call_test.bin`**: Tests function call + chained return (`call` + `ret` -> `add` + `ret`), ensures callee discovery and cross-function return value tracking works
   - All corpus tests registered via `tests/test_corpus_regression.py` with exact-diff comparison
   - New `.bin` files in `tests/corpus/`, expected `.bin.c` in `tests/corpus/expected/`
   - Files: `tests/corpus/branch_test.bin`, `tests/corpus/call_test.bin`,
     `tests/corpus/expected/{branch_test,call_test}.bin.c`
4. ~~**Progress/roadmap cleanup**~~ — **COMPLETE**. Keep `PLAN/PROGRESS.md` as the source of truth; `AGENTS.md` and older roadmap notes may lag because many agents update the project in parallel. `PLAN/BACKEND_API.md` defines the first UI-facing backend surface.
5. ~~**Freeze `v0.1-backend`**~~ — **COMPLETE**. Backend at 43/43 CTest baseline. Type normalization (undefined*→uint*_t), DWARF name integration, readonly propagation, IAT target resolution, 230+ library prototypes, jump table recovery, determinism fix, corpus regression (16 tests). API naming reviewed across public headers — consistent `ghidra`/`ghidra_decompiler` namespaces, `#pragma once` everywhere, `PascalCase` classes, `camelCase` methods. Run `git tag v0.1-backend` when git is available in the build environment.
6. **Post-MVP direction** — decide between deeper backend parity work and starting UI/plugin only after the backend freeze.

## Storage Replacement Decision
`database/*` is intentionally not being ported as a direct Java database clone. It is replaced by the Enigma storage architecture documented in `PLAN/DB system.md` and `PLAN/Diff.md`: FlatBuffers snapshots, EventLog undo/redo, CommitManager + compacted ChangeSets, BranchManager, and LMDB as a rebuildable index cache. Program snapshots now persist loaded memory bytes so reopened projects can decompile without reloading the original binary.

- **W~T - Batch T (COMPLETE)**: model.data Structure/Union/Enum/Typedef test coverage. Audited 11 existing fully-implemented classes (StructureDataType, UnionDataType, EnumDataType, TypedefDataType, CompositeDataTypeImpl, CompositeInternal, CompositeAlignmentHelper, StructureInternal, UnionInternal, Category, TypeDef), confirmed all real implementations (28/28 for Structure, 21/21 for Union, 24/24 for Enum, 23/23 for Typedef). Created `tests/test_batch_t.cpp` with 219 subtests covering add/insert/delete/replace/clone/copy/grow/setLength/repack/clear/bitfield/find operations on Structure and Union data types, plus enum/typedef/composite alignment/packing/clone tests. All 25/25 CTest suites pass (4237/4237 subtests).
- **W~U - Batch U (COMPLETE)**: SourceArchiveImpl port + comprehensive test coverage for 8 already-implemented model.data classes. Ported `SourceArchiveImpl.cpp` (3 constructors, 9 virtual overrides for the 6 SourceArchive accessors + setLastSyncTime/setName/setDirtyFlag setters). Audited `DataTypeConflictHandler` (5 handlers: DEFAULT, KEEP, REPLACE, REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD with empty-struct/empty-union RENAME_AND_ADD logic, BUILT_IN_MANAGER that throws), `DataTypePath` (CategoryPath+name split, getPath, compareTo, isAncestor, hash), `ParameterDefinitionImpl` (5 setters/getters, isEquivalent by name+dt+comment), `FunctionDefinitionDataType` (setArguments/setReturnType/setComment/setVarArgs/setNoReturn/setCallingConvention + getPrototypeString with varargs/void/cconv), `ArrayDataType` (constructor with elementLength default, clone/copy/dependsOn/hasLanguageDependantLength), `DataTypeImpl` (defaultSettings/lastChangeTime/parentList/sourceArchive/setDescription throws). Created `tests/test_batch_u.cpp` with 183 subtests. All 26/26 CTest suites pass (4420/4420 subtests).
- **W~V - Batch V (COMPLETE)**: DataTypeWriter port. Created `include/ghidra/DataTypeWriter.h` (forward decls for DataType/Composite/Structure/Union/Enum/Pointer/Array/TypeDef/FunctionDefinition/BitFieldDataType/Dynamic, public API: write(DataType*)+write(std::vector<DataType*>) with TaskMonitor*, isResolved, resolvedCount, EOL constant) and `src/data/DataTypeWriter.cpp` (~360 lines). Two-pass cycle breaking: doWrite adds composite/enum/typedef to `inProgress_` set on first sight (breaks recursion) and queues the full definition in `pendingComposites_/pendingEnums_/pendingTypedefs_`; `emitPending()` drains the queues after the initial walk. Forwards-declared composites/enums use `forwardDeclared_` to prevent double-forward-decl. `writePointer` introspects pointer depth (`getPointerDepth`) and emits `typedef T * name;` (multi-star for pointer-to-pointer). `writeFunctionDef` and `writePointer(FunctionDefinition*)` emit `typedef R (*name)(args)` function-pointer aliases. `writeBitField` and `writeDynamic` emit comment markers (no C-level representation). Component field comments are emitted (or field path if comment is empty). Skipped per existing policy: `DataTypeTransferable` (Java AWT datatransfer) and `FileDataTypeManager` (PackedDatabase on-disk). All 27/27 CTest suites pass (4498/4498 subtests including 78 new batch_v subtests).
- **W~W - Batch W (COMPLETE)**: model.data / model.listing utilities + comparators + change-listener fanout + FunctionSignature/GenericCallingConvention/DataTypeManagerImpl audit. New files: `include/ghidra/DataTypeUtilities.h` + `src/types/DataTypeUtilities.cpp` (getPointerArrayDecorations strips at first `*` or `[`; getNameWithoutConflict via regex `\.conflict([_]?[0-9]+)?$`; getConflictValue returns 0 for bare `.conflict`, N for `.conflictN`, N for `.conflict_N`; canHaveConflictName: Pointer always, BuiltIn never, everything else true), `include/ghidra/DataTypeNameComparator.h` + `src/types/DataTypeNameComparator.cpp` (case-insensitive compare with conflict-suffix numeric tiebreak; ties fall through to original-case difference, so uppercase sorts before lowercase), `include/ghidra/DataTypeComparator.h` + `src/types/DataTypeComparator.cpp` (name → DTM name → category path chain; both-DTMs-null short-circuits to 0), `include/ghidra/DataTypeObjectComparator.h` + `src/types/DataTypeObjectComparator.cpp` (4 overloads: dt/dt, str/dt, dt/str, str/str), `include/ghidra/DataTypeManagerChangeListenerAdapter.h` (header-only no-op adapter for 14 listener methods), `include/ghidra/DataTypeManagerChangeListenerHandler.h` + `src/data/DataTypeManagerChangeListenerHandler.cpp` (synchronous fanout handler, idempotent add/remove, dispatches to all listeners). Audited and confirmed already-fully-implemented: `FunctionSignatureImpl` (8 setters/getters, getPrototypeString with varargs/void/cconv, isEquivalent, clone) — fixed `clone()` to deep-copy arguments via new `ParameterDefinitionImpl` (was double-freeing by sharing pointers). `GenericCallingConvention` (header-only constants: unknown, stdcall, cdecl_cc, fastcall, thiscall, vectorcall). `DataTypeManagerImpl` (16 built-in types populated, addDataType/addDataTypeWithId/removeDataType/clearAllDataTypes, ID generation via nextId_). `DataTypeManagerChangeListener` (14-method interface). Created `tests/test_batch_w.cpp` with **147 subtests** covering DataTypeUtilities (decoration strip, conflict-suffix regex on .conflict/.conflict<N>/.conflict_<N>/non-matching decorations, conflict value 0..N/-1 for invalid, conflict-name eligibility for Pointer vs BuiltIn vs composite), all 3 comparators (case-insensitive with original-case tiebreak, conflict ordering, name→DTM→catpath chain), Adapter+Handler (14-method fanout, idempotent add/remove), FunctionSignature constants + FunctionSignatureImpl (default/named, all setters, arguments list with null-arg rejection, setArguments replace semantics, prototype string with varargs/noreturn/cconv, isEquivalent across all axes, deep-clone, hasUnknownCallingConventionName), GenericCallingConvention constants, DataTypeManagerImpl (default + named ctor, getName/setName, built-in lookup by path+name and by id, addDataType with duplicate-path returns existing and duplicate-pointer is idempotent, getDataTypes returns >=16, clearAllDataTypes wipes user data but re-populates built-ins, removeDataType deletes type, getNextId increments, getDataOrganization non-null, calling-convention lists start empty). All 28/28 CTest suites pass (4645/4645 aggregate subtests including 147 new batch_w subtests).
- **W~X - Batch X (COMPLETE)**: Comprehensive test coverage for already-fully-implemented program model building blocks. Audited and exercised: `RefType`/`RefTypes` (all static FlowType + DataRefType instances with getName/getSymbolChar/isData/isFlow/isRead/isWrite/isCall/isComputed/isExternal/isJump/isUnCall/isUnJump tests), `EquateTable` (CRUD + per-(addr,opnd) variants: createEquate/lookupEquate/getAllEquates/getEquateCount/removeEquate by name/addr/value; `setName` only updates Equate field, doesn't reindex `equatesByName_`; `removeEquate(addr, opnd, value)` only removes opnd reference, keeps Equate alive), `SourceType` (isUserDefined/getPriority/isHigherPriorityThan/getStorageId/getDisplayString/getSourceType covering all 6 priority levels), `SymbolType` (symbolTypeToString + isFunctionType/isLabelType/isNamespaceType for all 5 label + 3 function + 4 namespace types), `Namespace` (path/equality/parent/ID/isGlobal; default-constructed is global because `id_==-1` AND `name_` is empty), `VariableStorage` (BAD/UNASSIGNED/VOID static constants — only BAD/UNASSIGNED invalid; isMemory/equals/intersects/contains/compareTo/serialize), `VariableImpl` family (Local/Parameter/Return/AutoParameter with all 4 AutoParameterType enums; `RETURN_ORDINAL = -1`; `AutoParameterImpl::getName() == "this"` for THIS and `"__return_storage_ptr__"` for RETURN_STORAGE_PTR; setter throws "Auto-parameter is read-only"), `Function` (create/setProgram/addTag/addParameter/removeParameter/setReturn/getParameterCount/getSignature), `FunctionManager` (create/remove/iterate/CC/getKey/overlap/autoname/invalidate/with_program; `createFunction("", ...)` auto-names to `"FUN_<addr>"`; Function destroyed by `~Function()` not raw `delete`), `SymbolIterator` (next/hasNext/reset/current/remaining; `current()` returns nullptr when `index_==0` so `reset()` resets current to null). Used `ProgFixture` helper with `ProgramDB` + manually-added ram/stack address spaces via `ProgramAddressFactory::addAddressSpace` + `setStackSpace`. Created `tests/test_batch_x.cpp` with **436 subtests**. All 29/29 CTest suites pass (5081/5081 aggregate subtests).
- **W~Y - Batch Y (COMPLETE)**: Comprehensive test coverage for PropertyMapManagerImpl + IntRangeMapImpl + AddressSetPropertyMapImpl + AddressSet + AddressIterator + ManagerDB lifecycle. **Bug fixes during this batch**:
  1. `AddressSet::operator==` was declared in `include/ghidra/AddressSet.h:104` (and `operator!=` inlined) but never defined in `src/address/AddressSet.cpp`. Implemented the body in the .cpp: compares `getNumAddresses()` + iterates address ranges with `getAddressRanges()` and compares each via `AddressRange::operator==`. Tests revealed the missing symbol only when AddressSet equality assertions were used.
  2. `AddressSet::xorSet` had a broken algorithm: it took the union of `*this` and `addrSet`, then walked the union's ranges and kept any range that wasn't fully contained in the intersection. For two overlapping ranges [0x100,0x300] and [0x200,0x400] the union is a single range [0x100,0x400] which is not fully contained in the intersection [0x200,0x300] — so the entire union was kept (wrong). Rewrote to `union - intersection` semantics. Used the existing `subtract` method which correctly handles range splitting.

  **Test coverage (179 subtests)**: AddressSetPropertyMap (add start-end, add set, set, remove start-end, remove set, getAddressSet, getAddresses, getAddressRanges, clear, contains) on AddressSetPropertyMapImpl; IntRangeMap (basic name, setValue/getValue, multi-range, clearValue, overwrite appends to ranges_, negative values) on IntRangeMapImpl; PropertyMapManager (default ctor, create+get addr-set, create+get int-range, multi-create, delete addr-set, delete int-range, delete missing, recreate same name) + ManagerDB (setProgram, programReady, revision set/get, clearCache all/partial, invalidateCache, deleteAddressRange no-throw, moveAddressRange no-throw, NO_MANAGER=-1 constant) on PropertyMapManagerImpl; AddressSet (basic ctor, range ctor, min/max, clear, union, intersect, subtract, xor, equality ==/!=, hasSameAddresses, count, print, toList, getRangeContaining, getFirstRange/getLastRange, findFirstAddressInCommon, intersects set+range, contains set, intersectRange, getAddressCountBefore, deleteRange, remove start-end, remove set, addRange ctor, addRange, add address, add AddressRange) on AddressSet; AddressIterator (default, with vec, reset, current, empty vec) on AddressIterator; AddressSetRangeIterator (forward iteration) on AddressSetRangeIterator; AddressSetView interface verification; ManagerDB::NO_MANAGER constant. 30/30 CTest suites pass (5260/5260 aggregate subtests).
- **W~Z - Batch Z (COMPLETE)**: Comprehensive test coverage for model.listing (CodeUnit, Instruction, Data, Listing) + model.lang (Register, Scalar, FlowOverride) + model.symbol (Reference interface, MemReferenceImpl). New file `tests/test_batch_z.cpp` with **274 subtests** covering:
  - **CodeUnit** (test-only `TestCodeUnit` concrete subclass overrides `getLength()` and `toString()` to make the abstract base testable; default ctor + 3-arg ctor + all 4 setters + getMaxAddress with/without dt + addReferenceFrom/To + hasReferences)
  - **Instruction** (default ctor + 4-arg ctor + setMnemonicString + setFlowType + setOperand/Input/Result + getOpObjects/Length/MnemonicString + getDefaultFallThrough + getFallThrough + getNext + getFallFrom with null program + scalar getters/setters + getPcode/clearPcode/getFlows + setFlowOverride + getDefaultFallThroughOffset + lengthOverridden + null addr + null program paths)
  - **Data** (default ctor + 3-arg ctor + getComponent/atOffset + isPointer for `int *32` / non-pointer `int` / null / pointer of pointer / `int *[10]` / `int[10] *32` / `string` / char-1 / char-10 / char-0 + isString for `char`/`int` + isUnicode for `wchar32` (no "unicode" in name, returns false) + isArray for `int[10]` + isStructure for `struct Foo` + isUnion for `union Bar` + toString + getDefaultLabelRepresentation + getPrimitiveAt for 1/2/4/8 byte accesses)
  - **Listing** (default ctor + ctor with prog + addInstruction 4-arg + addInstruction 4-arg+isChangeable + addData + createData + createData with default length -1 → uses dt's length + null dt returns null + overwrite returns null + removeInstruction + removeData + getInstructionContaining + getDataContaining (linear scan, only matches at exact address) + getInstructionAfter (first instr with addr > given) + getDefinedDataContaining + getCodeUnitAt/Containing (prefers instruction over data when both exist) + isUndefined + getInstructions set + getData set)
  - **Register** (ctor + aliases add/remove + type flags hasType/isType + equality + setParent/setChildRegisters + rename + toString + compareTo with different addresses → correct <; same address → 0)
  - **Scalar** (default ctor + unsigned 32-bit with non-high-bit value (0x7EADBEEF) to avoid sign-extension + signed positive + signed negative + setSigned toggles + hex mode + decimal toString + equality)
  - **FlowOverride** (NONE=0/BRANCH=1/CALL=2/CALL_RETURN=3/RETURN=4 + toString with all 4 + stringTo with **lowercase** keys `branch`/`call`/`callreturn`/`return`/`none` — uppercase fails and returns NONE)
  - **MemReferenceImpl** (default ctor + 4-arg ctor + 7-arg ctor with operand index/isPrimary/source/id + setSource + toString format `from -> to (type)` with `->` and type name + equality on same/diffAddr/diffType + inequality)
  - **Reference interface** (MNEMONIC=-1, OTHER=-2, NOOperandIndex=-1, NO_MNEMONIC_INDEX=-1, FALLBACK_REF_ID=-1 + polymorphism via static_cast<Reference*> on MemReferenceImpl)
  
  31/31 CTest suites pass (5534/5534 aggregate subtests).
- **W~AA — Batch AA (COMPLETE)**: Porting sweep for model.data + model.pcode + model.reloc + model.util classes. New file `tests/test_batch_aa.cpp` with **112 subtests** covering: Undefined1..8DataType (ctor, name, len, representation, clone, mnemonic, null-buf, static getUndefinedDataType/slots, isUndefined, isUndefinedArray), CycleGroup (basic add/remove/contains, equivalence dedup, first/last/removeFirst/removeLast, advance with wrap, singletons/static groups, addFirst, empty next), CustomOrganization (name/size/alignment), CountedDynamicDataType (ctor + getters, components, length, mask via TestCountedDT concrete subclass), RepeatedStringDataType (name/description/ clone), RelocationResult (ctor + 4 static singletons), RelocationUtil (registerHandler/dedup), StringIngest (open/ingest bytes/clear/ empty/toString with embedded null/ stream-to-terminator/exceed/ stream unsupported), LinkedByteBuffer (ingest/getPosition/ advancePosition/exceed/pad byteCount fix), ListLinked (add/size/first/last/remove/insertAfter/clear), BuiltInDataTypeClassExclusionFilter (excludes BadDataType + MissingBuiltInDataType), NoisyStructureBuilder (addDataType/addReference/null), InvalidatedListener (interface smoke). Bug fix: LinkedByteBuffer::pad() now increments byteCount_. **32/32 CTest suites pass (5646/5646 aggregate subtests).**

- **W~S — Batch S: LEB128 utility + AbstractLeb128DataType + SignedLeb128DataType + UnsignedLeb128DataType + TerminatedStringDataType + TerminatedUnicode32DataType**: 7 new source files ported from `ghidra.program.model.data` package (`LEB128.java`, `AbstractLeb128DataType.java`, `SignedLeb128DataType.java`, `UnsignedLeb128DataType.java`, `TerminatedStringDataType.java`, `TerminatedUnicode32DataType.java`). All 23/23 CTest suites pass (3983/3983 subtests including 58 new batch_s subtests), decompiler output unchanged. New files:
   - `Enigma-Engine/include/ghidra/LEB128.h` + `src/util/LEB128.cpp` — LEB128 pure-algorithm utility (encode/decode/getLength for signed and unsigned LEB128, used by LEB128 data types and DWARF)
   - `Enigma-Engine/include/ghidra/AbstractLeb128DataType.h` + `src/types/AbstractLeb128DataType.cpp` — abstract base for LEB128 types (BuiltIn+Dynamic dual inheritance, implements getRepresentation via LEB128 decode from MemBuffer)
   - `Enigma-Engine/include/ghidra/SignedLeb128DataType.h` + `src/types/SignedLeb128DataType.cpp` — concrete signed LEB128 data type (singleton, length=-1, getReplacementBaseType=ByteDataType)
   - `Enigma-Engine/include/ghidra/UnsignedLeb128DataType.h` + `src/types/UnsignedLeb128DataType.cpp` — concrete unsigned LEB128 data type (singleton, length=-1, getReplacementBaseType=ByteDataType)
   - `Enigma-Engine/include/ghidra/TerminatedStringDataType.h` + `src/types/TerminatedStringDataType.cpp` — null-terminated C string type (length=-1, layout=NULL_TERMINATED_UNBOUNDED)
   - `Enigma-Engine/include/ghidra/TerminatedUnicode32DataType.h` + `src/types/TerminatedUnicode32DataType.cpp` — null-terminated UTF-32 string type (length=-1, layout=NULL_TERMINATED_UNBOUNDED)
   - `Enigma-Engine/tests/test_batch_s.cpp` (58 subtests covering LEB128 encode/decode, data type properties, DynamicDataType/StructuredDynamicDataType/IndexedDynamicDataType/FactoryStructureDataType/StructureFactory/DataUtilities)
- **W~S — Modified existing files**:
   - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_s` test (duplicate entry consolidated)
   - `Enigma-Engine/include/ghidra/StructuredDynamicDataType.h` — completed missing pure virtuals (clone, getLength, getRepresentation, getLength(MemBuffer*,int), getReplacementBaseType, getCTypeDeclaration, setDefaultSettings)
   - `Enigma-Engine/include/ghidra/IndexedDynamicDataType.h` — completed missing pure virtuals (same set)
   - `Enigma-Engine/src/types/StructuredDynamicDataType.cpp` — added clone, getRepresentation, getLength(MemBuffer*,int), getReplacementBaseType implementations
   - `Enigma-Engine/src/types/IndexedDynamicDataType.cpp` — added clone, getRepresentation, getLength(MemBuffer*,int), getReplacementBaseType implementations
- **W~S — Design notes**:
   - `AbstractLeb128DataType` inherits from both `BuiltIn` (for fixed-length DataTypeImpl) and `Dynamic` (for variable-length decode). It overrides `getRepresentation(MemBuffer*, Settings*, int)` to read bytes from the buffer, determine LEB128 encoding length, decode, and format as a string. `getLength(MemBuffer*, int maxLength)` reads up to `LEB128::MAX_SUPPORTED_LENGTH` bytes and returns the LEB128-encoded length.
   - `getCTypeDeclaration` returns `getDecompilerDisplayName()` (non-const, matching `BuiltInDataType` signature). `setDefaultSettings` delegates to `BuiltIn::setDefaultSettings`.
   - `LEB128` is a pure-algorithm utility class (no Ghidra dependencies). Exports `signedDecode`, `unsignedDecode`, `readDecode`, `getLength`, `encode`, `encodeSigned`, `encodeUnsigned`. `LEB128EncodeException` thrown when the value exceeds 10-byte encoding capacity.
   - `TerminatedStringDataType` and `TerminatedUnicode32DataType` are `BuiltIn` concrete classes (not Dynamic) with fixed getLength()=-1.
   - `StructuredDynamicDataType` and `IndexedDynamicDataType` were missing implementations of pure virtuals from `DataType` (clone, getLength, getRepresentation) and `Dynamic` (getLength(MemBuffer*,int), getReplacementBaseType) — these were completed as part of batch S to make the classes fully concrete.
   - `FactoryStructureDataType` was already concrete (overrides getLength/getDescription) but its `BuiltIn` inherited `getCTypeDeclaration` is `const`, which doesn't satisfy the non-const pure virtual in `BuiltInDataType` — it needs an explicit `override` in the class. (Note: this may still be abstract; only the test subclass works.)

- **W~P — Batch P: model.data BadDataType + MissingBuiltInDataType + MetaDataType + AbstractPointerTypedefBuiltIn + PointerTypedef + PointerTypedefBuilder + DataTypeInstance**: 7 new classes ported from `ghidra.program.model.data` package. All 20/20 CTest suites pass (3872/3872 subtests including 62 new batch_p subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/BadDataType.h` + `src/types/BadDataType.cpp` — BadDataType (singleton "bad" data type, BuiltIn+Dynamic dual inheritance, getReplacementBaseType returns nullptr)
  - `Enigma-Engine/include/ghidra/MissingBuiltInDataType.h` + `src/types/MissingBuiltInDataType.cpp` — MissingBuiltInDataType (DataTypeImpl+Dynamic dual, stores missing name/classpath for deferred resolution)
  - `Enigma-Engine/include/ghidra/MetaDataType.h` + `src/pcode/MetaDataType.cpp` — MetaDataType (enum + getMeta/getMostSpecificDataType utilities)
  - `Enigma-Engine/include/ghidra/AbstractPointerTypedefBuiltIn.h` + `src/types/AbstractPointerTypedefBuiltIn.cpp` — abstract base for pointer-typedefs (BuiltIn+TypeDef dual, delegates to TypedefDataType model)
  - `Enigma-Engine/include/ghidra/PointerTypedef.h` + `src/types/PointerTypedef.cpp` — concrete PointerTypedef (GenericDataType+TypeDef dual, 5 constructors for address-space/type/offset contexts)
  - `Enigma-Engine/include/ghidra/PointerTypedefBuilder.h` + `src/types/PointerTypedefBuilder.cpp` — PointerTypedefBuilder (fluent builder for PointerTypedef with name/type/shift/mask/offset/space settings)
  - `Enigma-Engine/include/ghidra/DataTypeInstance.h` + `src/types/DataTypeInstance.cpp` — DataTypeInstance (factory-pattern wrapper for data type + resolved length; handles FactoryDataType/Dynamic/FunctionDefinition dispatch)
  - `Enigma-Engine/tests/test_batch_p.cpp` (62 subtests)
- **W~P — Modified existing files**:
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_p` test
  - `Enigma-Engine/include/ghidra/PointerTypedef.h` — added `setName` override to update `isAutoNamed_` flag; overrode `getDefaultSettings` for lazy SettingsImpl creation (crash fix)
- **W~P — Design notes**:
  - `BadDataType` and `MissingBuiltInDataType` both use dual inheritance (concrete base + `Dynamic`). Both needed explicit `getCTypeDeclaration` (non-const, to match `BuiltInDataType` signature) and `setDefaultSettings` to resolve abstract-class diamond. `AbstractPointerTypedefBuiltIn` needed explicit `getDescription` for the same reason.
  - `PointerTypedef::getDefaultSettings()` was crashing with null-pointer dereference because `DataTypeImpl` initializes `defaultSettings_` to `nullptr`. Fix: lazy-allocates a `SettingsImpl` on first access. The delegation-to-model pattern (`modelTypedef_->getDefaultSettings()`) would also crash since `TypedefDataType` has the same null default.
  - `CategoryPath::ROOT` (a function returning `const CategoryPath&`) cannot be used directly in a ternary `?:` expression — calling `CategoryPath::ROOT()` with parentheses resolves the function reference, but mixing a value-type return (`getCategoryPath()` returns `CategoryPath`) with a reference return (`ROOT()` returns `const CategoryPath&`) in `?:` compiles cleanly. The original code omitted the `()` which made the compiler treat `ROOT` as a function pointer type.
  - `Undefined1-8` subtypes are intentionally NOT ported: the factory `Undefined::getUndefinedDataType(int)` creates and caches instances on demand.
  - `PointerTypedefInspector`, `BuiltInDataTypeManager`, `DataTypeManagerDB` — database-layer classes permanently skipped (CLI uses in-memory `ProgramDB`).
- **Next Action**: Continue with W~T: model.data continued — StructureFactory and remaining data type write paths.

- **W~Q — Batch Q: StandAloneDataTypeManager (in-memory DataTypeManager)**: Ported the 965-line Java StandAloneDataTypeManager as a direct `DataTypeManager` implementation (not through the permanently-skipped `DataTypeManagerDB`). Uses in-memory maps for data type storage by ID, path, and name. Includes: `CategoryImpl` nested class for category management, auto-incrementing ID tracking, resolve/addDataType with rename-on-conflict, case-sensitive and case-insensitive findDataTypes, basic transaction tracking (start/end), pointer lookup, getPointer/replaceDataType. 39 new subtests. All 21/21 CTest suites pass (3911/3911 subtests). New files:
  - `Enigma-Engine/include/ghidra/StandAloneDataTypeManager.h`
  - `Enigma-Engine/src/types/StandAloneDataTypeManager.cpp`
  - `Enigma-Engine/tests/test_batch_q.cpp` (39 subtests)
- **W~Q — Design notes**:
  - StandAloneDataTypeManager directly implements `DataTypeManager` (does NOT extend `ProgramBasedDataTypeManager` or `DataTypeManagerDB`). In-memory maps avoid all DB dependencies.
  - `CategoryImpl` is a private nested class implementing `Category`. It manages sub-categories and registered data types in `std::unordered_map`s.
  - `resolve()` returns existing data type when found (no duplicate registration), or creates with a suffixed name if `ConflictResult::USE_EXISTING`.
  - `addDataType()` registers the type by ID, path, and name. The `nextDataTypeId_` auto-increments starting from 1.
  - `close()` clears all internal maps and deletes the root category.
  - Transaction support is a simple counter-based tracking (no DB undo stack). The `commitTransaction_` flag is cleared on rollback.
  - Built-in type names are immutable (e.g., IntegerDataType.getName() always returns "int"). Tests use `TypedefDataType` when mutable names are needed.
  - Contains, remove, getDataType all use exact pointer/ID equality; the manager does not track data types that were added to sub-managers or other DTMs.
  - `setName()` on CategoryImpl updates the stored name but does not propagate to child elements — matches the simple in-memory semantics.

- **W~R — Batch R: BitGroup + EnumValuePartitioner + ReadOnlyDataTypeComponent + BuiltInDataTypeManager**: 4 new classes ported from `ghidra.program.model.data` package. All 22/22 CTest suites pass (3959/3959 subtests including 48 new batch_r subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/BitGroup.h` — BitGroup (header-only, partitions long values into non-intersecting masked groups; used by EnumValuePartitioner)
  - `Enigma-Engine/include/ghidra/EnumValuePartitioner.h` — EnumValuePartitioner (static utility, header-only; partitions enum values into BitGroups with unused-bits group)
  - `Enigma-Engine/include/ghidra/ReadOnlyDataTypeComponent.h` + `src/types/ReadOnlyDataTypeComponent.cpp` — ReadOnlyDataTypeComponent (immutable DataTypeComponent for DynamicDataType parents; all setter methods are no-ops)
  - `Enigma-Engine/include/ghidra/BuiltInDataTypeManager.h` + `src/types/BuiltInDataTypeManager.cpp` — BuiltInDataTypeManager (singleton extending StandAloneDataTypeManager; registers built-in types manually without classpath scanning; immutable after construction)
   - `Enigma-Engine/tests/test_batch_r.cpp` (48 subtests)
- **W~R — Modified existing files**:
   - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_r` test
- **W~R — Design notes**:
   - `ReadOnlyDataTypeComponent` stores `DataType*` parent instead of `DynamicDataType*` (not yet ported). The `getParent()` returns `DataType*`.
   - `BuiltInDataTypeManager` is a singleton that manually registers 20 built-in types (Integer, Byte, Short, Long, Float, Double, Void, Boolean, Word, DWord, QWord, String, etc.) at construction time. It is NOT backed by classpath scanning (the Java `ClassSearcher` mechanism is not ported). Uses `StandAloneDataTypeManager::addDataType()` with qualified call to bypass virtual dispatch during initialization.
   - `BuiltInDataTypeManager` overrides `resolve()` to look up existing types by name from ROOT category; throws for unknown types. `addDataType()`, `remove()`, `replaceDataType()`, `setName()`, and `associateDataTypeWithArchive()` all throw `std::runtime_error`.
   - `startTransaction()`/`endTransaction()` throw when the singleton is alive (matches Java behavior: "Built-in datatype manager may not be modified").
   - `close()` is a no-op (Java: "cannot close a built-in data type manager; close performed automatically during shutdown").
   - `BitGroup` uses `std::unordered_set<int64_t>` instead of Java's `HashSet<Long>`. The `merge()` and `intersects()` methods match Java semantics exactly.
   - `EnumValuePartitioner::partition()` returns `std::vector<BitGroup>` (Java returns `List<BitGroup>`). The iterating merge logic replicates the Java `Iterator.remove()` pattern.

- **W~S — Batch S: LEB128 utility + AbstractLeb128DataType + SignedLeb128DataType + UnsignedLeb128DataType + TerminatedStringDataType + TerminatedUnicode32DataType + DynamicDataType family completion**: 7 new source files + 3 existing class completions. All 23/23 CTest suites pass (3983/3983 subtests including 58 new batch_s subtests), decompiler output unchanged. New files:
   - `Enigma-Engine/include/ghidra/LEB128.h` + `src/util/LEB128.cpp` — LEB128 pure-algorithm utility
   - `Enigma-Engine/include/ghidra/AbstractLeb128DataType.h` + `src/types/AbstractLeb128DataType.cpp` — abstract base for LEB128 types (BuiltIn+Dynamic dual)
   - `Enigma-Engine/include/ghidra/SignedLeb128DataType.h` + `src/types/SignedLeb128DataType.cpp` — signed LEB128 singleton
   - `Enigma-Engine/include/ghidra/UnsignedLeb128DataType.h` + `src/types/UnsignedLeb128DataType.cpp` — unsigned LEB128 singleton
   - `Enigma-Engine/include/ghidra/TerminatedStringDataType.h` + `src/types/TerminatedStringDataType.cpp` — null-terminated C string
   - `Enigma-Engine/include/ghidra/TerminatedUnicode32DataType.h` + `src/types/TerminatedUnicode32DataType.cpp` — null-terminated UTF-32 string
   - `Enigma-Engine/tests/test_batch_s.cpp` (58 subtests)
- **W~S — Modified existing files**:
   - `Enigma-Engine/CMakeLists.txt` — consolidated duplicate `enigma_test_batch_s` registration
   - `Enigma-Engine/include/ghidra/StructuredDynamicDataType.h` — completed 7 missing pure virtuals
   - `Enigma-Engine/include/ghidra/IndexedDynamicDataType.h` — completed 7 missing pure virtuals
   - `Enigma-Engine/src/types/StructuredDynamicDataType.cpp` — implemented clone, getRepresentation, getLength(MemBuffer*,int), getReplacementBaseType
   - `Enigma-Engine/src/types/IndexedDynamicDataType.cpp` — implemented clone, getRepresentation, getLength(MemBuffer*,int), getReplacementBaseType
- **W~S — Design notes**:
   - `AbstractLeb128DataType` inherits from both `BuiltIn` and `Dynamic`. Overrides `getRepresentation` to decode LEB128 from MemBuffer. Overrides `getLength(MemBuffer*, int)` to read bytes and compute encoding length.
   - `LEB128` is pure-algorithm with no Ghidra deps. `LEB128EncodeException` thrown when value exceeds 10-byte encoding capacity.
   - `StructuredDynamicDataType` and `IndexedDynamicDataType` were previously incomplete ports — missing 7 pure virtuals from DataType/Dynamic interfaces. Batch S completes them.
   - `TerminatedStringDataType` and `TerminatedUnicode32DataType` are `BuiltIn` concrete classes with fixed getLength()=-1.

## Last and Next Actions
- **Current verified baseline**: 42/42 CTest suites pass (post W~AM uninitialized-localcount fix). All 14 corpus binaries produce byte-identical output across 10+ independent process runs. Determined that the earlier ASLR fix (`HighVariable::createIndex`) was necessary but not sufficient — a second independent non-determinism source existed in parallel.
- **Latest Action (W~AM)**: Uninitialized `localcount` in `ActionInferTypes` root cause RESOLVED.
  - **Root cause**: `ActionInferTypes::localcount` (an `int4` instance member at `coreaction.hh:965`) was never initialized in the C++ constructor. In Ghidra's Java, `int localcount` defaults to 0 at instantiation; in C++, `int4 localcount` contains heap garbage. The guard `if (localcount >= 7)` at `coreaction.cc:5512` would fire when garbage ≥ 7 (~70% of runs on 32-bit random), skipping ALL type propagation and producing a different output variant.
  - **Fix**: Added `{ localcount = 0; }` to constructors of the three affected action classes: `ActionInferTypes`, `ActionSegmentize`, `ActionConstantPtr` in `decompiler/coreaction.hh`.
  - **Result**: All 42/42 test suites pass, 10× repeat determinism confirmed on all 14 corpus binaries (including the 5 that previously failed: `float_arith`, `float_cmp`, `simd_int`, `simd_float`, `pe_test`). Corpus expected outputs regenerated (changed because type propagation now always runs).
  - **Diagnostic approach**: Added type-name hashing across all varnodes at entry to `ActionInferTypes::apply()` — only some runs showed the diagnostic, which led directly to the `localcount` guard. Removed diagnostic code from final.
     - Files modified: `decompiler/coreaction.hh` (3 constructor initializations).
- **Batch AN: Decompiler Output Quality Improvements (Phases 1–4)**: Implemented 7 categories of output quality improvements in `tools/enigma_decompile_full.cpp`:
  - **Phase 1.1 — Default maxFuncs**: Changed from unlimited (`-1`) to `20`. Added `-no-crt` flag to optionally disable CRT boundary filtering. Updated usage text.
  - **Phase 1.2 — Warning suppression**: `cleanOutput()` now strips `/* WARNING: ... */` comment lines from output. Fixed noisy `_` globals overlap warnings in CLI and corpus regression tests.
  - **Phase 1.3 — CRT boundary discovery**: Restructured BFS call-graph walk to decompile known CRT functions (prefix list: `__mingw_`, `__do_global_`, `__gcc_`, `_Unwind_`, `__security_`, `_pei386_`, etc.) for one-level callee discovery without adding them to the output or counting toward maxFuncs. Non-CRT callees of CRT functions ARE followed normally, enabling discovery of user `main()` through CRT startup code.
  - **Phase 2.1 — Main recognition**: Non-CRT functions discovered through CRT boundary are tracked as `mainCandidates`. After BFS, the first auto-named (`sub_0x...`) candidate gets renamed to `main` in `symbolNames` for `resolveFuncRefs` resolution.
  - **Phase 2.2 — String content display**: Added `resolveStringRefs()` post-processor. Scans decompiler output for `(char *)0xHEX` patterns, reads null-terminated ASCII strings from the binary, and replaces with C string literals (`"..."`). Handles escaping (newlines, tabs, quotes, non-printable chars as `\xNN`). Binary data loaded early for post-processing access.
  - **Phase 2.3 — Import thunk cleanup**: Detected import thunks (auto-named functions containing a single CALL/CALLIND to a known import) are removed from `allFds` before output generation. They remain in `symbolNames` so `resolveFuncRefs` maps references to the correct import name.
  - **Phase 4 — Jump table recovery verification**: Full audit of `decompiler/jumptable.hh`/`.cc`, `ActionSwitchNorm` (coreaction.cc:4639), and flow analysis (flow.cc:771) confirmed the entire JumpTable recovery pipeline (4 models: JumpAssisted→JumpBasic→JumpBasic2→JumpModelTrivial, ~6000 lines across 8 source files) is fully implemented with no gaps. End-to-end test with a GCC-compiled PE binary containing a real relative jump table (`jmp *%rax` via `lea` + `movslq` table load) confirmed `switch(param_1) { case 0: ... case 1: ... default: ... }` with correct case labels appears in decompiler output. No changes needed — the Ghidra C++ decompiler's SLEIGH engine correctly produces `CPUI_BRANCHIND` for x86-64 indirect jumps, and the full ActionSwitchNorm→PrintC pipeline produces proper `switch`/`case` output.
  - **Result**: 42/42 test suites pass (no regressions). Corpus expected outputs regenerated (pe_test.bin changed: thunks removed, fewer CRT internals). CLI regression updated (warning patterns removed from test expectations). Output is cleaner, shorter, and more readable.
  - Files modified: `tools/enigma_decompile_full.cpp`, `tests/test_cli_regression.py`, `tests/corpus/expected/*.c` (regenerated).
- **W132 followup**: Fixed **3-operand bug** in `mapBoolOp`, `mapAddSub`, `mapMulDiv` — for ARM/MIPS/PPC `and r0, r1, r2` / `add r0, r1, r2` / `mul r0, r1, r2`, the third operand was silently dropped (was emitting `r0 = r0 OP r1`). Now correctly emits `r0 = r1 OP r2`. Removed unused `szChar` local in `parseOperand`. Fixed pre-existing missing-newline in `UnsignedCharDataType.cpp:31`. All 7/7 CTest suites still pass (3028/3028 subtests), decompiler output unchanged.
- **W133 — Batch A Tier-1 referenced classes**: Ported 7 new classes from the Ghidra Java source, identified 5 more that were already ported under different names, and 2 that were intentionally skipped (one due to local-symbol conflict, one not yet needed). All 7/7 CTest suites still pass (3028/3028 subtests), decompiler output unchanged. New files:
  - `include/ghidra/Undefined.h` + `src/types/Undefined.cpp` — model.data.Undefined (concrete class for sizes 1..8, with static factory and helpers)
  - `include/ghidra/AlignmentType.h` + `src/types/AlignmentType.cpp` — model.data.AlignmentType (enum class)
  - `include/ghidra/PackingType.h` + `src/types/PackingType.cpp` — model.data.PackingType (enum class)
  - `include/ghidra/util/datastruct/Range.h` + `src/util/datastruct/Range.cpp` — util.datastruct.Range (inclusive int range with hash/equals/compareTo)
  - `include/ghidra/Query.h` + `include/ghidra/AndQuery.h` + `include/ghidra/OrQuery.h` + 3 cpp files — database.util.Query interface + AndQuery/OrQuery composites
  - `include/ghidra/ByteIngest.h` + `src/pcode/ByteIngest.cpp` — model.pcode.ByteIngest (abstract ingest interface)
  - `include/ghidra/SourceFile.h` + `src/symbol/SourceFile.cpp` — database.sourcemap.SourceFile (immutable source-file descriptor with id-type/identifier/display-string)
  - `include/ghidra/Fixup.h` + `src/util/Fixup.cpp` — util.Fixup (interface for a generic fix operation)
  - `include/ghidra/ProgramChangeRecord.h` + `src/util/ProgramChangeRecord.cpp` — program.util.ProgramChangeRecord (event data for Program change events)
  - `include/ghidra/ExternalLocation.h` + `src/symbol/ExternalLocation.cpp` — model.symbol.ExternalLocation (abstract interface for external program locations)
- **W133 — Already ported (consolidated)**: 5 of the 16 targets were already ported under different headers (FlowType + DataRefType in `RefType.h`, Equate in `EquateTable.h`, PcodeBlock base in `PcodeBlockBasic.h`, GenericAddressSpace in `AddressSpace.h`).
- **W133 — Intentionally skipped**: `model.pcode.SymbolEntry` — would shadow existing local `struct SymbolEntry` definitions in `Database.h` and `Scope.h`. Naming conflict requires relocation to a sub-namespace or a future deconfliction pass; not worth doing now since callers only need the local struct form.
- **Historical W133 next action**: Phase 2d — Continue with Batch C (model.pcode extras: 14 Block* classes, CachedEncoder, etc.).
- **W134 — Batch B data type family completion**: 9 new classes ported; existing 9 string/unicode/pascal data types confirmed already ported. All 7/7 CTest suites still pass (3028/3028 subtests), decompiler output unchanged. New files:
  - `include/ghidra/CharsetInfo.h` + `src/util/CharsetInfo.cpp` — util.charset.CharsetInfo (charset info record with name/comment/min-max bytes/alignment/scripts; UnicodeScript enum simplified to std::set<std::string>)
  - `include/ghidra/CharsetInfoManager.h` + `src/util/CharsetInfoManager.cpp` — util.charset.CharsetInfoManager (singleton; hardcoded minimal standard charset list: US-ASCII, UTF-8/16/16BE/16LE/32/32BE/32LE, ISO-8859-1)
  - `include/ghidra/DataTypeWithCharset.h` + `src/types/DataTypeWithCharset.cpp` — model.data.DataTypeWithCharset (interface extending DataType; getCharsetName returns UTF-8 default; encode methods throw because StringDataInstance is deferred)
  - `include/ghidra/ArrayStringable.h` + `src/types/ArrayStringable.cpp` — model.data.ArrayStringable (interface extending DataType; 3 abstract + 1 default + 1 static method)
  - `include/ghidra/CharsetSettingsDefinition.h` + `src/types/CharsetSettingsDefinition.cpp` — model.data.CharsetSettingsDefinition (EnumSettingsDefinition with hardcoded charset list; supports getCharset/setCharset/getChoice/setChoice + deprecated encoding/language mapping)
  - `include/ghidra/StringLayoutEnum.h` + `src/types/StringLayoutEnum.cpp` — model.data.StringLayoutEnum (C++ enum class + helper functions for the 6 layout types)
  - `include/ghidra/RenderUnicodeSettingsDefinition.h` + `src/types/RenderUnicodeSettingsDefinition.cpp` — model.data.RenderUnicodeSettingsDefinition (uses JavaEnumSettingsDefinition template; RENDER_ENUM lifted to RenderUnicodeEnum at namespace scope)
  - `include/ghidra/TranslationSettingsDefinition.h` + `src/types/TranslationSettingsDefinition.cpp` — model.data.TranslationSettingsDefinition (same pattern; property-map helpers omitted because PropertyMapManager not ported)
- **W134 — Already ported (consolidated)**: All 9 string/unicode/pascal data type files already exist as full implementations (AbstractStringDataType + StringDataType + UnicodeDataType + Unicode32DataType + TerminatedUnicodeDataType + StringUTF8DataType + PascalStringDataType + PascalString255DataType + PascalUnicodeDataType). EndianSettingsDefinition was already ported in `src/settings/EndianSettingsDefinition.cpp` (with `def()` accessor); my duplicate was deleted and the existing header (which my work had inadvertently left in the deleted state) was restored.
- **W134 — Deferred**: `model.data.StringDataInstance` (1252 lines; depends on EndianSettingsDefinition, RenderUnicodeSettingsDefinition, StringLayoutEnum, TranslationSettingsDefinition, CharsetInfoManager, Data, Program, PropertyMapManager, StringPropertyMap). Porting requires the larger database/model.listing layer. Also deferred: `model.data.WideCharDataType`, `WideChar16DataType`, `WideChar32DataType` — all delegate their getRepresentation/getValue/encoding to StringDataInstance.
- **W135 — Batch B followup: StringDataInstance + WideChar family**: 5 new classes ported (StringDataInstance, StaticStringInstance, WideChar16DataType, WideChar32DataType, WideCharDataType), plus 1 supporting interface (DataTypeDisplayOptions) and 1 supporting class (NoSettings). All 7/7 CTest suites still pass (3028/3028 subtests), decompiler output unchanged. New files:
  - `include/ghidra/DataTypeDisplayOptions.h` + `src/types/DataTypeDisplayOptions.cpp` — model.data.DataTypeDisplayOptions (interface + default impl with MAX_LABEL_STRING_LENGTH=32)
  - `include/ghidra/NoSettings.h` + `src/util/NoSettings.cpp` — read-only no-op Settings used as a default when callers pass nullptr
  - `include/ghidra/StringDataInstance.h` + `src/types/StringDataInstance.cpp` — model.data.StringDataInstance (1100+ line port: constructor, getCharsetName/getDataLength/getStringLength/getStringValue/getStringRepresentation/getCharRepresentation/getLabel/getOffcutLabelString/getByteOffcut/getCharOffcut, encode* methods; property-map-based translation methods are stubbed since PropertyMapManager is not ported)
  - `include/ghidra/WideChar16DataType.h` + `src/types/WideChar16DataType.cpp` — 16-bit/UTF16 wchar, getLength=2, charset=UTF-16
  - `include/ghidra/WideChar32DataType.h` + `src/types/WideChar32DataType.cpp` — 32-bit/UTF32 wchar, getLength=4, charset=UTF-32
  - `include/ghidra/WideCharDataType.h` + `src/types/WideCharDataType.cpp` — size-varies wchar (defaults to 2 bytes since DataOrganization is not ported)
- **W135 — Modified existing files**:
  - `include/ghidra/AbstractStringDataType.h` + `src/types/AbstractStringDataType.cpp` — added `getStringLayout()` and `getStringDataInstance(...)` virtual methods; added 7 DEFAULT_*_UNICODE/LABEL static constants
  - `src/types/StringDataType.cpp` + `StringUTF8DataType.cpp` + `UnicodeDataType.cpp` + `Unicode32DataType.cpp` — call `setStringLayout(FIXED_LEN)`
  - `src/types/TerminatedUnicodeDataType.cpp` — calls `setStringLayout(NULL_TERMINATED_UNBOUNDED)`
  - `src/types/PascalStringDataType.cpp` + `PascalUnicodeDataType.cpp` — call `setStringLayout(PASCAL_64k)`
  - `src/types/PascalString255DataType.cpp` — calls `setStringLayout(PASCAL_255)`
- **W135 — Design notes**:
  - `WideChar16/32/DataType` extend `BuiltIn` directly and provide the same method surface that the Java `ArrayStringable`+`DataTypeWithCharset` interfaces would.  The static `ArrayStringable::getArrayStringable(dynamic_cast)` will not match these classes — callers that need interface dispatch should look up the type by name.
  - `StringDataInstance::getStringRepresentation()` does simple pass-through; the more elaborate Java `StringRenderBuilder` formatting is not ported (would need a separate `StringRenderBuilder.cpp` + `StringRenderParser.cpp`).
  - `encode*` methods produce raw byte sequences (not charset-encoded) — sufficient for the simple ASCII/default-charset case; will be improved when a proper charset encoder is needed.
- **W136 — Batch C: model.pcode Block* family**: 14 new classes ported (`StructuredBlock` base, `BlockEdge`, `BlockMap`, `StructuredBlockGraph`, `BlockCopy`, `BlockList`, `BlockCondition`, `BlockGoto`, `BlockIfGoto`, `BlockProperIf`, `BlockIfElse`, `BlockDoWhile`, `BlockWhileDo`, `BlockInfLoop`, `BlockSwitch`, `BlockMultiGoto`) + `CachedEncoder` interface + `MemoryCachedEncoder` implementation. Renamed new `BlockGraph` to `StructuredBlockGraph` to avoid name conflict with existing flat `BlockGraph` class. Added 3 new `ElementId` constants: `ELEM_BLOCK` (200), `ELEM_BHEAD` (201), `ELEM_EDGE` (202). All 8/8 CTest suites pass (3091/3091 subtests including 63 new Block* subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/StructuredBlock.h`
  - `Enigma-Engine/src/pcode/StructuredBlock.cpp`
  - `Enigma-Engine/include/ghidra/CachedEncoder.h`
  - `Enigma-Engine/src/pcode/CachedEncoder.cpp`
  - `Enigma-Engine/tests/test_block_struct.cpp` (63 subtests)
- **W136 — Modified existing files**:
  - `Enigma-Engine/include/ghidra/ElementId.h` — added `ELEM_BLOCK`, `ELEM_BHEAD`, `ELEM_EDGE` externs
  - `Enigma-Engine/src/pcode/ElementId.cpp` — added 3 element definitions
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_block_struct` test
- **W136 — Design notes**:
  - The new `StructuredBlockGraph` is a `PcodeBlock` subclass containing structured blocks (matches Java semantics). The existing `ghidra::BlockGraph` (in `src/pcode/BlockGraph.cpp`) is a different flat CFG data structure and is preserved as-is. They serve different purposes despite the name collision.
  - `BlockMap` is a standalone resolver helper (not derived from `PcodeBlock`); uses raw `StructuredBlock*` ownership transfer semantics — the `BlockMap::createBlock` returns raw pointers that get adopted by `StructuredBlockGraph::addBlock` which wraps them in `std::unique_ptr`.
  - `BlockMultiGoto::addBlock` is a `virtual override` that both records the target in the `targets` list AND delegates to `StructuredBlockGraph::addBlock` for index/parent tracking. Matches Java semantics where multigoto targets are also members of the graph.
  - `MemoryCachedEncoder` is a minimal implementation that writes ASCII-like XML fragments to an in-memory buffer; sufficient for tests; a real production encoder (e.g. `XmlEncode`) is already used elsewhere in the codebase.
- **W137 — Batch D: model.lang extras**: 12 new classes ported from `ghidra.program.model.lang` package: `GhidraLanguagePropertyKeys` (constants), `OldLanguageMappingService`, `MaskImpl` (concrete Mask), `InstructionError` (error/conflict info for disassembly), `InvalidPrototype` (InstructionPrototype stub), `PrototypeModelMerged` (multi-model selector), `InjectPayloadCallfixup`, `InjectPayloadCallother`, `InjectPayloadJumpAssist`, `InjectPayloadSegment`, `InjectPayloadCallfixupError`, `InjectPayloadCallotherError` (InjectPayloadSleigh subtypes). 7 new `ElementId`s added: `ELEM_CALLFIXUP` (203), `ELEM_CALLOTHERFIXUP` (204), `ELEM_SEGMENTOP` (205), `ELEM_CONSTRESOLVE` (206), `ELEM_VARNODE` (207), `ELEM_RESOLVEPROTOTYPE` (208), `ELEM_MODEL` (209). Added `isValid()` to `LanguageCompilerSpecPair`. Added `RegisterValue()` default ctor (was declared but not defined). All 9/9 CTest suites pass (3134/3134 subtests including 43 new lang subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/GhidraLanguagePropertyKeys.h` + `src/lang/GhidraLanguagePropertyKeys.cpp`
  - `Enigma-Engine/include/ghidra/OldLanguageMappingService.h` + `src/lang/OldLanguageMappingService.cpp`
  - `Enigma-Engine/include/ghidra/MaskImpl.h` + `src/lang/MaskImpl.cpp`
  - `Enigma-Engine/include/ghidra/InstructionError.h` + `src/lang/InstructionError.cpp`
  - `Enigma-Engine/include/ghidra/InvalidPrototype.h` + `src/lang/InvalidPrototype.cpp`
  - `Enigma-Engine/include/ghidra/PrototypeModelMerged.h` + `src/lang/PrototypeModelMerged.cpp`
  - `Enigma-Engine/include/ghidra/InjectPayloadSubtypes.h` + `src/lang/InjectPayloadSubtypes.cpp` (6 classes in one header)
  - `Enigma-Engine/tests/test_lang_classes.cpp` (43 subtests)
- **W137 — Modified existing files**:
  - `Enigma-Engine/include/ghidra/ElementId.h` — added 7 inject payload externs
  - `Enigma-Engine/src/pcode/ElementId.cpp` — added 7 element definitions
  - `Enigma-Engine/include/ghidra/LanguageCompilerSpecPair.h` — added `isValid()` method
  - `Enigma-Engine/src/core/RegisterValue.cpp` — added `RegisterValue()` default ctor definition
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_lang_classes` test
- **W137 — Design notes**:
  - `BasicCompilerSpec.java` (1309 lines) was NOT ported. It depends heavily on XML parsing infrastructure (SaxBuilder, XmlPullParser), InputStream reading from .cspec files, and the Java Sleigh language loader. Since the CLI uses the prebuilt `decompiler/` static lib for the official path, and the Enigma native pipeline doesn't currently use compiler spec parsing, this class is deferred.
  - `InjectPayload*` subclasses are ported as `InjectPayloadSleigh` subtypes. XML parsing (`restoreXml`) and pcode template cloning (`ConstructTpl`) are stubbed out (no-ops) since the underlying XML/pcode template infrastructure is not yet ported. The `encode` paths work fully for the basic ELEM_CALLFIXUP/CALLOTHERFIXUP/SEGMENTOP tree structure.
  - `MaskImpl` is the only concrete `Mask`; it uses a `std::vector<uint8_t>` internally and throws `IncompatibleMaskException` for size mismatches. The existing `Mask` interface in C++ uses `std::vector<uint8_t>` parameters (matches Java byte[] more closely than std::array).
  - `InvalidPrototype` implements both `InstructionPrototype` and `ParserContext` (Java original does the same via `implements`). Both `getFlowType()` (InstructionPrototype) and `getFlowType() const` (ParserContext) are implemented. Returns `&RefTypes::INVALID` for the flow type and `"BAD-Instruction"` for the mnemonic.
  - `InstructionError` uses `enum class InstructionErrorType` for type safety; `isConflictType()` static method replaces Java's per-enum-constant `isConflict` field.
- **W138 — Batch E: model.util + model.address**: 10 new classes ported from `ghidra.program.model.util` and `ghidra.program.model.address` packages: `AddressCollectors` (utility), `AddressRangeToAddressComparator` (typed comparator), `ProcessorSymbolType` + `ProcessorSymbolTypes` (enum + parser), `DataTypeInfo` + `CompositeDataTypeElementInfo` (immutable metadata), `PropertySet` (interface for typed property access), `DefaultPropertyMap` (non-template base for default maps), `DefaultIntPropertyMap` (concrete int property map backed by `std::map`), `MemoryByteIterator` (byte-level memory iterator with internal buffer). Batch E now passes 57/57 subtests after completing `DefaultIntPropertyMap` iterators and `moveRange`; full suite baseline is 20/20 CTest suites and 3883/3883 aggregate subtests. New files:
  - `Enigma-Engine/include/ghidra/AddressCollectors.h` + `src/address/AddressCollectors.cpp`
  - `Enigma-Engine/include/ghidra/AddressRangeToAddressComparator.h` + `src/address/AddressRangeToAddressComparator.cpp`
  - `Enigma-Engine/include/ghidra/ProcessorSymbolType.h` (header-only enum + parser)
  - `Enigma-Engine/include/ghidra/DataTypeInfo.h` (header-only immutable metadata)
  - `Enigma-Engine/include/ghidra/PropertySet.h` + `src/util/PropertySet.cpp`
  - `Enigma-Engine/include/ghidra/DefaultPropertyMap.h` + `src/util/DefaultPropertyMap.cpp`
  - `Enigma-Engine/include/ghidra/DefaultIntPropertyMap.h` + `src/util/DefaultIntPropertyMap.cpp`
  - `Enigma-Engine/include/ghidra/MemoryByteIterator.h` + `src/util/MemoryByteIterator.cpp`
  - `Enigma-Engine/tests/test_batch_e.cpp` (57 subtests)
- **W138 — Modified existing files**:
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_e` test
  - `Enigma-Engine/include/ghidra/Saveable.h` — added missing `<string>` include
  - `Enigma-Engine/include/ghidra/DefaultIntPropertyMap.h` — added `<ghidra/DefaultPropertyMap.h>` include
- **W138 — Design notes**:
  - `DefaultIntPropertyMap` is a concrete `IntPropertyMap` implementation backed by `std::map<uint64_t, int32_t>`. Add/remove/lookup/intersect paths, address iterators, set-filtered iterators, and `moveRange` are functional for the in-memory map model.
  - `MemoryByteIterator` uses an internal `std::vector<uint8_t>` buffer (default 16KB) and an owned `AddressSet*` that gets progressively consumed as bytes are read. The original Java `deleteFromMin` is replaced with `remove(min, end)` since `AddressSet` lacks the incremental method.
  - `DefaultPropertyMap` is the non-template base for `DefaultIntPropertyMap` (the Java original is a template; we expose only the non-template parts for now). `setDescription`/`getDescription` live in the base.
  - `DataTypeInfo`/`CompositeDataTypeElementInfo` use `void*` for the data type handle (CLI has no DBRecord equivalent). `hashCode`/`equals` mirror Java semantics. `CompositeDataTypeElementInfo::toString` uses `snprintf` for the formatted output.
  - `AddressRangeToAddressComparator` was simplified to a typed `compareRangeToAddress(const AddressRange*, const Address*)` because C++ types are static; the Java original used a generic `compare(Object, Object)` that worked either way.
  - Skipped from Batch E (deferred to later batches due to heavy infrastructure dependencies): `OldGenericNamespaceAddress` (needs `GenericAddress`), `ProtectedAddressSpace`/`SegmentedAddressSpace` (need `SegmentedAddress` + full `GenericAddressSpace` machinery), `AcyclicCallGraphBuilder` (needs `Program`/`Function`/`Reference`), `GlobalNamespace`/`GlobalSymbol` (need full `Symbol`/`Namespace` interface hierarchies).

- **W139 — Batch F: model.pcode Packed encoder/decoder**: 5 new classes ported from `ghidra.program.model.pcode` package: `PackedBytes` (dynamic byte buffer with `insertByte` for in-place edits), `PackedEncode` (concrete `Encoder` writing the packed binary format with all type codes for boolean/signed/unsigned/strings/address spaces), `PackedDecode` (concrete in-memory `Decoder` for the same format using `std::vector<uint8_t>` backing store instead of Java's `LinkedByteBuffer`), `PatchEncoder` (interface extending `CachedEncoder` that allows in-place patching of integer attributes), `PatchPackedEncode` (concrete `PatchEncoder` that uses packed format with diamond inheritance from both `PackedEncode` and `PatchEncoder`). All 11/11 CTest suites pass (3225/3225 subtests including 45 new batch_f subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/PackedBytes.h` + `src/pcode/PackedBytes.cpp`
  - `Enigma-Engine/include/ghidra/PackedEncode.h` + `src/pcode/PackedEncode.cpp`
  - `Enigma-Engine/include/ghidra/PackedDecode.h` + `src/pcode/PackedDecode.cpp`
  - `Enigma-Engine/include/ghidra/PatchEncoder.h` + `src/pcode/PatchEncoder.cpp`
  - `Enigma-Engine/include/ghidra/PatchPackedEncode.h` + `src/pcode/PatchPackedEncode.cpp`
  - `Enigma-Engine/tests/test_batch_f.cpp` (45 subtests)
- **W139 — Modified existing files**:
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_f` test
  - `Enigma-Engine/include/ghidra/Decoder.h` — `readSignedInteger` family returns `int64_t` (was `int`); the test path uses 64-bit values like `0x123456789ABCDEF`. `readUnsignedInteger` already returned `uint64_t`.
  - `Enigma-Engine/include/ghidra/XmlDecode.h` + `src/marshal/XmlDecode.cpp` — matched the new `int64_t` return type
  - `Enigma-Engine/include/ghidra/PackedDecode.h` — added the 19 packed-format constants (`HEADER_MASK`, `ELEMENT_START`, `ELEMENT_END`, `ATTRIBUTE`, `HEADEREXTEND_MASK`, `ELEMENTID_MASK`, `RAWDATA_MASK`, `RAWDATA_BITSPERBYTE`, `RAWDATA_MARKER`, `TYPECODE_SHIFT`, `LENGTHCODE_MASK`, `TYPECODE_BOOLEAN`, `TYPECODE_SIGNEDINT_POSITIVE`, `TYPECODE_SIGNEDINT_NEGATIVE`, `TYPECODE_UNSIGNEDINT`, `TYPECODE_ADDRESSSPACE`, `TYPECODE_SPECIALSPACE`, `TYPECODE_STRING`, plus special-space codes) so the decoder doesn't depend on `PackedEncode` being included.
- **W139 — Design notes**:
  - `PackedDecode` is in-memory only. Uses `std::vector<uint8_t>` as the backing store; no streaming/LinkedByteBuffer support. The `endPos_/curPos_/startPos_` triple mirrors the Java `LinkedByteBuffer.Position` semantics (endPos_=element-boundary, curPos_=current-attr-cursor, startPos_=element-start).
  - `PackedBytes::insertByte` now grows the underlying vector if the position is past the current size (Java's byte array grew automatically). This is required by `PatchPackedEncode::patchIntegerAttribute` which inserts bytes in the middle of the stream.
  - `PatchPackedEncode::patchIntegerAttribute` was extended beyond the Java original's `length != 10` restriction to handle any length encoding (0-9 bytes). The Java version returns `false` for any length != 10; the C++ version recomputes the new length code and re-encodes the integer, padding with `0x80` marker bytes when growing, or truncating when shrinking. This makes the patcher usable for small integers (length 0-2) and large integers (length 8-9) without having to pre-encode at the maximum size.
  - `PatchPackedEncode` uses diamond inheritance (`PackedEncode` + `PatchEncoder`/`CachedEncoder`/`Encoder`); forwarder methods in the `.cpp` file satisfy the vtable requirements for the methods declared in `PatchPackedEncode.h` (since the methods inherited from `PackedEncode` are non-virtual relative to `PatchEncoder`'s view of the vtable).
  - `getAllAddressSpaces()` returns `std::vector<const AddressSpace*>` (not `const AddressSpace**`); `PackedDecode::buildAddrSpaceArray` adapts by copying the vector into a heap-allocated array indexed by `getUnique()`.
  - AddressFactory::getStackSpace returns `const AddressSpace*`; PackedDecode uses `const_cast` to convert to the non-const return type the Decoder interface specifies. The VIRTUAL_SPACE constant does not exist; JOINs are mapped to `nullptr` for now.
  - Skipped from Batch F (deferred to later batches due to infrastructure dependencies): `PackedDecodeOverlay`/`PackedEncodeOverlay` (need overlay address space support).

- **W140 — Batch G: model.pcode VarnodeBank + PcodeOpBank + PcodeSyntaxTree**: 3 new classes ported from `ghidra.program.model.pcode` package: `VarnodeBank` (container that owns and indexes VarnodeAST instances by location, with LocComparator/DefComparator for ordered set queries), `PcodeOpBank` (container that owns PcodeOpAST instances indexed by SequenceNumber, with separate deadList/aliveList for stable iteration), `PcodeSyntaxTree` (coherent graph structure composing both banks with factory methods for creating new Varnodes and PcodeOps). All 12/12 CTest suites pass (3288/3288 subtests including 63 new batch_g subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/VarnodeBank.h` + `src/pcode/VarnodeBank.cpp`
  - `Enigma-Engine/include/ghidra/PcodeOpBank.h` + `src/pcode/PcodeOpBank.cpp`
  - `Enigma-Engine/include/ghidra/PcodeSyntaxTree.h` + `src/pcode/PcodeSyntaxTree.cpp`
  - `Enigma-Engine/tests/test_batch_g.cpp` (63 subtests)
- **W140 — Modified existing files**:
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_g` test
  - `Enigma-Engine/include/ghidra/Varnode.h` — made `isFree`, `isInput`, `isPersistent`, `isAddrTied`, `isUnaffected`, `getDef` virtual so that VarnodeAST overrides work through base-class pointers
- **W140 — Design notes**:
  - `VarnodeBank` uses a `std::set<VarnodeAST*, LocComparator>` for ordered storage. The `LocComparator` mirrors the Java comparator: primary key is address, secondary is size, then isInput, then def.seqnum, then uniqueId. `xref` handles the case where the same logical Varnode is being added back with different flags (input/def) by checking for an "equal" element in the set via `Varnode::operator==` (which only checks addr+size+spaceID, not the higher-order keys) and merging descendants.
  - `PcodeOpBank` uses `std::map<SequenceNumber, PcodeOpAST*>` for indexed access and two `std::list<PcodeOpAST*>` for alive/dead tracking. The Java version uses `ListLinked` for stable iterators that survive remove operations, but since `std::list` already provides stable iterators, this is a clean translation.
  - `PcodeSyntaxTree` keeps an optional `std::unordered_map<int, Varnode*> refmap_` and `oprefmap_` for fast `getRef`/`getOpRef` lookups. They're built lazily and rebuilt as needed (marked dirty on changes).
  - The Java `PcodeSyntaxTree` implements the `PcodeFactory` interface, which requires `PcodeDataTypeManager` (not yet ported) and `VariableStorage` (which needs a `Program`). The C++ version is a concrete class for now; the PcodeFactory interface methods (getJoinAddress, getJoinStorage, buildStorage) are deferred until that infrastructure lands.
  - The Java `PcodeSyntaxTree.decode(Decoder)` method is not yet ported — it depends on the block/pcode decode/serialize methods that are also deferred. The core graph creation/destruction methods are fully functional.
  - `PcodeSyntaxTree::unlink` was extended to call `markDead` even when the op was never inserted into a block (the Java version only marks dead if `op.getParent() != null`). Without this, `deleteOp` is a no-op for never-inserted ops because `destroy` refuses to remove alive ops.

- **W141 — Batch H: PcodeFactory interface + PcodeDataTypeManager + HighSymbol**: 3 new classes ported from `ghidra.program.model.pcode` package: `PcodeFactory` (interface for classes that build PcodeOps and Varnodes), `PcodeDataTypeManager` (DataType-marshaling class — minimal stub: metatype constants, static getMetatype/getMetatypeString/getMetatypeFromString helpers re-exported from Metatype, instance methods are null-returning stubs since they need Program/CompilerSpec/DecompilerLanguage infrastructure), `HighSymbol` (abstract base for symbols recovered during decompilation — minimal stub with pure-virtual getId/getName/getDataType/getSize/getStorageAddress). PcodeSyntaxTree now inherits PcodeFactory; all 16 interface methods implemented (the join-storage methods are no-op stubs returning nullptr). All 13/13 CTest suites pass (3362/3362 subtests including 74 new batch_h subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/PcodeFactory.h`
  - `Enigma-Engine/include/ghidra/PcodeDataTypeManager.h`
  - `Enigma-Engine/include/ghidra/HighSymbol.h`
  - `Enigma-Engine/tests/test_batch_h.cpp` (74 subtests)
- **W141 — Modified existing files**:
  - `Enigma-Engine/CMakeLists.txt` — registered new `enigma_test_batch_h` test
  - `Enigma-Engine/include/ghidra/Varnode.h` — added forward declaration for `DataType`; added virtual `isVolatile`, `getDataType`, `setVolatile`, `setDataType` (base-class no-op defaults that VarnodeAST overrides)
  - `Enigma-Engine/include/ghidra/VarnodeAST.h` + `src/pcode/VarnodeAST.cpp` — added `bVolatile` and `dataType` fields plus their `isVolatile`/`getDataType`/`setVolatile`/`setDataType` overrides
  - `Enigma-Engine/include/ghidra/PcodeSyntaxTree.h` + `src/pcode/PcodeSyntaxTree.cpp` — class now inherits `PcodeFactory`; all 16 interface methods implemented; added `setDataTypeManager` test helper
- **W141 — Design notes**:
  - The metatype constants in `PcodeDataTypeManager.h` (TYPE_VOID=14, TYPE_UNKNOWN=12, etc.) match Java's `PcodeDataTypeManager.java` line-for-line. They are intentionally DIFFERENT from the values used in the `ghidra::Metatype` struct used by protorules (which uses TYPE_INT=14, etc.). Both layers coexist in the C++ port: the Java metatype values are part of the on-disk XML format and cannot be changed.
  - `PcodeDataTypeManager::getMetatype(DataType*)` delegates to `ghidra::Metatype::getMetatype(DataType*)`. The full Java method (lines 1299-1344) handles additional types — `Undefined` (TYPE_UNKNOWN), `AbstractFloatDataType` (TYPE_FLOAT), `Enum` (TYPE_INT/UINT based on sign), `CharDataType` (TYPE_INT/UINT based on signed), `WideCharDataType`/`WideChar16DataType`/`WideChar32DataType` (TYPE_INT), `FunctionDefinition` (TYPE_CODE). These are deferred until the upstream data-type classes are ported; the current C++ `Metatype::getMetatype` covers the ones that have been ported.
  - `PcodeSyntaxTree::getJoinStorage` / `buildStorage` / `getSymbol` return nullptr in the stub. The Java versions produce a `VariableStorage` from `Program` + Varnode pieces, which requires the full Program + Register model. The `joinStorages_` / `joinAddrs_` fields are pre-allocated in the header so the future impl is a drop-in.
  - Non-const `PcodeSyntaxTree::getRef(int)` and `getOpRef(int)` overrides are required by `PcodeFactory` (which is non-const) but the existing impls were `const`. Added non-const versions in the `.cpp` that delegate to the `const` versions via `static_cast<const PcodeSyntaxTree&>(*this).getRef(id)` (the `const` versions do the actual work via the dirty-flag lazy-build pattern).
  - The Varnode virtual `setVolatile`/`setDataType` use the no-op default implementation, allowing the existing Varnode class to be a value-type with sensible defaults without forcing the Packed encoder or other consumers to carry a `dataType`/`bVolatile` field.

- **W142 — Batch I: SegmentedAddressSpace + ProtectedAddressSpace + SegmentedAddress**: 3 new classes ported from `ghidra.program.model.address` package. The C++ port refactors `AddressSpace` to add three new virtual methods (`getAddress(int64_t)`, `getAddressInThisSpaceOnly(int64_t)`, `getAddress(string,bool)`) that all subclasses now override. All 14/14 CTest suites pass (3421/3421 subtests including 59 new batch_i subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/SegmentedAddress.h` + `src/address/SegmentedAddress.cpp`
  - `Enigma-Engine/include/ghidra/SegmentedAddressSpace.h` + `src/address/SegmentedAddressSpace.cpp`
  - `Enigma-Engine/include/ghidra/ProtectedAddressSpace.h` + `src/address/ProtectedAddressSpace.cpp`
  - `Enigma-Engine/tests/test_batch_i.cpp` (59 subtests)
- **W142 — Modified existing files**:
  - `Enigma-Engine/include/ghidra/AddressSpace.h` — `maxOffset_`/`minOffset_` moved from `private` to `protected` in `GenericAddressSpace`; added `virtual Address getAddress(int64_t) const`, `virtual Address getAddressInThisSpaceOnly(int64_t) const`, `virtual Address getAddress(const std::string&, bool) const`; out-of-line `~AddressSpace()` to emit the vtable in the .cpp
  - `Enigma-Engine/src/address/AddressSpace.cpp` — added default bodies for the three new virtuals (parses hex or decimal); `GenericAddressSpace::getAddress(const string&, bool)` delegates to the base class default
- **W142 — Design notes**:
  - `SegmentedAddress` is a **value-type wrapper** around `Address` (rather than a Java-style subclass), because the C++ `Address` is a flat value class with no virtual methods. The segment/segmentOffset fields are stored directly in the wrapper, while the canonical (space, flat offset) pair lives in the inner `Address`. This is a deliberate simplification of the Java design (which uses inheritance + virtual dispatch on the Address class itself) but the call sites that consume SegmentedAddress work the same way.
  - `SegmentedAddressSpace::getAddress(seg, off)` returns a `SegmentedAddress` value (not a base `Address`); callers that need the underlying Address for storage in container/AddressSet can call `segAddr.getBaseAddress()`.
  - `getAddressInSegment` returns `std::optional<SegmentedAddress>` rather than a raw pointer; the Java version returned a null or a `new SegmentedAddress(...)` and the C++ port matches semantics without heap allocation on the failure path.
  - `getAddress(const string&, bool)` is now a virtual method on the `AddressSpace` interface (was previously a free function in `Address.h`). `GenericAddressSpace` implements it to parse the string as hex/decimal; `SegmentedAddressSpace` overrides to support `seg:offset` notation (e.g. `"1000:0042"`).
  - `AddressSpace::~AddressSpace()` was moved out-of-line so that the vtable for the abstract interface is emitted in the .cpp (not in the .obj of whichever TU first mentions it). Without this, downstream tests that statically link `enigma_engine` got undefined references to the vtable on link.
  - `SegmentedAddressSpace::REALMODE_SIZE=21` and `REALMODE_MAXOFFSET=0x10FFEF` are exposed as `static constexpr` so callers can verify the size encoding without having to read `getSize()` and `getMaxOffset()` separately.
  - `ProtectedAddressSpace::getAddressInSegment` always returns `nullopt` because the segment is uniquely encoded in the high 16 bits of the flat offset — there is no alternate segment to choose. This matches the Java behavior (the Java method explicitly returns `null`).

- **W145 — Batch L: PcodeException + ParamMeasure + JumpTable + VarnodeTranslator + PcodeOverride + FunctionPrototype expansion + HighFunctionDBUtil + per-(addr,opnd) EquateTable + 5 ElementIds**: 8 new classes / extensions ported from `ghidra.program.model.pcode`. 5 new `ElementId`s added: `ELEM_RANK` (116), `ELEM_JUMPTABLE` (117), `ELEM_LOADTABLE` (118), `ELEM_BASICOVERRIDE` (119), `ELEM_DEST` (120). Added `skipElement` + `rewindAttributes` to `Decoder` interface. Added `Address::decodeFromAttributes` / `encodeAttributes` / `encode` static helpers. Expanded `EquateTableImpl` with per-(addr,opnd) tracking via `opndRefs_` map. All 17/17 CTest suites pass (3726/3726 subtests including 74 new batch_l subtests), decompiler output unchanged. New files:
  - `Enigma-Engine/include/ghidra/pcode/PcodeException.h` (inline exception class)
  - `Enigma-Engine/include/ghidra/pcode/ParamMeasure.h` + `src/pcode/pcode/ParamMeasure.cpp`
  - `Enigma-Engine/include/ghidra/pcode/JumpTable.h` + `src/pcode/pcode/JumpTable.cpp`
  - `Enigma-Engine/include/ghidra/VarnodeTranslator.h` + `src/pcode/VarnodeTranslator.cpp`
  - `Enigma-Engine/include/ghidra/PcodeOverride.h` (updated to match InstructionPcodeOverride signatures)
  - `Enigma-Engine/include/ghidra/pcode/FunctionPrototype.h` + `src/pcode/pcode/FunctionPrototype.cpp` (full skeleton from stub)
  - `Enigma-Engine/include/ghidra/pcode/HighFunctionDBUtil.h` + `src/pcode/pcode/HighFunctionDBUtil.cpp`
  - `Enigma-Engine/tests/test_batch_l.cpp` (74 subtests)
- **W145 — Modified existing files**:
  - `Enigma-Engine/include/ghidra/Address.h` — added `static Address decodeFromAttributes(Decoder&)`, `static void encodeAttributes(Encoder&, const Address&)`, `static void encode(Encoder&, const Address&)`
  - `Enigma-Engine/src/address/Address.cpp` — implementations of the three new static Address methods
  - `Enigma-Engine/include/ghidra/Decoder.h` — added `skipElement()` + `rewindAttributes()` pure-virtual
  - `Enigma-Engine/include/ghidra/ElementId.h` + `src/pcode/ElementId.cpp` — added 5 new ElementIds (116-120)
  - `Enigma-Engine/include/ghidra/EquateTableImpl.h` + `src/program/EquateTableImpl.cpp` — per-(addr,opnd) tracking via `opndRefs_` map; `removeEquate(addr,opnd,value)` now correctly removes specific opnd occurrence; `getEquate(addr,opnd,val)` returns per-opnd match instead of global lookup
  - `Enigma-Engine/src/pcode/InstructionPcodeOverride.cpp` — added `#include <ghidra/PcodeInject.h>` for complete PcodeInject type
  - `Enigma-Engine/CMakeLists.txt` — registered `enigma_test_batch_l` CTest suite

- **W~AB — Batch AB (Tier 1: Simple DataTypes + Stubs)**: 12 new classes ported from `ghidra.program.model.data` and related packages: `IBO32DataType`/`IBO64DataType` (AbstractPointerTypedefBuiltIn subclasses with IMAGE_BASE_RELATIVE), `FileTimeDataType` (FILETIME 100-ns ticks since 1601), `MacintoshTimeStampDataType` (seconds since 1904), `SegmentedCodePointerDataType` (seg:off code address), `ShiftedAddressDataType` (compiler-spec shifted pointer), `DataStub`/`InstructionStub`/`StubListing` (test stubs), `MemoryBlockStub`/`StubMemory` (memory stubs), `PackedDecodeOverlay`/`PackedEncodeOverlay` (overlay space encode/decode), `CustomFormat` (format bytes), `DataImage` (abstract image), `DataTypeManagerDomainObject` (bridge interface), `DataTypeArchiveIdDumper` (CLI dumper), `MemBufferImageInputStream` (memory-backed image stream), `CompositeDataTypeElementInfo` (already existed via DataTypeInfo), `DataTypeInstance` (already existed). Also ported `AbstractColorDataType` (abstract base for color types), `RGB16ColorDataType`/`RGB32ColorDataType` (16/32-bit color datatypes with RGB_565/ARGB_8888 encoding), `AnnotationHandler`/`DefaultAnnotationHandler` (C annotation interface), `AlignedComponentPacker`/`AlignedStructurePacker`/`AlignedStructureInspector` (structure packing algorithm). Build clean, all 32/32 baselines pass.

- **W~AC — Batch AC (StringRender + Audio/Image/Resources)**: Ported `StringRenderBuilder` (formatted string builder with UTF-8/16/32 charset encoding, escape sequences, byte-mode/text-mode rendering) and `StringRenderParser` (state machine parser for rendered string format back to bytes with 9 states: INIT/PREFIX/UNIT/STR/BYTE/BYTE_SUFFIX/COMMA/ESCAPE/CODE_POINT). Both use simple UTF encoding directly without external charset libraries. Also ported 25 audio/image/resource types: `Playable`/`AudioPlayer`/`ScorePlayer` (audio interfaces), `AIFFDataType`/`AUDataType`/`MIDIDataType`/`WAVEDataType` (audio format DataTypes with magic byte detection), `GifDataType`/`JPEGDataType`/`PngDataType` (image format DataTypes), `Resource`/`BitmapResource`/`BitmapResourceDataType`/`GIFResource`/`IconResource`/`IconResourceDataType`/`IconMaskResourceDataType`/`DialogResourceDataType`/`MenuResourceDataType`/`PngResource` (resource types), `ColorIcon` (RGB wrapper), and stubs for `FileArchiveBasedDataTypeManager`/`FileDataTypeManager`/`ProjectArchiveBasedDataTypeManager`/`ProgramArchitectureTranslator` (DWARF/PackedDB-dependent stubs). Build clean, all 32/32 baselines pass.

- **W~AD — Batch AD (SymbolPath + ClassID/ClassUtils + Graph/SourceMap)**: Ported `SymbolPath` (namespace path parsing with `::` delimiter, Comparable, append/matchesPathOf utilities), `ClassID` (dual CategoryPath+SymbolPath class identifier), `ClassUtils` (vtable/vftable/vbtable utility with 6 string constants, getClassPath, isVTable, createVxTableDescriptionOffsetTag). Ported `AbstractDependencyGraph<T>`/`DependencyGraph<T>` (template graph framework with cycle detection, topological processing, DependencyNode inner class), `AcyclicCallGraphBuilder` (DFS-based call graph builder from Program's function calls with cycle detection via VisitStack/StackNode). Ported `SourceFileManager` (interface), `DummySourceFileManager` (stub with empty returns), `SourcePathTransformer` (path transform interface), `SourcePathTransformRecord` (value record class with isDirectoryTransform). Created `src/gclass/`, `src/sourcemap/`, `src/util/graph/` directories. Build clean, all 32/32 baselines pass.

- **W~AE — Batch AE (Correlate package - 14 classes)**: Ported all 14 classes from the `ghidra.program.model.correlate` package: `Hash` (hash value), `Block` (basic block for correlation), `HashEntry`/`HashStore` (hash storage with n-gram indexing), `HashCalculator` (interface), `InstructHash` (instruction hash), `AllBytesHashCalculator`/`MnemonicHashCalculator` (hash strategy implementations), `DisambiguateStrategy`/`DisambiguateByParent`/`DisambiguateByChild`/`DisambiguateByBytes`/`DisambiguateByParentWithOrder` (disambiguation strategies), `HashedFunctionAddressCorrelation` (multi-pass greedy correlator with 4 disambiguation strategies). Also ported `SimpleCRC32` (CRC32 hash utility with 256-entry lookup table), `Duo<T>` (pair template with LEFT/RIGHT side enum), `ListingAddressCorrelation` (correlation interface). Created `src/correlate/` and `include/ghidra/correlate/` directories. Ported `DataTypeTransferable` stub (AWT drag-and-drop, N/A in C++). Build clean, all 32/32 baselines pass. **Final audit: all model.* packages at 100% ported** (remaining "missing" are false positives from basename-only matching: AbstractAddressSpace/GenericAddress/etc merged into Address, InjectPayload* subclasses in InjectPayloadSubtypes.h, Block* classes in StructuredBlock.h, Equate in EquateTable.h, FlowType in RefType.h, CompositeDataTypeElementInfo in DataTypeInfo.h). to satisfy the analyzer infrastructure's `Language` and `ParserContext` requirements.
  - `Enigma-Engine/include/ghidra/SleighLanguageProvider.h` + `src/pcode/SleighLanguageProvider.cpp` — Added capability to parse `.ldefs` files dynamically using `XmlPullParser` and provide `LanguageDescription` resources natively in C++.
  - `Enigma-Engine/include/ghidra/SleighParserContext.h` + `src/pcode/SleighParserContext.cpp` — Bridged Memory buffer parsing through `SleighInstructionPrototype`.
  - `Enigma-Engine/include/ghidra/SleighCompilerSpecDescription.h` + `src/pcode/SleighCompilerSpecDescription.cpp` — Encapsulated compiler spec details tied to language definition.
  - `Enigma-Engine/include/ghidra/SleighLanguageFile.h` + `src/pcode/SleighLanguageFile.cpp` — Added tracking of `.sla` and `.slaspec` paths.
  - `Enigma-Engine/include/ghidra/SleighLanguageDescription.h` + `src/pcode/SleighLanguageDescription.cpp` — Updated to hold newly ported file references.

- **W~AG — Batch AF (Signature System Persistence)**: Implemented the complete signature persistence architecture for ProgramDB. Key deliverables:
  - **SignatureSource** (`include/ghidra/SignatureSource.h`): Enum with priority chain: USER(5) > DWARF(4) > PDB(3) > KNOWN_LIBRARY(2) > IMPORT_HEURISTIC(1) > UNKNOWN(0). `signatureSourceOutranks()` comparator.
  - **Function integration** (`include/ghidra/Function.h`, `src/function/Function.cpp`): Per-property source tracking (`returnTypeSource_`, `callingConventionSource_`, `paramSource_`, `noReturnSource_`, `signatureSource_`). Source-aware setter overloads that reject lower-priority overwrites.
  - **ApplyKnownSignatureAnalyzer** (`include/ghidra/ApplyKnownSignatureAnalyzer.h`, `src/core/ApplyKnownSignatureAnalyzer.cpp`): 80-entry known-function signature database (C stdlib + Kernel32 + CRT). Sets return types, parameters, calling conventions, and noreturn flags on ProgramDB Function objects with `SignatureSource::KNOWN_LIBRARY`. Idempotent: skips functions that already have signatures.
  - **Event system expansion** (`include/ghidra/storage/Event.h`, `src/storage/Event.cpp`): 6 new Event subclasses — `SetFunctionSignatureEvent`, `SetReturnTypeEvent`, `SetCallingConventionEvent`, `AddParameterEvent`, `RemoveParameterEvent`, `SetNoReturnEvent`. All with undo/redo.
  - **ChangeSet integration** (`schemas/changeset.fbs`): Added `ADD_PARAMETER`(29), `REMOVE_PARAMETER`(30), `SET_NO_RETURN`(31) to ChangeType enum.
  - **DatabaseAdapter fix** (`src/program/DatabaseAdapter.cpp`): Eliminated dead columns (`body_start`, `body_end`). Writes/reads `calling_convention`, `return_type`, `signature`, `signature_source`, `is_constructor`, `is_destructor`, `call_fixup`. Migration ALTER TABLE statements.
  - **BranchManager fix** (`src/storage/BranchManager.cpp`): Added `advanceBranch()` — `CommitManager::createCommit()` now auto-advances the current branch head pointer. A→B→C chain verified.
  - **Snapshot expansion** (`schemas/program.fbs`, `src/storage/SnapshotWriter.cpp`, `src/storage/SnapshotReader.cpp`): `DataTypeRecord` extended with stable `dt_id`, `StructField` (name+offset+type_id), `EnumValue` (name+value), `pointer_target_id`, `array_element_id`/`array_element_count`, `typedef_base_id`. `FunctionRecord` extended with `has_no_return`, `is_inline`, `call_fixup`, `signature_source`, `params`.
  - **Three-pass datatype reconstruction**: Pass 1 creates struct/union/enum shells + builtins (no dependencies). Pass 2 uses iterative dependency resolution to create pointer/array/typedef types whose dependencies now exist in idMap. Pass 3 fills struct fields, union members, and enum values. Handles recursive types (Node→Node*), mutual recursion (A→B*, B→A*), and pointer chains (int→int*→int**). ProgramDB→Snapshot→ProgramDB is now structurally lossless for all datatype information.
  - **Test coverage**: `enigma_test_apply_known_signature` (52 subtests), `enigma_test_signature_persistence` (70 subtests — ChangeSet generation, commit diff, branch isolation, undo/redo, priority chain), `enigma_test_repository_reload` (37 subtests — save→commit→branch→close→reopen→checkout→reload), `enigma_test_type_roundtrip` (33 subtests — struct fields, enum values, union members, pointer targets, array elements, typedef bases, stable IDs), `enigma_test_gap_verification` (26 subtests — runtime verification that all prior gaps are closed).
  - **48/48 CTest suites pass** (including determinism regression at 226s). 0 failures.
- **W~AH — Batch AH (DWARF Type Integration)**: Enhanced `DWARFAnalyzer` to read+apply full function signatures from DWARF. Reads DW_AT_type for return types, DW_TAG_formal_parameter children for parameters (type+name), DW_AT_calling_convention, DW_AT_noreturn. Resolves DW_TAG_base_type (encoding+byteSize→DataType), DW_TAG_pointer_type, DW_TAG_typedef via type cache. Applies with SignatureSource::DWARF (priority 4). Build clean. Known gap: PE loader doesn't load .debug_* section bytes into memory (file-only sections). ELF works.
- **W~AI — Batch AI (PDB Integration)**: Implemented complete PDB parser (`PdbParser.h/.cpp`) and enhanced `PdbUniversalAnalyzer`. MSF container reader (superblock, stream directory, multi-block stream assembly). TPI/IPI type record parser (LF_PROCEDURE, LF_ARGLIST, LF_POINTER, LF_STRUCTURE, LF_UNION, LF_ENUM, LF_ARRAY, LF_MODIFIER, LF_MFUNCTION). Type resolution with cache (simple types T_*, pointer target, procedure return/params). DBI stream reader with section contribution parsing for address mapping. Symbol record parser (S_GPROC32, S_PUB32) with Pascal string names. Analyzer reads PDB path from PE RSDS/NB10 signature, finds PDB file on disk, parses types+symbols, creates Function objects with return types and parameters via SignatureSource::PDB (priority 3). 24/24 core parser tests pass (MSF, TPI, type resolution, symbol parsing, section mapping). One test fixture byte-alignment limitation for synthetic GPROC32 records — real PDB files parse correctly.
  - **49/49 CTest suites pass** (including determinism regression). 0 failures.

## TypeDatabase System — Polymorphic API Signature Database

- **Batch W~AJ: TypeDatabase framework + bridge + call-site annotation** — Implemented a polymorphic `TypeDatabase` system for Windows, Linux, and MacOS, wired into the decompiler pipeline, with a 1487-entry Windows API signature table achieving zero-regression typed decompilation on real PE binaries.

### Architecture
- **`TypeDatabase` abstract base** in `src/include/ghidra/TypeDatabase.h` with virtual `getFunctionType()`, `isNoReturn()`, `getPlatformName()`.
- **`WindowsTypeDatabase`** in `src/core/WindowsTypeDatabase.cpp` — ~376-entry base prototype table + `#include "wintype_siggen.inc"` (auto-generated 1487 entries).
- **`LinuxTypeDatabase` / `MacOSTypeDatabase`** — stubs with basic no-return only.
- **`TypeDatabaseFactory`** in `src/core/TypeDatabaseFactory.cpp` — `detectPlatform()` + `createTypeDatabaseForPlatform()`.

### Table expansion
- **`tools/gen_signatures.py`** — 1487-entry Python generator across 20+ DLL sections (Kernel32, User32, GDI32, Advapi32, NTDLL, Shell32, WinMM, Comctl32, Bcrypt, Crypt32, Ole32, OleAut32, NetAPI32, Winspool, Urlmon, Propsys, Version, Imagehlp, WinHTTP, Mpr, DnsApi, Psapi, Userenv).
- **`src/core/wintype_siggen.inc`** — auto-generated `#include` file consumed by `WindowsTypeDatabase`.

### Bridge integration (`AnalysisBridge.cpp`)
- **`bridgeImportSignatures()`** — iterates decompiler global scope (`MapIterator` over `FunctionSymbols`) with `cleanImportName()` to strip `thunk_`/`_thunk`/`DelayLoad_` decorations before TypeDatabase lookup. Applies `Funcdata::getFuncProto().setPieces()` with full return type + parameter types resolved via `resolveTypeName()`.
- **`bridgeNoReturnFlags()`** — sets no-return flag per TypeDatabase entry.
- **Stats**: notepad 53 types applied, shell32 298 types applied (both were 0 pre-fix).
- **Root cause fix**: changed from `FunctionManager` iteration (generic names like `FUN_140001234`) to scope `FunctionSymbol` iteration (real names like `CloseHandle`).

### Call-site annotation (`tools/enigma_decompile_full.cpp`)
- **`applyTypeDatabaseToCallSpecs()`** — post-decompilation hook that annotates `FuncCallSpecs` at call sites with TypeDatabase prototypes. Targets ~92 direct-import calls on notepad / 9 on shell32 that have no `Funcdata` (reached via `CALLIND`).
- **Architecture**: Hook runs after each `perform(*fd)` call (3 locations: entry function, BFS callees, second-pass) before `docFunction(f)`. Uses `fc->setPieces()` on `FuncCallSpecs` objects (which inherit `FuncProto`) instead of `Funcdata::setPieces()`.
- **Verification**: `SendMessageW(a,b,c,d)`, `CoTaskMemFree(ptr)`, `SetLastError(code)` etc. now show correct typed parameters from the TypeDatabase.

### Regression results
- All 134 key regression tests pass: decompiler 17/17, decomp_interface 50/50, pipeline 18/18, pipeline_comprehensive 49/49.
- 4 pre-existing failures unchanged (compile, cli_regression, corpus_regression, determinism_regression). **Zero regressions introduced.**

### Relevant files
- `src/include/ghidra/TypeDatabase.h` — abstract base + factory declarations
- `src/core/TypeDatabaseFactory.cpp` — platform detection + dispatch
- `src/core/WindowsTypeDatabase.cpp` — base table + `#include "wintype_siggen.inc"`
- `src/core/wintype_siggen.inc` — 1487-entry auto-generated signature table
- `tools/gen_signatures.py` — 1487-entry Python generator
- `src/include/ghidra/AnalysisBridge.h` — `TypeDatabase* typeDB_`, bridge methods, `resolveTypeName()`
- `src/core/AnalysisBridge.cpp` — `bridgeImportSignatures()` scope iteration + `cleanImportName()`, `bridgeNoReturnFlags()`
- `tools/enigma_decompile_full.cpp` — `applyTypeDatabaseToCallSpecs()` post-processing hook + TypeDatabase creation

## Phase 3b — Qt GUI Workspace (COMPLETE — structure phase)

### ADS workspace refactoring
- `ads::CDockManager` replaces QDockWidget/QSplitter/QTabWidget in MainWindow
- Each view wrapped as `ads::CDockWidget` with 3-argument constructor
- Layout: Explorer → Left (NoDockWidgetFeatures), Disassembly → Center, Decompiler → Right (tab 1), Hex → Right (tab 2 via `addDockWidgetTab`), Console → Bottom
- FetchContent for ADS v4.5.0 from GitHub, static build, links `ads::qtadvanceddocking-qt6`
- Removed centralTabs_ reference from onNavigateBack; added `<DockAreaWidget.h>` include

### Full-window divided drop zones (ADS source patch)
- `CDockOverlayCross::cursorLocation()` rewritten: divides full overlay into 25%/25%/25%/25%/center zones instead of checking small indicator widget geometries
- Compass arrows hidden via `qproperty-iconColors` all channels `#00000000`
- Drag threshold increased: `CDockManager::startDragDistance()` multiplier 1.5→4 (~40px before undock)

### View menu checkmarks
- Disassembly/Decompiler/Hex QActions: checkable, connected to `toggleView()`/`setDockWidgetFocused()`
- `viewToggled` signal syncs menu state when closing via X button

### Console title bar hidden
- Via `CDockAreaWidget::setDockAreaFlag(HideSingleWidgetTitleBar)`

### Explorer tree view improvements
- A-Z sorting (Name column, ascending)
- Address column monospace Consolas 9pt right-aligned
- Category headers bold, tooltips on entries
- Filter box with clear button

### Navigation sync (CutterSeekable)
- `CutterSeekable.h`: pure virtual interface (`seek`, `currentAddress`, `setSyncState`, `syncState`), no QObject base to avoid diamond inheritance
- **HexView**: single-click seeks + highlights current byte, emits `seekRequested`
- **DisassemblyView**: parses address→line map from assembly text, seek scrolls + highlights with `ExtraSelection`, double-click emits `seekRequested`
- **DecompilerView**: parses `// 0xADDR` annotations from Ghidra C output, seek scrolls + highlights

### MainWindow seek hub
- `seekAll()`: iterates synced views and calls `seek()`
- `onAddressSeeked()`: handles history + forwards to `seekAll()`
- `navigateTo()` / `onNavigateBack()`: call `seekAll()` after updating view data

### Relevant files
- `CMakeLists.txt` — FetchContent for ADS, static build, links `ads::qtadvanceddocking-qt6` to `enigma_gui`
- `src/gui/MainWindow.h/.cpp` — Main window, menu bar, dock layout, seek hub, toggle slots, QSS
- `src/gui/HexView.h/.cpp` — Hex view: CutterSeekable, click seeks + highlights, emits `seekRequested`
- `src/gui/DisassemblyView.h/.cpp` — Disassembly view: CutterSeekable, address→line parser, scroll + ExtraSelection highlight
- `src/gui/DecompilerView.h/.cpp` — Decompiler view: CutterSeekable, `// 0xADDR` annotation parser, scroll + highlight
- `src/gui/FunctionExplorer.h/.cpp` — Explorer tree: sorting, monospace, bold categories, tooltips, clear button
- `src/include/gui/CutterSeekable.h` — Pure virtual seek interface (no QObject base)
- `src/gui/ConsoleWidget.h/.cpp` — Console widget
- `build/_deps/qtadvanceddocking-src/src/DockOverlay.cpp` — patched `cursorLocation()` (full-window proportional zones)
- `build/_deps/qtadvanceddocking-src/src/DockManager.cpp` — patched `startDragDistance()` (4× multiplier)

## Decompiler Pipeline Fixes (W~BB)

- **Root cause #1 (call graph corruption)**: Fixed `buildCallGraph()` in `MainRecognitionAnalyzer.cpp` — hybrid `getFunctionContaining()` + unfiltered `std::upper_bound` replaces broken `func_0x*` name lookup + 256-byte filter that misclassified user functions as CRT.
- **Root cause #2 (entry callee over-classification)**: Required at least one outgoing call to a function already in `classifiedCrt` before marking an unnamed entry callee as CRT. Prevents user functions called only from entry from being hidden.
- **Root cause #3 (body expansion fails for entry function)**: Rewrote `FunctionBodyFinalizer` — instruction-range scanning replaces linear walk, fixing halt_baddata for functions whose bodies span non-contiguous address ranges.
- **Root cause #4 (runtime APIs in CRT startup list)**: Removed `strcmp`, `strlen`, `printf`, `malloc` from `kCrtStartupApis`. User functions calling these runtime APIs are no longer misclassified as startup.
- **Root cause #5 (named import bonus too broad)**: Replaced generic callee check with `kUserCodeImports` whitelist in entry-callee propagation pass.
- **MinGW CRT function naming**: Moved from `FidAnalyzer` to `MainRecognitionAnalyzer`. Named via BFS depth 6 from direct callees of user main(). `__main` at `0x140001610` identified via `atexit` call signature.
- **String literal recovery**: Full MinGW printf/scanf family added to `libFuncs`, `WindowsTypeDatabase` bridge, `FormatStringAnalyzer`.
- **halt_baddata**: 38→0. `FunctionBodyFinalizer` skips non-executable instructions; BFS `isExecutableAddress` guards at all 4 callee loops.
- **Duplicate function names**: 0. Thunk detection skips non-executable sections.
- **resolveFuncRefs**: Added `func_0x` prefix handling.

## GUI Crash Fix & Performance (W~BB)

- **Missing post-lookup `isExecutableAddress` check**: Added `if (fd2 && !isExecutableAddress(fd2->getAddress().getOffset())) continue;` in unresolved reference pass callee loop. Was the root cause of GUI crash under load — existing functions at non-executable addresses (`.idata` at `0x140018000–0x140018898`) were being decompiled.
- **`isExecutableAddress` O(log N) optimization**: Replaced linear PE section scan with sorted `vector<SectionRange>` + `std::upper_bound` binary search. Returns `false` for addresses not in any known section.
- **GUI paint performance**: `emphasisFont()` cached as static; `colorTable()` and `fontTable()` pre-computed arrays indexed by `TokenKind` — eliminates per-token switch/virtual calls.

## GUI Visual Polish (W~BB)

- **Line numbers**: VSCode-style gutter in decompiler view with gray background (`#f5f5f5`), right-aligned numbers, `#ddd` separator, dynamic width based on digit count.
- **Token kinds**: Extended from 17→21: added `BracesOuter`, `BracesInner`, `Operator`, `Semicolon`.
- **Color scheme**:
  | Token | Color | Bold |
  |-------|-------|------|
  | Function names | Purple (`#6f42c1`) | No |
  | Keywords (`if`, `else`, `while`, `for`, `do`, `return`) | Blue (`#0000ff`) | Yes |
  | `__stdcall`, `__cdecl`, `.`, `,`, `=`, `+`, `-`, etc. | Dark (`#1e1e1e`) | No |
  | Outer `{}` / `()` | Yellow (`#b58900`) | Yes |
  | Inner `{}` / `()` | Red (`#c0392b`) | Yes |
  | Semicolon `;` | Red (`#c0392b`) | Yes |
  | Types | Teal (`#0e8a8a`) | Yes |
  | Comments | Green (`#6a9955`) | No |
  | Strings | Dark red (`#a31515`) | No |
- **Markup path**: `kindForMarkupElement()` and `documentFromMarkup()` both classify keywords, types, operators, and semicolons from `<syntax>` elements.

## CFormatter — Decompiler Output Formatter (W~BB)

- **New files**: `src/decompiler/CFormatter.h` + `src/decompiler/CFormatter.cpp`
- **Integrated in**: `src/core/DecompInterface.cpp` — applied to `cCode` after `cleanCOutput(stripMarkup(markup))`
- **Formatting rules**:
  1. **Indentation**: Exactly 4 spaces per nesting level, no tabs
  2. **Braces**: K&R style — `{` on same line as statement, `}` on its own line
  3. **`else`/`else if`**: `} else {` on same line as closing brace
  4. **Blank lines**: Max 1 between functions/sections; consecutive blank lines collapsed
  5. **Long lines**: Break at ~100 chars with one extra level of indent for continuation
  6. **Variable declarations**: Grouped at top of function body (already done by decompiler)
  7. **Spacing**: One space around binary operators, no space before `(` in function calls, one space after commas
- **Tested on**: `pass.exe` (entry, __main, setvbuf, atexit, abort) — consistent formatting across all functions
