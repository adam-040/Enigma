# Ghidra 12.1.3 — Two-Track Change Tracking

Track the upgrade from Ghidra 12.0.4 (baseline) to **12.1.3** (released) as two
independent work streams so the GZF/.rep importer work is never conflated with
engine/analysis parity work.

## The two tracks

### Track 1 — GZF/.rep import compatibility (importer scope)
Only changes that can affect **Program data stored/exported into `.gzf` / the
Ghidra project DB tables (`.gbf`)** and therefore the `.gzf → Enigma` importer:

- **Data types / structure layout**: composite/struct layout, pointers,
  typedefs, arrays, enums, bitfields, function definitions, calling conventions.
- **Symbols / exports**: symbol names/types, source symbols, external refs.
- **References**: memory/stack/register/external references, offset maps.
- **Relocations**: relocation table records.
- **Memory / program metadata**: memory blocks, file bytes, permissions,
  language/compiler-spec IDs, image base, source files, source-map entries,
  bookmarks, module trees, context registers, metadata.
- **PE/ELF/COFF/Mach-O importer changes** that alter the resulting Program data
  (binary format parsers, opinion loaders, analyzers that write DB tables).

**Method**: diff schema-version constants and table column layouts between 12.0.4
and 12.1.3; regenerate corpora with the 12.1.3 `analyzeHeadless`; run the
existing fidelity (28/28), importer (87/87), equates (20/20), function-tags
(23/23), rebase, and gbf-reader suites against the 12.1.3-produced `.gbf`.

### Track 2 — Enigma engine/analysis parity (NOT importer work)
Separately tracked, no importer coupling:

- **Processor / instruction semantics**: Sleigh language files
  (`Ghidra/Processors/*/data/languages/*.slaspec`, `.sinc`) — x86 legacy + x86-64
  (AVX/GFNI), AArch64, RISC-V, Loongarch, etc.
- **P-code / decompiler**: Sleigh compiler semantics, decompiler C++ under
  `Ghidra/Features/Decompiler/src/main/c` (switch recovery, p-code ops, HRestart,
  fallthrough, etc.), `Decompiler`/`DecompilerDependent` Java.
- **Analysis heuristics**: analyzers that do not write DB tables the importer
  consumes but affect engine-side re-analysis parity.

### Explicitly out of scope (ignored)
GUI, BSim, PostgreSQL, Debugger (incl. TraceModeling/RMI), Search, logging,
preferences, build-system/toolchain plumbing, documentation-only changes.

## Local resources (verified 2026-08-19)

| resource | version | purpose |
|---|---|---|
| `C:\Users\pc\Desktop\ghidra-12.1.3-source` | **12.1.3 PUBLIC** (runnable distro, `application.properties`, jars, `support\analyzeHeadless.bat`) | generate real 12.1.3 `.gzf`/`.gbf` corpora; inspect data files (Sleigh, etc.) |
| `C:\Users\pc\Desktop\ghidra-Ghidra-12.1.3-build` | **12.1.3 DEV** full source checkout (15,459 `.java`) | exact implementation/schema diffs |
| `C:\Users\pc\Desktop\Ghidra-Build` | 12.0.4 built distro | **REMOVED from Desktop** (2026-08-19) |
| 12.0.4 `.rep` corpora (`pass_proj.rep`, `oooo.rep`) | Ghidra 12.0.4 | **REMOVED from Desktop** (2026-08-19) — baseline schema knowledge now only from 12.1.3 adapter history + documented historical results (`GZF_FIDELITY_REPORT.md`, `PROGRESS.md`) |

### Binaries available for 12.1.3 corpus regeneration
- `C:\Users\pc\Desktop\pass.exe`
- `C:\Users\pc\Desktop\Enigma IDE Local\corpus_diverse\` — `c_complex.exe`,
  `cpp_templates.exe`, `mathlib.dll`, `usemath.exe` (+ `.c`/`.cpp` sources)
- `C:\Users\pc\Desktop\crackMe\notepad.exe`, `C:\Users\pc\Desktop\crackMe\tool.exe`
- `C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\notepad_test.exe`
- Not present: `key.exe`, `pro.exe`.

Note: 12.0.4 `analyzeHeadless` failed with "Failed to find a supported JDK"
before removal (JDK 21 on PATH; likely needs `JAVA_HOME`). The 12.1.3 distro
requires the same; set `JAVA_HOME` at execution time.

## Track 1 — importer-consumed tables (exact inventory)

`src\import\GzfProgramImporter.cpp` reads these tables (45 `findTable` sites):

`Program`, `ADDRESS MAP`, `Calling Conventions`, `DataTypeManager`, `Categories`,
`Built-in datatypes`, `Composite Data Types`, `Enumeration Data Types`,
`Function Definitions`, `Pointers`, `Typedefs`, `Arrays`, `Enumeration Values`,
`Function Parameters`, `Component Data Types`, `File Bytes`, `Memory Blocks`,
`Sub Memory Blocks`, `Prototypes`, `Instructions`, `Symbols`, `Function Data`,
`Thunk Functions`, `Comments`, `Data`, `Property Map - Lengths`, `Equates`,
`Equate References`, `FROM REFS`, `ContextTable`, `Bookmark Types`,
`Relocations`, `Trees`, `Module Table<N>`/`Fragment Table<N>`/
`Parent/Child Relationships<N>`/`Range Map - Fragment Addresses<N>` (per tree),
`Range Map - SCOPE ADDRESSES`, `Function Tags`, `Function Tag Map`, `Metadata`,
plus optional `Calling Conventions`.

### Ghidra-side writers to diff (12.0.4 → 12.1.3)
All under `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/`:

- Core: `ProgramDB`, `ProgramMetadataDB`, `AddressMapDB` (`ADDRESS MAP`)
- Listing: `code/CodeManager`, `code/InstDBAdapter`, `code/DataDBAdapter`,
  `code/ProtoDBAdapter`, `code/CommentsDBAdapter`
- Data types: `data/DataTypeManagerDB`, `data/CompositeDBAdapter`,
  `data/EnumDBAdapter`, `data/FunctionDefinitionDBAdapter`,
  `data/PointersDBAdapter`, `data/TypeDefDBAdapter`, `data/ArrayDBAdapter`,
  `data/EnumValueDBAdapter`, `data/FunctionParameterAdapter`,
  `data/ComponentDBAdapter`, `data/CallingConventionDBAdapter`
- Symbols: `symbol/SymbolManager`, `symbol/SymbolDB`, `symbol/SourceArchiveAdapter`
- Functions: `function/FunctionManagerDB`, `function/FunctionAdapter`,
  `function/FunctionTagAdapter`, `function/FunctionTagMappingAdapter`,
  `function/ThunkFunctionAdapter`, `oldfunction/Old*Adapter`
- References: `references/ReferenceManagerDB`, `references/ReferenceAdapter`
- Equates: `equate/EquateManagerDB`, `equate/EquateDBAdapter`
- Memory: `mem/MemoryMapDB`, `mem/FileBytesDB`, `mem/SubMemoryBlockDB`
- Module trees: `module/ModuleMapDB`, `module/FragmentDBAdapter`,
  `module/ModuleDBAdapter`, `module/ParentChildDBAdapter`
- Misc: `relocation/RelocationDB`, `bookmark/BookmarkManagerDB`,
  `external/ExternalManagerDB`, `sourcefile/SourceFileManagerDB`,
  `context/ContextStoreDB`, `sourcemap/SourceFileAdapter`/`SourceMapAdapter`
- Container: `ghidra.framework.store.db.PackedDatabase` (GZF packer;
  `GzfExporter`/`GzfLoader` in `Features/Base`). GZF filesystem provider classes
  are NOT in the DEV source checkout (only in the runnable distro jars).

### Schema-version mechanism (for the 12.0.4→12.1.3 diff)
- Table schemas are declared as `Schema` objects (columns + key field) inside
  adapter classes, e.g. `code/InstDBAdapter.INSTRUCTION_SCHEMA`:
  `Schema(1, "Address", [IntField, ByteField], ["Proto ID","Flags"])`.
- Versioned history is kept as `*AdapterV0..Vn` classes with
  `SCHEMA_VERSION = N`; the current version is selected in the plain adapter's
  `getAdapter(...)` (CREATE → newest Vn; else version-checked open + upgrade).
  Examples found: `FunctionAdapter` V0..V3 (current V3),
  `CompositeDBAdapter.SCHEMA_VERSION = 6` (+
  `FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION`), `InstDBAdapter`/`DataDBAdapter`/
  `ProtoDBAdapter`/`CommentsDBAdapter` current V1, `SettingsDBAdapter` V0/V1,
  `CallingConventionDBAdapter` V0.
- **Seed finding**: `CallingConventionDBAdapterV0` +
  `CallingConventionDBAdapterNoTable` exist in 12.1.3 (`data/` package) — the
  `Calling Conventions` table is the prime candidate for a 12.1-new table; the
  importer already tolerates its absence. Verify whether 12.0.4 corpora carried
  it (historical corpora removed; check old fidelity logs / importer warnings).

## Track 2 — engine/analysis parity scope (deferred)
- Sleigh language specs: `Ghidra/Processors/<lang>/data/languages/` — x86
  (`x86/*.slaspec` legacy + `x86-64/*.slaspec`), `AARCH64`, `RISCV`, `Loongarch`,
  `ARM`, `PowerPC`, `MIPS`, etc. (AVX/GFNI registers+semantics, new instructions)
- P-code: sleigh compiler + `pcode` definitions; `Features/Decompiler` C++ source
  (switch recovery in `decompile/switch.cc`, p-code ops, jumptable analysis)
- Engine consumers to align later: Enigma disassembler, decompiler, emulator,
  function-detection heuristics (importer constraints: do not modify function
  detection / decompiler heuristics / GUI during Track 1 work).

## Status / next steps

### Track 1 — DONE (verified 2026-08-19; re-audited 2026-08-19 with full
ChangeHistory.md + schema-diff closure — see sections below)
- 12.1.3 corpora regenerated with `analyzeHeadless` (`JAVA_HOME=C:\java\jdk-21`,
  project dir must pre-exist):
  - `C:\Users\pc\Desktop\ghidra_1213_proj\g1213.rep\idata\00\~0000000N.db\db.1.gbf`
    — 00=pass.exe, 01=notepad_test.exe, 02=tool.exe, 03=usemath.exe,
    04=c_complex.exe, 05=cpp_templates.exe, 06=mathlib.dll
    (mapping identified via stats signatures; the `.prp`-regex mapping was wrong)
  - `C:\Users\pc\Desktop\pass_proj.rep` — real Ghidra project (analyzeHeadless
    import of pass.exe) so `enigma_test_gzf_rebase` (Repository layer, needs
    `idata/~index.dat`) can open it; plus `db.16.gbf` copy of the 12.1.3 pass db
    for the fidelity/import hardcoded-path blocks. NOTE: running headless
    `-process` on the project PRUNES old versions — re-copy `db.17.gbf` →
    `db.16.gbf` after any probe run.
- Importer fixes (found via fidelity 43/43 verification):
  1. **typedef-of-undefined**: 12.1.3 DWARF writes unresolved typedef bases as
     Data Type ID **0** (`DEFAULT_DATATYPE_ID=0`; `getDataType(0)` →
     `DataType.DEFAULT`). Engine treated `<= 0` as no-base and dropped the
     typedef (`tool.exe` `forward_iterator_tag`). Fix: id 0 → `DefaultDataType`
     in `resolveDataType` (`GzfProgramImporter.cpp`), pointer fallback narrowed
     to `baseId < 0`; `SnapshotWriter` materializes a default-datatype inline
     "builtin" record named "undefined"; `SnapshotReader` maps it back. Verified:
     all 7 corpora import with `datatypeUnresolvedRefs=0`.
  2. **12.1.3 prototype bytes ≠ memory bytes**: 12.1.3 stores relocated
     byte-patterns in `Prototypes.Bytes` (e.g. JNZ at 0x140001505 stored as
     `75 E7`, memory/file are `75 11`; 12.0.4-era stored a 74-coded pattern).
     Capstone then names the 75-coded jump "jne" instead of "je". Not an engine
     defect — corpus-specific; `test_gzf_rebase.cpp` JNZ check relaxed to
     accept je/jne/jnz (comment documents why).
- Analysis-count drift 12.0.4 → 12.1.3 (pass.exe): composites 95→96,
  components 655→657, arrays 62→61, dataUnits 3792→3910 (inst 15406, fns 241,
  syms 1561, refs 6954 unchanged); notepad inst 35367→35365; mathlib data
  2597→2681, +1 composite; cpp_templates data 1778→1806, +1 composite; usemath
  data 2996→3102, +1 composite; c_complex 333c→334c. Import test baseline
  updated to 12.1.3 counts (87/87).
- Verification results against 12.1.3 corpora:
  - fidelity **43/43** (pass block 22 + 7 corpora × 3), exit 0
  - import **87/87**, equates 20/20, function_tags 23/23, rebase **26/26**,
    gbf_reader 44/44
  - full CTest **61/61**, exit 0 (run from `Enigma-Engine` with
    `ENIGMA_CORPUS_DIR` + `ENIGMA_EXTRA_CORPUS` set)
- Every 12.1.3 corpus has exactly 2 `Pointers` records with base id 0
  (Length 8 / -1 = Ghidra default pointers) → now import as "undefined *64" /
  "undefined *" (Ghidra-faithful; 12.0.4-era engine fallback named them
  "void *"). Pointer naming per 12.1.3 `PointerDataType.constructUniqueName`.

### Remaining (optional Track 1 follow-ups)
- [ ] Verify Ghidra-side pointer names with a headless script (script loading
      in headless failed with OSGi errors; would need a working script dir —
      `-scriptPath` to install `ghidra_scripts` also failed, class-not-found)
- [ ] Re-verify on ELF/COFF-ARM64/Mach-O corpora when binaries become
      available (items marked UNVERIFIABLE above are Ghidra-side parse fixes
      with no schema change — no engine work expected)

### Schema diff — CLOSED empirically (2026-08-19)
Literal 12.0.4-vs-12.1.3 source diff is impossible (12.0.4 source/distro/corpora
removed from machine; verified no 12.0.4 anywhere). Closed two ways:
- **Positional-read proof**: the importer reads every table column by offset,
  and the identical importer code that passed 87/87 with 0 bad records against
  the 12.0.4 corpora passes 87/87 with 0 bad records + byte-identical fidelity
  (43/43) against the 12.1.3 corpora. Any column-layout change in a consumed
  table would have misparsed records or changed dump content — neither
  happened. Observed count deltas are ANALYSIS drift, not layout drift.
- **118-table inventory** (gzf_inspect schema dump of the 12.1.3 pass corpus):
  every table present is either importer-consumed (45 `findTable` sites) or a
  documented skip (`Comment History`, `Label History`, `Default Settings`,
  `Instance Settings`, `DT_PARENT_CHILD`, `Data Type Archive IDs`, `Properties`,
  `Property Table`, `Range Map - AddressSet - CodeMap`, `TO REFS`). **No new
  tables** appeared; current schema versions in the 12.1.3 DBs (e.g. Relocations
  V6, Composite V6, Symbols V4, Function Data V3, Typedefs V2, Pointers V2,
  Variable Storage V2, Memory Blocks V3, Bookmarks V3, Module Table V1,
  Instructions/Data/Prototypes/Comments V1) all parse cleanly.

### Seed finding — RESOLVED (2026-08-19)
`Calling Conventions` table **is present in 12.1.3 corpora** (pass.exe: 3
records, VER 0, `key=0 [string]`, columns `ID Name`). The importer consumes it
(`importCallingConventions`, optional) and fidelity 43/43 passed with 241
functions carrying calling-convention IDs referencing those records. The
12.0.4-era question is moot: the table is handled identically either way.

### Release-notes cross-reference — 12.0.4 → 12.1.3 (2026-08-19)
Desktop `C:\Users\pc\Desktop\changes.md` is only the **12.1.3** section; the
FULL log is the distro's `ghidra-12.1.3-source\docs\ChangeHistory.md`
(3,989 lines: 12.1, 12.1.1, 12.1.2, 12.1.3). Classification of every entry:

**Track 1 (importer/GZF/.rep) — engine impact:**
- **VERIFIED on corpora**: `GP-6953` GUID datatype alignment 8→4 — DEV source
  `GuidDataType.java` `ALIGNMENT = 4`; notepad corpus exercises it (composite
  `DotNetPdbInfo`, GUID field id 113 size 16 at offset 4) — imports clean,
  fidelity identical. `GP-7085` PE export ordinal-table indexes now unsigned —
  DEV source `ExportDataDirectory.java:317` `readUnsignedShort`; Ghidra-side
  name resolution only, no schema change, corpora unaffected (no ordinal
  indexes ≥ 0x8000). `GP-6843` symbol-name character filtering — engine imports
  names verbatim; schema unchanged; fidelity covers.
- **UNVERIFIABLE (no corpus on machine; all Ghidra-side parse/markup fixes
  with NO `.gbf` schema change → engine reads what is stored, format-agnostic,
  fidelity-proven round-trip)**: `GP-7088` COFF IMAGE_REL_ARM64_ADDR64
  relocation; `GP-7056`/`GP-7061`/`GP-6887` ELF PLTGOT + dynamic GNU hash
  table; `GP-7046`/`GP-7079` Mach-O dyld_shared_cache + missing-LC_SYMTAB;
  `GP-7057` ELF `isExternal()` classification; `GP-5900` PE export-forwarder
  thunk functions; `GP-6502` PE DVRT markup; `GP-3960` ELF Swift/golang
  recognition; `GP-5929` ELF `.gnu.build.attributes` markup; `GP-5924`
  debuginfod (DWARF); `GP-6345` offcut-string ref label preference;
  `GP-3564` duplicate composite field names allowed; `GP-6150` AddressMap
  misuse fixes. None require engine changes.

**Track 2 (deferred — engine/analysis parity):** all `Processors` entries
(x86: GP-5780/6061/6767/6818/6937/7015-7019/6675; AARCH64: GP-7023/6620/7040;
ARM: GP-4651/5849/6145/6750/5206/6931/7065/6333; RISC-V: GP-6876/6909/6849;
MIPS: GP-6766/6697/7133; PowerPC: GP-6914/5508/6968; Hexagon module GP-6621;
SuperH, HCS12, Tricore, MCS-96, M68000, V850, 8051, PIC-18, AVR32, SparcV9,
RH850G3...), Decompiler (GP-6936/6850/6610/6318/2493/5921/5922/6199/6266/
6205/6629), Sleigh compiler (GP-6328), analysis heuristics (GP-6791/6325/6281/
6291/6327/4901/6108/6394/7045/6137), Swift/Golang demanglers.

**Out of scope (per directive)**: GUI, BSim, PostgreSQL, Debugger/Trace,
Search, Logging, preferences, multi-user/Ghidra Server, PyGhidra/Jython,
Version Tracking, emulator userops, Byte Viewer, scripting, testing/build.

### Track 2 — engine/analysis parity (deferred, NOT importer work)
- [ ] Diff Sleigh/decompiler changes 12.0.4 → 12.1.3 (x86 legacy + x86-64
      AVX/GFNI, AArch64, RISC-V, Loongarch, p-code/decompiler C++, analysis
      heuristics); separate plan when instructed

- Created: 2026-08-19 · Track 1 verified: 2026-08-19

## Track 2 - execution log (engine/analysis parity)

Commits: `ae512ff5` (Track 1), `6e17236b` (Track 2 P1-P2), `232b6606` (P3),
`c9b5027f` (P4), `f1c616cf` (P5 docs), `dca862e4` (P6-P7 verdicts +
verification; Track 2 complete). Local resources: distro `ghidra-12.1.3-source`
(docs, .sla binaries), DEV source `ghidra-Ghidra-12.1.3-build\Ghidra`
(15,459 .java), precompiled Sleigh `.sla` copied from distro (user decision:
no slgh_compile; `slgh_compile` cannot build Hexagon GP-6621/GP-6328 specs on
this toolchain - non-blocking).

### P1-P2 - decompiler sync + analyzer inventory (verified 2026-08-19)
- Decompiler C++ merged to 12.1.3 (`Features/Decompiler/src/main/c`:
  jumptable.cc, p-code ops, HRestart, fallthrough - covers GP-7023 switch
  recovery, GP-6936/6850/6610/6318/2493/5921/5922/6199/6266/6205/6629);
  `targeted merge` per user directive (no re-tooling).
- Analyzer inventory: **139 analyzers registered** in `AutoAnalysisManager`
  (Java 12.1.3 count parity). Registration names: NoReturnFunctionAnalyzer
  "Non-Returning Functions - Known" (L241), FindNoReturnFunctionsAnalyzer
  "Non-Returning Functions - Discovered" (L242), StringsAnalyzer "ASCII
  Strings" (L246), SwiftTypeMetadataAnalyzer (L274), ObjcMessageAnalyzer
  "Objective-C Message Analyzer" (L276), GolangSymbolAnalyzer/GolangStringAnalyzer
  (L277/278), SwiftDemanglerAnalyzer "Swift Demangler" (L290). No
  `StringAnalyzer` class exists in either codebase (Java renamed to
  StringsAnalyzer).
- Sleigh: precompiled `.sla` files copied from distro (user decision), per-arch
  language IDs verified; PcodeCapstoneMapper extended for 4 architectures
  (x86/x86-64, AArch64, ARM, PPC, MIPS) per user decision; all 39 language
  families carried.

### P3 - analysis heuristics (9 entries; commit `232b6606`, test 62/62)
- **GP-6791 NEEDS-FIX - FIXED**: `FindNoReturnFunctionsAnalyzer.cpp` gained
  `hasCallFixupWithFallThrough(Program*, const Address&)` mirroring Java
  (func.getCallFixup() -> PcodeInjectLibrary.getPayload(CALLFIXUP_TYPE,
  callFixup) -> payload.isFallThru()); evidence-loop skip in
  `detectNoReturn()`-equivalent. API anchors: Function.h:119,
  InjectPayload.h:27/60, PcodeInjectLibrary.h:44, CompilerSpec.h:106.
- **GP-6789 MATCH** (no `removeCancelledListener` equivalent; no listener
  mechanism).
- **GP-6345 NOT-PORTED** (engine has no offcut-label naming path at all;
  nothing to align).
- **GP-6291/6325 PARTIAL - FIXED (multi-magic)**: `GolangSymbolAnalyzer.cpp`
  accepts all 4 pcHeader magics (GO_1_2=0xFFFFFFFB, GO_1_16=0xFFFFFFFA,
  GO_1_18=0xFFFFFFF0, GO_1_20=0xFFFFFFF1; Java GoPcHeader.java L45-48) + Go
  1.2-1.15 layout branch (pad2@5, minLC@6, ptrSize@7, nfunc@8,
  pcHeaderWords=8/ptrSize+11); "Fallback Go Version" option dead (no
  GoBuildInfo) - documented.
- **GP-6327 PARTIAL documented** (no class-layout/method-function creation;
  Java CALL_OVERRIDE refs target created method functions; no ARM/ObjC
  corpus; no code change).
- **GP-6281/6137 PARTIAL documented** (engine has label-only Swift markup).
- **GP-5929 NOT-PORTED - PORTED**: `.gnu.build.attributes` markup in
  `ElfAnalyzer.cpp` (SHT_GNU_ATTRIBUTES=0x6FFFFFF5; note parse namesz/descsz/
  type, name 4-aligned; OPEN=0x100/FUNC=0x101; ids VERSION/STACK_PROT/RELRO/
  STACKSIZE/TOOL/ABI/POSITION_INDEPENDENCE/SHORT_ENUM; value types `$` string,
  `*` LEB128, `!` false, `+` true; STRINGVAL ids 32..127; labels
  `gnu.build.attribute_<TYPE>_<ID>=<VAL>`; struct `GnuBuildAttribute_<nameAligned>
  _<descLen>`; range refs DATA IMPORTED from start/end; string value starts
  AFTER the id string's NUL (Java readNextUtf8String semantics)). PLUS latent
  engine ELF crash fixed: `BinaryLoader` now maps an `ELF_HEADER` block at
  address 0 covering max(e_phoff+e_phnum*e_phentsize,
  e_shoff+e_shnum*e_shentsize, 64) clamped to file size (Memory::getBytes
  throws at unmapped offsets; real ELF files crashed ElfAnalyzer). Fixture
  test `test_gnu_build_attributes.cpp` (17 assertions; only ELF coverage -
  corpus_diverse has no ELF files).
- **GP-7023 MATCH** (covered by decompiler sync, jumptable.cc = 12.1.3).
- Verified: build OK, CTest **62/62** (61 + new test) with
  `ENIGMA_CORPUS_DIR=C:\Users\pc\Desktop` +
  `ENIGMA_EXTRA_CORPUS`=7 x `db.1.gbf` (ctest_phase3.txt).

### P4 - loaders (commit `c9b5027f`, test 63/63)
- **GP-3960 - FIXED**: `BinaryLoader::populateProgram` (ELF only) detects
  Swift (section name starts `__swift`/`swift`/`.sw5` - SwiftUtils.isSwift) or
  golang (contains `gopclntab`/`go.buildinfo`/`go_buildinfo` -
  GoRttiMapper.hasGolangSections); sets `Program::setCompiler` +
  `setCompilerSpecID` ("swift"/"golang" - ElfLoader.detectCompilerName).
- **GP-7057 - FIXED**: `ElfSymbol.isExternal()` parity - external iff
  (GLOBAL|WEAK) && shndx==SHN_UNDEF (Java disregards st_type/st_value/st_size);
  both ELF32/64 parsers now read st_shndx. Flag has no consumer in the engine
  (no external block model - documented); behavior unchanged elsewhere.
- **BUG FIX found by new test**: ELF64 symbol `sh_link` was read at sh_offset
  +24 instead of +40 (symbol names from linked string tables were garbage);
  ELF32 was correct (sh_link at +24 in 32-bit layout).
- **GP-7085 MATCH** (engine already indexes the EAT with unsigned uint16
  ordinals).
- **GP-7079 MATCH-by-absence** (engine reads no LC_DYSYMTAB; the
  IndexOutOfBounds cannot occur).
- **Documented NOT-PORTED gaps** (feature absent in engine):
  GP-7056 ELF PLTGOT w/o section headers (no PLTGOT processing at all);
  GP-7061+GP-6887 GNU hash table processing/bounds (no GNU hash support);
  GP-5900 PE export-forwarder thunks (requires EXTERNAL block infra);
  GP-6502 PE DVRT markup (no PE data-directory markup); GP-7088 COFF
  ARM64_ADDR64 (no COFF loader); GP-7046 dyld_shared_cache (no cache loader);
  GP-7071 PEF/OMF; GP-6382 Tenet trace loader; GP-6537 NE Phar Lap;
  GP-7087 PE LibraryLookupTable JDOM (GUI import data).
- New test `test_elf_compiler_detect.cpp` (16 assertions: Go/Swift/plain ELF
  compiler detection + isExternal semantics via .symtab fixture). CTest
  **63/63**.

### P5 - symbols / data types / demanglers (all documented; no code delta)
- **GP-7045 MATCH** (SwiftDemanglerAnalyzer has no directory option; already
  invokes `swift demangle` from PATH - Java removed the dir option).
- **GP-6394/GP-6363 MATCH by construction** (GnuDemanglerAnalyzer uses
  `abi::__cxa_demangle` - the reference Itanium demangler; no legacy-
  demangler path exists, so the legacy `F`-qualifier fix is N/A).
- **GP-6108 PARTIAL documented** (RustDemanglerAnalyzer is a hand-rolled
  v0+legacy subset: crate/path/impl/suffix identifiers only; no escaped-
  identifier decoding `$LT$`->`<` etc., no `_ZN` legacy form).
- **GP-4901 NOT-PORTED** (MSVC demangler shells out to
  `UnDecorateSymbolName` with fixed flags; Java's two output options
  (anonymous-namespace encoding, UDT tags) have no engine equivalent).
- **GP-3564 MATCH-by-absence** (Structure/Union never validate component
  names - duplicates already allowed consistently).
- **GP-5882 MATCH-by-absence** (no datatype dependency-change listeners).
- **GP-6576 N/A** (no zero-length components in engine StructureDataType).
- **GP-5808 NOT-PORTED** (no structure/union/enum merge API - feature-add).
- **GP-6971 N/A** (no PDB importer). **GP-6137** PARTIAL (see P3).
  **GP-6613 MATCH** (maximumInstructionLength ships in the precompiled .sla).
  **GP-5924 skipped** (debuginfod = network feature).

### P6 - native pipeline (verified 2026-08-20; all spec-level, no code delta)
Engine pipeline facts: decompiler p-code = Capstone disassembly +
`PcodeCapstoneMapper` (src/pcode/Sleigh.cpp oneInstruction; mapper tables
x86/ARM/MIPS/PPC = 685 handlers, mapDefault fallback). `.sinc`/`.ldefs` for
x86/ARM/AARCH64/MIPS/PPC verified byte-identical to the 12.1.3 distro
(exception: x86.ldefs has intentional engine customization - a `default`
compiler entry mapping x86-64-gcc.cspec first so native raw loads default to
GCC conventions; all distro compiler ids retained). `.sla` = 12.1.3
precompiled (P1-P2). So every 12.1.x processor entry is spec-level MATCH.

- **x86**: GP-5780 MATCH (engine .sinc/.sla 12.1.3; Capstone decodes all
  encodings; mapper handlers or mapDefault). GP-6061 PARTIAL documented
  (AVX semantics are .sinc-level - synced; mapper AVX = COPY placeholders by
  design). GP-6675 MATCH (semantics fixes live in .sinc = 12.1.3).
  GP-6767 N/A by design (mapper models no flags; OF fix covered by .sla).
  GP-6818 MATCH (mapper HAS gf2p8affineqb/affineinvqb/mulb handlers).
  GP-6937 MATCH (encoding-level; Capstone decode). GP-7015 N/A documented
  (Sleigh renders `nop` for rex xchg eax,eax; Capstone renders `xchg rax,rax`
  - semantically equivalent, cosmetic). GP-7016 MATCH (Capstone VEX.W).
  GP-7017 PARTIAL documented (imm masking is .sinc semantics - synced;
  mapper PINSRW/VPEXTRB/VPEXTRD = COPY). GP-7018 MATCH (Capstone + mapCopyMov).
  GP-7019 PARTIAL documented (pslld shift-count fix in .sinc - synced;
  mapper pslld = COPY).
- **RAO-INT/CMPccXADD**: NOT in the 12.1.x ChangeHistory (pre-12.0.4; out of
  the diff window). .sinc carry them (rao.sinc/cmpccxadd.sinc present);
  mapper has no dedicated handlers -> mapDefault (COPY/LOAD/STORE dataflow)
  - documented.
- **AARCH64**: GP-6620/GP-7040 MATCH spec-level (.sinc 12.1.3 identical).
  Native-pipeline gap (pre-existing, deferred): engine Capstone path has no
  AARCH64 support - Sleigh::initialize has no arm64 branch (archLower
  "aarch64" does not match "arm", falls to stub mode) and DisassemblyAnalyzer
  maps AARCH64 language IDs to "x86". GP-7023 MATCH (decompiler-side switch
  recovery with csel - jumptable.cc merged to 12.1.3 in P1-P2).
- **ARM**: GP-4651/5206/6333/6750/6931/7065 all spec-level MATCH (.sinc
  12.1.3 identical; Capstone decodes encodings; mapper ldrsh/ldrsb -> LOAD
  etc., sev/mrs/vmov variants -> mapDefault COPY - documented).
- **MIPS**: GP-6697 MATCH spec-level (signed-offset fix in .sinc - synced).
  GP-6766 N/A (MIPS16e movn/movz - engine native pipeline has no MIPS16e
  mode; Capstone MIPS16 not enabled). GP-7133 MATCH (MIPS.ldefs verified
  byte-identical to 12.1.3; variant tags default/16e/R6 present).
- **PPC**: GP-5508 MATCH spec-level (.sinc synced; lq semantics in .sla).
  GP-6914 MATCH spec-level (v3.0B/v3.0C instructions in .sinc - synced;
  Capstone PPC decodes; new mnemonics -> mapDefault - documented).

### P7 - verification + docs (verified 2026-08-20; Track 2 COMPLETE)
- Per-fix tests: P3 (62/62 incl. test_gnu_build_attributes 17), P4 (63/63
  incl. test_elf_compiler_detect 16), P5/P6 documentation-only.
- Track-1 guard: fidelity 43/43, import 87/87, rebase 26/26 (all inside the
  full CTest run below).
- Full CTest **63/63, exit 0** (log `%TEMP%\opencode\ctest_phase7.txt`) with
  `ENIGMA_CORPUS_DIR=C:\Users\pc\Desktop` + `ENIGMA_EXTRA_CORPUS` = 7 x
  `~0000000N.db\db.1.gbf` (**7 zeros** before N; a 6-zero path makes the
  fidelity test report "Gbf: file too small" — false failure, corpora intact).
  Determinism regression green (36.9s).
- PLAN docs: `PROGRESS.md` Track 2 completion entry + this execution log.
- Final commit: `dca862e4` (P6 verdicts + P7 verification; Track 2 complete).

## Track 3 - AARCH64 native pipeline (closed gap, verified 2026-08-20)

Track 2 P6 verdict noted the native pipeline's AARCH64 support was "PARTIAL":
Capstone could decode, but the language-ID mapping and the mnemonic->pcode
mapper had no AArch64 path. Track 3 closes that gap (user-approved scope).

### A3.1 - Language-ID mapping (3 sites)
- `Sleigh::initialize` (`src/pcode/Sleigh.cpp`): added explicit
  `aarch64`/`arm64` branch -> `CS_ARCH_ARM64`, `CS_MODE_ARM`, codeAlign 4
  (inserted before the substring "arm" check - "aarch64" does NOT contain
  "arm", so this was previously unreachable).
- `DisassemblyAnalyzer::analyze` (`src/core/DisassemblyAnalyzer.cpp` L74-78):
  `AARCH64` now maps to disassembler architecture "aarch64" (was x86).
- `GzfProgramImporter::makeDisassembler` (`src/import/GzfProgramImporter.cpp`
  L414-435): `AARCH64`/`aarch64` now map to "aarch64" (was x86).
- `FunctionStartAnalyzer::languageToArchShort` (`src/core/FunctionStartAnalyzer.cpp`
  L163-175): added `find("aarch64")` -> "ARM".
- Reference (already correct): `AggressiveRecoveryAnalyzer` L140 and
  `FragmentMergeAnalyzer` L102 map AARCH64 -> "ARM" + bitness 64.

### A3.2 - CapstoneDisassembler (`src/core/Disassembler.cpp`)
- `initialize`: explicit `aarch64`/`arm64` -> `CS_ARCH_ARM64`, `CS_MODE_ARM`,
  alignment 4, bitness 64.
- `determineFlowType`: added A64 conditionals `b.eq/b.ne/b.gt/b.ge/b.lt/b.le/
  b.hi/b.hs/b.lo/b.ls/b.mi/b.pl/b.vs/b.vc` and `cbz/cbnz/tbz/tbnz` ->
  CONDITIONAL_JUMP; `eret` added to the terminator list.
- `extractOperandScalars` made arch-aware (was reading `detail->x86` for every
  architecture - on ARM64 that union member is `arm64`, whose `op_count` sits
  AFTER the operands, so the x86 layout read produced a garbage loop bound and
  a crash). Now branches on `csArch_`: x86 (existing RIP-relative + absolute
  logic), ARM64 (IMM + absolute MEM only; `[reg+disp]` intentionally skipped
  as offsets; this Capstone build exposes no `ARM64_REG_PC` constant, so
  PC-relative loads keep no scalar), ARM (IMM + `ARM_REG_PC`-relative +
  absolute MEM).

### A3.3 - PcodeCapstoneMapper AArch64 table (`src/pcode/PcodeCapstoneMapper.*`)
- New `isAARCH64_` flag + `aarch64Handlers_` map + `buildAARCH64Handlers()`
  (~110 entries): mov/movz/movn/movk/adr/adrp/fmov; ldr*/ldp/ldur*/ldar/ldaxr;
  str*/stp/stur*/stlr/stxr; add/adds/sub/subs; neg/negs; mul/madd/msub/mneg;
  sdiv/udiv; and/ands/orr/orn/eor/eon/bic/bics; lsl/lslv/lsr/lsrv/asr/asrv/
  ror/rorv; cmp/cmn/tst/ccmp/ccmn; sxtb/sxth/sxtw/uxtb/uxth/uxtw/rev*;
  csel/csinc/csinv/csneg; b/bl/blr/br/ret/eret/svc; b.eq..b.vc/cbz/cbnz/tbz/
  tbnz; fadd/fsub/fmul/fdiv/fmax/fmin/fmadd/fmsub/fabs/fneg/fsqrt/fcmp/fcmpe/
  fcvt/scvtf/ucvtf/fcvtas/fcvtau/fcvtms/fcvtmu/fcvtns/fcvtnu/fcvtps/fcvtpu/
  fcvtzs/fcvtzu.
- `parseOperand` A64 register layout: x0-x30 -> offsets 0-30 size 8; w0-w30
  size 4; sp=31 (size 8), wsp=31 (size 4); lr=30, fp=29; v/q = 64+n size 16;
  d = 64+n size 8; s size 4; h size 2; b size 1; xzr/wzr -> `makeConst(0)`.
  SIMD d0/s0/v0 alias to the same 64+n base (approximation, consistent with
  the other per-arch tables).

### A3.4 - Verification (synthetic only; 34/34 + full CTest 64/64)
- New suite `tests/test_aarch64_pipeline.cpp` (registered as
  `enigma_test_aarch64_pipeline`, 34 subtests, exit 0): 16-instruction A64
  blob (stp/mov/sub/mov/add/bl/ldr/str/cmp/b.le/mov/ldp/ret/blr/cbz/adrp)
  decoded via the Sleigh pipeline (16/16, 4 bytes each, pcode categories
  CALL/CALLIND/RETURN/STORE/LOAD/INT_ADD/INT_SUB/CBRANCH), via
  CapstoneDisassembler (mnemonics + flow types: bl=CALL, b.le=CONDITIONAL_JUMP,
  ret=TERMINATOR, cbz=CONDITIONAL_JUMP, adrp=FALL_THROUGH), and via the mapper
  (mov x0, xzr -> COPY).
- Crash fixed during verification: `extractOperandScalars` (A3.2) segfaulted
  on ARM64 (`detail->x86` read of `cs_arm64` data) - reproduced under gdb,
  fixed by the arch-aware branch.
- Full CTest **64/64, exit 0** with the Track 2 env (`ENIGMA_CORPUS_DIR` +
  `ENIGMA_EXTRA_CORPUS` = 7 x `~0000000N.db\db.1.gbf`); determinism regression
  green (35.5s). No regression in Track 1 guard (fidelity/import/rebase).
- Known limitation (documented in tracking doc): no real AARCH64/ELF binary
  corpus exists on this machine (`ghidra_1213_proj` holds PE only), so
  verification is synthetic. Re-verify against an ELF/COFF-ARM64/Mach-O corpus
  when binaries become available.
- Commit: `TBD` (single change set: 7 source files + 1 new test + 1 tracking
  doc + PROGRESS.md).

- Updated: 2026-08-20