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

### A3.4 - Verification (34/34 synthetic + real-ELF end-to-end; full CTest 64/64)
- New suite `tests/test_aarch64_pipeline.cpp` (registered as
  `enigma_test_aarch64_pipeline`, 44 subtests, exit 0): 16-instruction A64
  blob (stp/mov/sub/mov/add/bl/ldr/str/cmp/b.le/mov/ldp/ret/blr/cbz/adrp)
  decoded via the Sleigh pipeline (16/16, 4 bytes each, pcode categories
  CALL/CALLIND/RETURN/STORE/LOAD/INT_ADD/INT_SUB/CBRANCH), via
  CapstoneDisassembler (mnemonics + flow types: bl=CALL, b.le=CONDITIONAL_JUMP,
  ret=TERMINATOR, cbz=CONDITIONAL_JUMP, adrp=FALL_THROUGH), via the mapper
  (mov x0, xzr -> COPY), and end-to-end on a real cross-compiled AArch64 ELF
  (`tests/corpus/aarch64_fib.elf`: load -> architecture AARCH64 -> language
  `AARCH64:LE:64:v8A` -> populateProgram -> entry-point disassembly).
- Crash fixed during verification: `extractOperandScalars` (A3.2) segfaulted
  on ARM64 (`detail->x86` read of `cs_arm64` data) - reproduced under gdb,
  fixed by the arch-aware branch.
- **Real-ELF gap found by the end-to-end run** (a second instance of the
  "AARCH64 lacks the ARM substring" bug class): `BinaryLoader::guessLanguageFromArch`
  tested `find("ARM")`, which never matches "AARCH64" - so the AARCH64 ELF's
  program language stayed "unknown" and every analyzer that calls
  `createDisassembler` received an empty architecture string. Fixed by adding
  an explicit AARCH64 branch returning `AARCH64:LE:64:v8A` (the variant tag
  that actually exists in the distro `.ldefs`; `:default` is not a real
  AARCH64 variant). Verified on the real ELF: `_start` and `fib` both decompile
  to correct C (global write via `adrp/add/str` resolves to `ptr_0x220230`,
  recursion + tail structure correct).
- Corpus regression extended: `tests/corpus/aarch64_fib.elf` (1640-byte
  freestanding A64 ELF cross-compiled with clang `-target aarch64-linux-gnu`
  + lld) + `tests/corpus/expected/aarch64_fib.elf.c` baseline; Python
  `test_corpus_regression.py` runs it (16/16 raw+ELF tests pass).
- Full CTest **64/64, exit 0** with the Track 2 env (`ENIGMA_CORPUS_DIR` +
  `ENIGMA_EXTRA_CORPUS` = 7 x `~0000000N.db\db.1.gbf`); determinism regression
  green (38.0s). No regression in Track 1 guard (fidelity/import/rebase) or
  the corpus regression.
- Known limitation lifted: verification now covers a real AArch64 ELF
  (single-function freestanding binary). A larger ELF/COFF-ARM64/Mach-O
  corpus would broaden coverage; the mapper table's ~110 entries are exercised
  only partially by the synthetic blob + this binary.
- Commits: `6bdae421` (Track 3 initial: mapper + pipeline + synthetic test) +
  `9eb1be20` (real-ELF verification: guessLanguageFromArch AARCH64 fix,
  corpus ELF + baseline, test + regression extension).

- Updated: 2026-08-20

## Track 4 - ARM32 / MIPS / PowerPC real-ELF verification (closed, 2026-08-20)

Track 3 verified AARCH64 with a real cross-compiled ELF and caught the
"AARCH64 lacks 'ARM' substring" bug class twice. Track 4 applies the same
methodology to the remaining native-pipeline archs (ARM32, MIPS, PowerPC):
cross-compile real ELFs with clang 22.1.8 (`D:\msys64\mingw64\bin\clang.exe`,
`-target <t> -O1 -fno-inline -nostdlib -static -ffreestanding
-fno-asynchronous-unwind-tables -fuse-ld=lld -Wl,-e,_start`), decompile
end-to-end with `enigma_decompile_full`, fix every gap found. **No commits
made in this track - user commits.**

### A4.1 - ELF loader endianness (big-endian PPC was undetectable)

- `parseELF()` read all header/section/symbol/dynamic fields with LE
  reinterpret_cast reads. A BE PPC ELF (e_machine 0x14) came out as
  e_machine 0x1400 (unknown arch), entry point byte-swapped
  (0xd8000110 vs 0x100100d8) -> "Unsupported architecture: " and
  `guessLanguageFromArch` fell through to x86 defaults.
- Fix: `elf16/elf32/elf64/elfs32/elfs64` byte-swap helpers (gated on
  `elfBigEndian_` = EI_DATA byte `rawData_[5] == 2`), used across
  `parseELF`, `parseELF32/64`, `parseELF32/64Symbols`,
  `parseELF32/64Dynamic`. Also removed bitness_ overrides per e_machine
  (bitness comes from EI_CLASS byte 4; EM_MIPS 0x08 is 32/64).
- Added `case 0x14` (EM_PPC) + `case 0x15` (EM_PPC64) -> "PowerPC".
- `isBigEndian()` now returns EI_DATA==2 for ELF (was always false).
- `guessLanguageFromArch` gained `bool bigEndian` param (default false,
  header default keeps old callers compiling): MIPS -> MIPS:LE/BE:32:default,
  PowerPC -> PowerPC:BE:32:default / PowerPC:LE:32:default,
  PowerPC 64 BE -> PowerPC:BE:64:default, PowerPC 64 LE ->
  PowerPC:LE:64:64-32addr (no PowerPC:LE:64:default exists in ppc.ldefs),
  ARM BE -> ARM:BE:32:v8. Callers updated: `populateProgram`
  (BinaryLoader.cpp:231), `enigma_decompile_full.cpp:593`.
- `extractOperandScalars` got `cs_mips` + `cs_ppc` branches (MIPS_REG_PC
  PC-relative MEM -> resolved target; IMM -> Scalar; MEM with no base ->
  disp Scalar). Previously MIPS/PPC fell into the `detail->x86` branch -
  same UB crash class as the ARM64 segfault from Track 3.

### A4.2 - Capstone BE mode propagation (analysis pipeline)

- `CapstoneDisassembler::initialize` set `CS_MODE_BIG_ENDIAN` at the top but
  the ARM/MIPS/PPC branches overwrote `csMode` with the bitness mode,
  discarding it. BE PPC decoded as LE (1 of 16 entry bytes decoded).
- Fix: OR `CS_MODE_BIG_ENDIAN` into csMode in the ARM/MIPS/PPC branches.
- Hardcoded `createDisassembler(arch, bitness, false)` callers made
  endian-aware: `FunctionStartAnalyzer` (6 sites, new
  `languageIsBigEndian(lidStr)` = `lidStr.find(":BE:")`), `DisassemblyAnalyzer`,
  `FragmentMergeAnalyzer`, `GzfProgramImporter::makeDisassembler`
  (derives from language ID). `AggressiveRecoveryAnalyzer` +
  `AggressiveInstructionFinderAnalyzer` already used `lang->isBigEndian()`.
- `Sleigh::initialize` (experimental pipeline) gained `setBigEndian(bool)`;
  ORs the BE mode for ARM/MIPS/PPC Capstone handles.

### A4.3 - Corpus + tests

- New corpus ELFs (all from the same freestanding fib/sum/max3 source,
  `-fno-inline` keeps all functions; `sum()` constant-folds to 0x6f):
  `tests/corpus/arm32_fib.elf` (e_machine 0x28, LE32, 1292 B),
  `tests/corpus/mipsel_fib.elf` (e_machine 0x08, LE32, 1684 B),
  `tests/corpus/ppc32_fib.elf` (e_machine 0x14, BE32, 1124 B).
  Baselines `tests/corpus/expected/<name>.c` (UTF-8 no BOM, trailing blank
  line matches tool stdout; `Set-Content` BOM pitfall avoided via
  `[System.IO.File]::WriteAllText` + `UTF8Encoding($false)`).
- `test_corpus_regression.py` extended: 19/19 pass (16 previous + 3 new).
- `test_aarch64_pipeline.cpp` section 5: per-arch loop
  (arch/bitness/bigEndian/language-guess/entry/populateProgram/language ID/
  createDisassembler/entry disasm >= 4 insns @ 4 bytes). 74/74 pass.

### A4.4 - End-to-end decompile verification

- ARM32: `_start` calls sum()/fib(10), `fib` recursion correct,
  `sum` -> 0x6f.
- MIPS (LE): same correctness; `g_glob` write appears as
  `**(int32_t**)(arg_t9 + 0x100f0)` (MIPS gp-relative addressing kept
  symbolic - known quality limitation, not a pipeline failure).
- PowerPC (BE): `fib` recursion correct (different loop form), `sum` ->
  0x6f, `*ptr_0x10020190 = ...` (global write resolved to absolute
  address; BE data section addresses now correct after A4.1).
- Full CTest 64/64 exit 0; determinism 47.4s; corpus regression 19/19.

## Track 5 - Large stripped x86-64 ELF scale verification (closed, 2026-08-20)

Track 4 verified ARM32/MIPS/PPC at small scale (3 tiny ELFs). Track 5
stress-tests the pipeline at scale with a real stripped 1.1 MB x86-64 ELF
(`C:\Users\pc\Desktop\ELF-Binary`, e_machine 0x3E, EXEC, no symbol table,
~862 KB of `.text` at 0x400130, entry 0x4038b1). The analysis pipeline
discovers 3192-3213 function starts; the decompiler previously never saw
most of them. **No commits made in this track - user commits.**

### A5.1 - Analysis-time pointer size bug (found at scale)

- `ApplyDataArchiveAnalyzer::added` computed the archive pointer size as
  `lang ? lang->getDefaultSpace()->getSize()/8 : 4`. During analysis the
  ProgramDB holds ONLY a language ID string - no `Language*` object is ever
  attached (`Program::setLanguage` has no callers), so the fallback `4` was
  always taken. On 64-bit ELFs the GCC/Windows type archives (`FILE`,
  `va_list`, `HANDLE`, `LPVOID`, ...) were materialized as 4-byte pointers.
  Observed as "Detected format: ELF, pointer size=4" on the 64-bit ELF.
- Fix: when `lang` is null, parse the third `:`-separated component of the
  language ID ("family:endian:size:variant") and derive ptrSize
  (16/24 -> 2, <=32 -> 4, else /8). Now prints pointer size=8 for the
  x86-64 ELF. Real Ghidra builds the language from the ID and reads
  `getDefaultSpace()->getSize()`; the ID-derived size is equivalent for the
  analysis-phase archive materialization.

### A5.2 - -all flag (decompile every discovered function)

- The tool's BFS only follows entry-reachable calls (the stripped ELF's
  entry reaches just 23 functions); the other ~2970 analysis-discovered
  functions were bridged into the decompiler scope but never decompiled.
- Added `-all` to `enigma_decompile_full`: after the BFS, iterate the
  decompiler global scope (MapIterator over FunctionSymbols, same pattern as
  `AnalysisBridge::bridgeImportSignatures`) and decompile every function in
  executable memory, skipping CRT and already-processed ones; honors
  `-max-func`. Full run: 2964 functions decompiled in ~67s (2970 expected -
  CRT-filtered), deterministic (two runs byte-identical).

### A5.3 - Corpus + tests

- `tests/corpus/large_x86_64.elf` (1,131,168 B) + baseline
  `tests/corpus/expected/large_x86_64.elf.c` from `-all -max-func 50`
  (42 functions, 31,834 bytes; baseline captured via stdout like
  `regenerate_corpus.py`, NOT `-o` which writes CRLF - pitfall: the expected
  file must be LF like the other baselines).
- `test_corpus_regression.py` + `regenerate_corpus.py` extended:
  **20/20 pass**. Full CTest **64/64 exit 0** (determinism 50.0s).
- Known artifact: one `halt_baddata` in the full output
  (`func_0x4a975d`) - the function-start scan landed on `ff ff` padding
  before valid code at a stripped binary's alignment gap; expected
  behavior for stripped binaries, not a pipeline defect.

- Updated: 2026-08-20

## Track 6 - Dynamically-linked ELF import resolution (closed, 2026-08-20)

Track 5 covered a stripped (static, no imports) ELF. Track 6 verifies a
real dynamically-linked ELF end-to-end: `C:\Users\pc\Desktop\crack_tests\
impossible` - an AArch64 PIE (ELF64, DYN, entry 0xc78, `.dynsym` 0x320,
`.plt` 0x14b0, `.got` 0x5758, `.got.plt` 0x5780, `.rela.dyn` 0x6a8,
`.rela.plt` 0x750, 8,176 B). **No commits made in this track - user
commits.**

### A6.1 - ELF dynamic import gap (found at recon)

- Dynamically-linked ELF imports were NOT resolved to names: `entry()`
  showed `(*ptr_0x5798)()` instead of `__libc_init()`. Three causes:
  1. `parseELFImports` only extracted DT_NEEDED library names
     (`functionName="(dynamic)"`, address 0) - no function imports.
  2. `parseELFSymbols` skips undefined symbols (value 0), which is exactly
     what `.dynsym` entries for imports look like.
  3. No ELF relocation parsing at all - no SHT_RELA/SHT_REL, no
     JUMP_SLOT/GLOB_DAT handling, so GOT slots and PLT stubs had no names.
- PE imports worked because the PE IAT holds the function VA; ELF GOT slots
  are zeroed in the file (runtime-resolved), so the PE-style 8-byte IAT read
  can never name an ELF import.

### A6.2 - Fix: `parseELFRelocations` in `BinaryLoader.cpp`

- Added `parseELFRelocations()` (called after `parseELFImports`), with
  ELF32/ELF64 variants:
  - Iterates SHT_RELA (4) / SHT_REL (9) sections (`.rela.plt`, `.rela.dyn`).
  - Resolves each entry's symbol name through the linked symbol table's
    string table (relocation `sh_link` -> symtab, symtab `sh_link` -> strtab).
  - JUMP_SLOT relocations: adds an import at the GOT slot (r_offset) AND at
    the PLT stub (`plt_vaddr + pltHeader + stubIdx * stubSize`) so both the
    indirect call `(*_ptrace)()` and the call site `ptrace()` resolve.
    PLT layout per arch: AARCH64 header 32/stub 16; ARM 20/12; MIPS/PPC/
    x86 16/16 (see `pltLayout`). JUMP_SLOT types: x86 7, ARM 22,
    AARCH64 0x402, MIPS 2, PPC 21, RISCV 5 (`jumpSlotRelocType`).
  - GLOB_DAT / data imports (stdin, stdout): import at the GOT slot only.
- Result: 33 imports (15 JUMP_SLOT x 2 slots + 2 GLOB_DAT + 1 DT_NEEDED),
  `entry()` calls `__libc_init()`, all 15 PLT stubs named (`ptrace`,
  `syscall`, `scanf`, `malloc`, `free`, `setvbuf`, `prctl`, ...).

### A6.3 - Fix: PE-only IAT read in `enigma_decompile_full`

- The tool's import loop read 8 bytes at each import address and mapped the
  value as the function VA (the PE IAT trick). For ELF, `.got.plt` slots in
  the file contain the lazy-binding PLT0 placeholder (0x14b0) - so every
  JUMP_SLOT import mapped `symbolNames[0x14b0] = name`, the last one
  (`prctl`) won, and the PLT0 thunk function at 0x14b0 was wrongly named
  `prctl` (two `prctl` functions in output, one dereferencing the reserved
  slot 0x5790). Guarded the IAT read with `getFormatName() == "PE"`.

### A6.4 - Pre-existing, unrelated pipeline error

- `Analysis pipeline error: Writing is not allowed` on this binary is
  pre-existing (reproduced with relocations disabled - Imports: 1, same
  error): the `ELF_HEADER` block (address 0, read-only) overlaps this PIE's
  low-VA sections. Caught in the tool (falls back to direct symbolNames
  bridging); output unaffected. Not caused by Track 6.

### A6.5 - Corpus + tests

- `tests/corpus/aarch64_pie_dyn.elf` (8,176 B, the `impossible` binary) +
  baseline `tests/corpus/expected/aarch64_pie_dyn.elf.c` from
  `-all -max-func 50` (10 functions incl. 9 named import stubs). Deterministic
  (two runs byte-identical).
- `test_corpus_regression.py` + `regenerate_corpus.py` extended:
  **21/21 pass**. Full CTest **64/64 exit 0** (determinism 32.1s).

- Updated: 2026-08-20

## Track 7 - Cross-arch dynamic-import resolution (closed, 2026-08-20)

Track 6 verified dynamic-import naming on one arch (AArch64 PIE). Track 7
applies the same verification to the remaining native-pipeline archs by
cross-compiling dynamically-linked ELF shared objects with clang 22.1.8 +
lld (`-shared -nostdlib -ffreestanding`, undefined function/data refs ->
lld emits PLT/GOT + JUMP_SLOT/GLOB_DAT relocs): `x64_dyn.elf` (R_X86_64_*,
RELA), `arm_dyn.elf` (R_ARM_*, **REL** format), `ppc_dyn.elf` (R_PPC_*),
`mips_dyn.elf`. **No commits made in this track - user commits.**

### A7.1 - ARM: wrong PLT layout crashed the tool

- Track 6 assumed ARM PLT = 20-byte header + 12-byte stubs (binutils
  layout). lld emits a 32-byte header (16 bytes of PLT0 code + 16 bytes of
  `d4` padding) with 16-byte stub slots, so the stub-import addresses landed
  at 0x103b4 + 12i - on the padding and one slot behind the real stubs.
  The tool crashed (0xC0000005) creating functions at mid-`.plt` padding
  addresses, and every stub got the PREVIOUS symbol's name.
- Fix: `armPltStubLayout()` locates the real stub base and stride from the
  `.plt` bytes - every ARM stub starts with `add ip, pc, #imm`
  (0xe28fc600); the first two matches give the base and stride. Linker-
  independent (works for lld 32/16 and binutils 20/12). Both ELF32 and ELF64
  parsers now use `{stubBase, stubSize}` instead of the header-based math.

### A7.2 - PPC: no contiguous stub region (phantom imports)

- PPC's `.plt` is a GOT-style 4-byte slot table (JUMP_SLOT r_offsets point
  into it, values are stub addresses in `.text` already named by lld's
  `.plt_pic32.*` symbols). Track 6's `header + idx*stub` math produced
  phantom imports at wrong addresses. Fix: `pltLayout` returns `{0, 0}` for
  PPC and MIPS (MIPS has no `.plt` either - it uses `.MIPS.stubs`), and the
  stub-import push is gated on `stubSize > 0`. PPC call sites now resolve to
  the real `.plt_pic32.*` symbol names; `*_g_data` data import works.

### A7.3 - Verified results per arch

- **x86-64** (10 JUMP_SLOT + 1 GLOB_DAT, RELA): all 10 stubs named, calls
  show `fib()`, `prctl()`, ...; recursive `fib` decompiles through its PLT
  stub; `_g_data` resolved. Layout {16, 16} already correct.
- **ARM** (10 JUMP_SLOT + 1 GLOB_DAT, REL): crash fixed; every stub derefs
  its own GOT slot (`(*_prctl)()` inside `prctl()`), `_start` calls all 10
  named imports, `*_g_data` resolved.
- **PPC** (10 JMP_SLOT + 1 ADDR32 data reloc): stubs named via `.plt_pic32.*`
  symbols, calls + recursion correct, `*_g_data` resolved.
- **MIPS**: lld emits NO dynamic relocations for MIPS `-shared` (GOT holds
  lazy-binding placeholders, no `.rel[a].plt`/`.rel[a].dyn`), so imports stay
  unnamed GOT-relative (`arg_t9 + offset`) - an lld artifact, not a loader
  gap; documented as a known limitation.

### A7.4 - Corpus + tests

- `tests/corpus/{x64_dyn,arm_dyn,ppc_dyn,mips_dyn}.elf` (2,720-3,680 B) +
  baselines from `-all -max-func 50` (deterministic, two runs byte-identical;
  AArch64 baseline byte-unchanged at 1425 B - no regression).
- `test_corpus_regression.py` + `regenerate_corpus.py` extended:
  **25/25 pass**. Full CTest **64/64 exit 0** (determinism ~32-41s, varies
  with load).

## Track 8 - GUI feature gaps (closed, 2026-08-20)

Track 1-7 closed backend/loader gaps. Track 8 fixes the four GUI gaps audited
in `C:\Users\pc\Desktop\gaps\main-gaps.md`: features that are fully built and
tested in the engine but never reached the Qt interface. **No commits made in
this track - user commits.**

### A8.1 - Disassembly vs. HexView visibility scope

- `DisassemblyModel::buildIndex` filtered out every non-executable block
  (`if (!(block->getFlags() & FLAG_EXECUTE)) continue;`), so `.rdata`/`.data`/
  `.rsrc` were invisible to the Disassembly window and `addressToRow(addr)`
  returned -1 for any data address (Hex -> ASM sync stuck on the nearest
  previous instruction).
- Fix: new `DisasmRow::Kind::DataSection`. `buildDataSections()` emits one
  banner row per non-executable initialized block (`; === .rdata (0x.. - 0x..)
  ===`) plus a 16-byte hex+ASCII dump row per chunk, merged into the address-
  ordered index. Every byte of every chunk is mapped in `addressToRow_` so
  `addressToRow()` resolves data addresses exactly. `seek()`/`applySelection()`
  walk-back now accepts a containing `DataSection` row, and `lineText()`/
  `rowTokens()` render them (search and selection work over data rows).

### A8.2 - Equate system connected to the disassembly

- `DisassemblyFieldView::tokenizeOperands` rendered every numeric constant raw
  (`0x20`) even though the EquateTable imports bindings and its tests pass
  (20/20).
- Fix: tokenizer now tracks the Ghidra operand index (top-level comma count)
  and queries `EquateTable::getEquate(addr, opIndex, value)` for each hex
  literal; matches render as the equate name with a new `TokenKind::Equate`
  token (amber) instead of the raw number. Works in both the indexed and
  fallback disassembly paths.

### A8.3 - Advanced comment system connected to the disassembly

- `buildTokensForDecoded` only ever showed gap text; user/imported comments
  (EOL / Pre / Post / Plate / Repeatable) stored on `CodeUnit` were never
  read by the GUI.
- Fix: after tokenizing operands, the view queries
  `Listing::getCodeUnitAt(addr)` and appends the non-empty comment fields
  (EOL, repeatable, post, plate, pre) as a green `; ...` token at line end.

### A8.4 - String injection in the decompiler GUI

- The CLI (`enigma_decompile_full.cpp` `resolveStringRefs`) turns `(char *)0xHEX`
  pointer arguments into C string literals, but the GUI decompiler
  (`MainWindow` STEP 6 -> `DecompilerView`) never did, so strings appeared as
  hex addresses.
- Fix: `DecompilerView` gained a program pointer (`setProgram`, wired at all 5
  program-swap sites in MainWindow) and two helpers: `readStringAt()` reads
  up to 256 printable bytes from program memory at a VA; `tryResolveStringToken()`
  detects the `( <type> * ) 0x...` cast pattern in the token history (both the
  markup path `documentFromMarkup` and the fallback path `tokenizeCLine`) and
  replaces the hex literal with an escaped string-literal token.

### A8.5 - Verification

- Full build clean (85 targets, incl. `enigma_gui`). Corpus regression **25/25**,
  full CTest **64/64 exit 0** - no engine/CLI regression.
- GUI behavior verified by code inspection + build (no GUI test harness exists);
  run `enigma_gui.exe` and navigate to a data section / import a Ghidra project
  to see the new data rows, equate names, comments and string literals.

- Updated: 2026-08-20
---

## Track 9 - Function Entry Boundary Trimming (Task 1.4, backlog P1) (closed, 2026-08-20)

Backlog item 1.4 from `C:\Users\pc\Desktop\gaps\ENIGMA_ENGINE_GAPS_MASTER_PLAN.md`
(also `GHIDRA_12_1_3_ENGINE_GAPS.md`): Function Start Search could create
functions whose entry point sits on alignment padding (`0x90`/`0x66 0x90`/
`0x0F 0x1F`/`0xCC` runs). `findZeroPrologueFunctions`/`findCallDestinations`
skip first-byte `0xCC`/`0x00` but ALLOW `0x90`, so a call targeting padding
produced a `func_0x...` entry anchored on NOP bytes. Acceptance: zero function
entries on padding bytes.

### Implementation

- `src/core/FunctionStartAnalyzer.cpp`:
  - `trimPaddingEntry(Memory*, Disassembler*, const Address&)` - walks forward
    over consecutive instructions that decode as `nop`/`int3` (Capstone via
    the cached `createDisassembler` handle; bounded 64 instructions), returns
    the first real instruction address, or an INVALID address when the padding
    runs to the block boundary. Fast pre-filter: entry first byte must be
    0x90/0xCC/0x66/0x0F; any non-padding first byte is never touched. The
    disassembler walk makes the pre-filter safe (`0F 05` syscall, `66 89`
    real instructions etc. stop the walk at length 1).
  - `trimPaddingFunctionEntries(Program*, TaskMonitor*)` - post-pass at the
    END of `FunctionStartAnalyzer::added()` (after all 7 discovery passes +
    edge cases). Per candidate:
    - invalid walk (padding to block end) => DROP the phantom function
      (`removeFunction`);
    - another function already owns the trimmed address => DROP the phantom;
    - otherwise MOVE: `removeFunction(entry)` + `createFunction(name,
      trimmed, body, SourceType::ANALYSIS)` preserving the auto-generated name
      and any body tail already expanded past the padding. Guard: never steal
      an address inside a different function's body.
  - `added()` summary message extended with `trim:<N>`.
- No changes to the discovery passes themselves - the trim runs last so every
  discovery source (pdata, pattern, call, jmp, multi, zero-prologue, wrapper,
  edge cases) is covered uniformly.

### Test

- New suite `tests/test_function_boundaries.cpp` (registered as
  `enigma_test_function_boundaries`, 15/15): synthetic ProgramDB
  (`x86:LE:64:default`, 0xC0-byte executable `.text` block) with three
  call targets on padding + one real entry preceded by padding:
  - MOVE: `90 90 | 4C 89 44 24 08 C3` (padding + `mov [rsp+8],r8`) =>
    entry moves 0x1058 -> 0x105A, name `func_0x1058` preserved;
  - DROP (owned): `90 90 90 | 55 48 89 E5 C3` (pattern pass already owns the
    trimmed entry) => phantom at 0x1030 removed, `func_0x1033` kept;
  - DROP (block end): 32-byte NOP run at the end of the block => phantom at
    0x10A0 removed;
  - UNTOUCHED: `90 | 31 C0 C3` (`xor eax,eax; ret` preceded by padding) =>
    `func_0x1091` never moved;
  - exactly 3 functions remain after analysis.
  Analyzer output: `Trimmed 1 function start(s) off padding, dropped 2.`

### Verification

- Full CTest **65/65 exit 0** (was 64) incl. corpus/determinism regressions
  (real binaries exercise the new pass end-to-end with no output drift).
- **No commits made - user commits.**

- Updated: 2026-08-20

## Track 10 - PE Export-Forwarder Thunks (Task 2.1, GP-5900) (closed, 2026-08-20)

Backlog item 2.1 from `C:\Users\pc\Desktop\gaps\ENIGMA_ENGINE_GAPS_MASTER_PLAN.md`
(register GP-5900 in `GHIDRA_12_1_3_ENGINE_GAPS.md`): PE export forwarding
(`DLL.OrdinalName` strings in the export directory) produced a bogus
image-space function at the forwarder RVA (parseExports added a SymbolInfo
with address = forwarder RVA). Acceptance: a forwarded export generates a
`Function` with `isThunk()==true` whose `getThunkedFunction()` has
`isExternal()==true` and a name matching the forwarding string.

### Implementation

- `src/include/ghidra/BinaryLoader.h`: `ExportInfo` extended with
  `bool isForwarder=false; std::string forwarderString; std::string dllName;`.
- `src/core/BinaryLoader.cpp` `parseExports()` (SimplePELoader):
  - reads `exportDirSize` (optional header +100 PE32 / +116 PE64, fallback 40
    when 0) and the DLL name RVA (export dir +12, resolved via
    `readStringAtRVA` into `exp.dllName`);
  - a function RVA inside `[exportDirRVA, exportDirRVA + exportDirSize)` is a
    forwarder: `isForwarder=true`, `forwarderString = readStringAtRVA(funcRVA)`,
    `address=0`; forwarder entries are pushed to `exports_` but NOT `symbols_`
    (no bogus image-space function), normal exports unchanged;
  - bounds checks widened to `optHeaderOffset+104` (PE32) / `+120` (PE64).
- `src/core/BinaryLoader.cpp` `populateProgram()`: exports loop rewritten
  (GP-5900 comment). Normal exports (`address > 0`) stay as image-space
  `IMPORTED` labels. Forwarders become a Ghidra-style EXTERNAL-space pair:
  - EXTERNAL space created lazily (`addrFactory->getAddressSpace("EXTERNAL")`
    else `new GenericAddressSpace("EXTERNAL", 64, TYPE_EXTERNAL, 0)` +
    `addAddressSpace`), mirroring `src/import/GzfProgramImporter.cpp:1505-1513`;
  - **F2 target**: forwarder string split on the first `.` (no dot => library =
    exporting DLL, symbol = whole string). External symbol
    (`createExternalSymbol`, `SourceType::IMPORTED`, isFunction=true) +
    `ExternalManager::addExternalLocation(lib, sym, addr, id, "", true)` +
    `FunctionManager::createFunction` with `setExternal(true)`; dedup via
    `externals->getExternalLocation(lib, sym)` + `getFunctionAt`;
  - **F1 thunk**: library = exporting DLL (`exp.dllName`, fallback "UNKNOWN"),
    name = export name, `originalImportName` = full forwarder string,
    `setExternal(true) + setThunk(true) + setThunkedFunction(target)`;
  - library namespaces via `symTable->getNamespace(lib, global)` else
    `externals->addExternalLibrary(lib,"")` + `createNameSpace`; symbol ids are
    an incrementing counter from 0 (impl auto-rebases collisions).
- `FunctionManager::createFunction` is external-space safe (no space
  validation; keys by offset), so no model changes were needed.

### Test

- New suite `tests/test_pe_loader.cpp` (registered as `enigma_test_pe_loader`,
  **33/33**): synthetic PE32+ (DOS `MZ`/e_lfanew, COFF x86-64 with one
  `.exp` section, opt header 0x20B, ImageBase 0x140000000, export dir RVA
  0x1000 size 0x80) with two exports:
  - `NormalFunc` -> RVA 0x1100 (normal: image label + function kept);
  - `ForwardedFunc` -> RVA 0x1070 (inside the dir) forwarding to
    `NTDLL.RtlAllocateHeap` (string at RVA 0x1070);
  - asserts: export flags (`isForwarder`, `forwarderString`, `dllName`),
    NO function/label at imageBase+0x1070, EXTERNAL space exists and is typed
    external, `NTDLL`/`RtlAllocateHeap` external location (label, library,
    isFunction), thunk location with `originalImportName ==
    "NTDLL.RtlAllocateHeap"`, thunk `isThunk()` in EXTERNAL space whose
    thunked function `isExternal()` and named `RtlAllocateHeap` (and not
    itself a thunk).

### Verification

- Full CTest **66/66 exit 0** (was 65) incl. corpus/determinism regressions
  (real PEs exercise the new forwarder path with no output drift).
- **No commits made - user commits.**

- Updated: 2026-08-20
## Track 11 - ELF Dynamic PLTGOT Recovery for Stripped Binaries (Task 2.2, GP-7056) (closed, 2026-08-20)

Backlog item 2.2 from `C:\Users\pc\Desktop\gaps\ENIGMA_ENGINE_GAPS_MASTER_PLAN.md`
(register GP-7056): ELF loading relied entirely on section headers
(`e_shoff != 0`); a stripped binary (no section headers) produced no memory
blocks, no symbols, and no imports. Acceptance: in a stripped ELF with no
section headers, all `DT_JMPREL` imports are resolved to named symbols at
correct GOT/PLT addresses.

### Implementation

All in `src/core/BinaryLoader.cpp` (`SimplePELoader`; there is no separate
`ElfLoader.cpp`/`Elf_Shdr` table in the engine). New `parseELFStripped()`
fallback invoked from `parseELF()` after the section-based passes **only when
`sections_` is empty**, so normal binaries are completely untouched:

- `ElfPhdr` struct + `phdrs_` + `parseELFProgramHeaders()` (both ELF32
  phentsize 32 and ELF64 phentsize 56 layouts); `phdrVaToFileOffset()` maps
  VAs through PT_LOAD segments.
- **PT_LOAD -> memory sections**: each loadable segment becomes a
  `seg_<n>` `SectionInfo` (p_flags permissions), so `populateProgram`
  creates real blocks and the existing hex/analysis paths work on the
  stripped image.
- **PT_DYNAMIC tags**: `DT_NEEDED` (library records, `(dynamic)` shape),
  `DT_STRTAB`/`DT_SYMTAB`/`DT_SYMENT`, `DT_JMPREL`/`DT_PLTRELSZ`/`DT_PLTREL`
  (7=RELA / 17=REL), `DT_RELA`/`DT_RELASZ`/`DT_RELAENT`,
  `DT_REL`/`DT_RELSZ`/`DT_RELENT`.
- **Dynamic symbol table**: sized from the largest relocation symbol index
  (no DT_SYMSZ tag), names resolved via DT_STRTAB; includes UND symbols the
  section-based `parseELFSymbols` skips.
- **Relocations -> named imports** (mirrors the section-based
  `parseELF*Relocations` naming): JUMP_SLOT names the GOT slot + its PLT
  stub; GLOB_DAT-class names the GOT slot only.
- **PLT stub location without sections**:
  - x86/x86-64: reverse scan — every stub is `FF 25 <disp32>`; find the
    `jmp [rip+disp32]` (64-bit, disp resolved through the instruction
    address) or `jmp [disp32]` (32-bit) whose displacement targets exactly
    the GOT slot, so stub addresses are exact per import;
  - AArch64: scan for the 16-byte stub `adrp x16; ldr x17,[x16,#imm]; add;
    br x17` with precise masks (`adrp & 0x9F000000 == 0x90000000` + x16,
    `ldr & 0x3B000000 == 0x39000000` + 64-bit `& 0xC0000000` + x17 + [x16],
    `br == 0xD61F0220`); a base is accepted only when the next two matches
    follow at 16-byte strides (PLT0 contains the same adrp/ldr/br at +4, so
    a naive first-match picks PLT0+4 with a 28-byte stride);
  - ARM: reuses the `add ip, pc, #imm` (0xe28fc600) first-two-matches scan
    (existing `armPltStubLayout` logic) over executable segments;
  - MIPS/PPC: no contiguous stubs — GOT slots only (matches the section
    path's {0,0} behavior).

### Test

- New suite `tests/test_elf_pltgot.cpp` (registered `enigma_test_elf_pltgot`,
  **22/22**; `ENIGMA_SOURCE_DIR` now defined for all foreach-registered
  tests):
  - **Synthetic stripped ELF64** (x86-64, RELA, e_shoff=0; 3 phdrs:
    text R+X with PLT0 + 2 stubs, data R+W with .dynamic/.dynsym/.dynstr/
    .rela.dyn/.rela.plt/GOT, PT_DYNAMIC): exact import set
    `(dynamic) libc.so.6`, `puts@0x401230` + stub `puts@0x400110`,
    `printf@0x401238` + stub `printf@0x400120`, GLOB_DAT `_g_data@0x401240`;
    2 `seg_*` sections; `populateProgram` maps a block at 0x400000 and
    labels at every GOT slot + PLT stub;
  - **Synthetic stripped ELF32** (x86, REL, 1 JUMP_SLOT): `puts@0x40110C` +
    stub `puts@0x400110` via the 32-bit absolute `jmp [disp32]` scan;
  - **Real fixtures**: `x64_dyn_stripped.elf` (objcopy
    `--strip-section-headers`; e_shoff=0) import set == original
    `tests/corpus/x64_dyn.elf` exactly; `aarch64_dyn_stripped.elf`
    (section-header fields zeroed in a copy — MinGW objcopy lacks AArch64
    BFD support) matches the original on all addressed imports (GOT slots +
    PLT stubs); note: the aarch64 corpus file's `.dynstr` **section header
    is bogus** (offsets point into `.relro_padding`), so the section path
    emits a garbage library record while the stripped path resolves the
    true DT_NEEDED names — the fixture comparison excludes address-0
    library records (pre-existing Track 6/7 quirk, unchanged).

### Verification

- Full CTest **67/67 exit 0** (was 66) incl. corpus + determinism
  regressions (the fallback only runs when `sections_` is empty, so real
  binaries with section headers are byte-for-byte unaffected).
- **No commits made - user commits.**

## Track 12 - ELF GNU Hash Table Parser & Dynamic Symbol Sizer (Task 2.3, GP-7061 / GP-6887) (closed, 2026-08-20)

Backlog item 2.3 from `C:\Users\pc\Desktop\gaps\ENIGMA_ENGINE_GAPS_MASTER_PLAN.md`
(register GP-7061 / GP-6887): dynamic symbol recovery relied on SYSV `.hash`
sections (or, in the Task 2.2 stripped path, on the largest relocation symbol
index). Modern Linux linkers emit only `DT_GNU_HASH`; symbols not referenced
by any relocation were lost. Acceptance: dynamic symbols resolve on binaries
that only supply `DT_GNU_HASH`.

### Implementation

All in `src/core/BinaryLoader.cpp` `parseELFStripped()` (the `SimplePELoader`
owns all ELF parsing; there is no `GnuHashTable.cpp`/`ElfLoader.cpp`):

- `DynTags` now collects `DT_HASH` (4) and `DT_GNU_HASH` (0x6FFFFEF5).
- `parseGnuHashSymCount(hashOff)` parses the GNU hash header (`nbuckets`,
  `symoffset`, `bloom_size`, `bloom_shift`), the bucket table and the
  symbol-index chains (each chain word terminated by the low bit), and
  returns `symoffset + highestReachableIndex + 1` — the exact dynamic
  symbol count. Boundary guards: `nbuckets`/`symoffset` ≤ 2^22,
  `bloom_size` ≤ 2^20, every read bounds-checked against `rawData_.size()`
  (no bloom-filter verification is needed for counting, so the filter is
  skipped entirely).
- Dynamic symbol count precedence: GNU hash → SYSV hash (`nchain@+4`) →
  largest relocation symbol index (Task 2.2 fallback).
- **Defined dynamic symbols are now populated** (`GP-6887`): for each
  entry, mirror `parseELF64Symbols`/`parseELF32Symbols` exactly — skip
  `nameIdx == 0` or `value == 0`; `isFunction = (stype == 2)`;
  `isExternal = (bind == 1 || bind == 2) && shndx == 0` (GP-7057 rule);
  ELF32 uses the 32-bit layout (value@+4, size@+8, info@+12, shndx@+14)
  vs ELF64 (info@+4, shndx@+6, value@+8, size@+16). Undefined (UND)
  symbols with value 0 stay out of `symbols_` — they surface as imports
  through the relocations instead.

### Test

`tests/test_elf_pltgot.cpp` extended 22 → **24/24**:

- Synthetic stripped ELF64 now carries a **real `DT_GNU_HASH` table**:
  header + 1-word bloom + bucket table + chains, `symoffset = 1`, symbols
  1..4 bucketed at `chainPos = idx - symoffset` (bucket count auto-chosen
  so all four names hash to distinct buckets; GNU hash = the djb2 variant,
  `h = h*33 + c`, computed in the builder). A 5th dynsym entry
  `my_func` (GLOBAL FUNC, defined @ 0x400180) is **referenced by no
  relocation**, so it is only recoverable through the hash-sized table —
  assert `getSymbols()` contains it at 0x400180 with `isFunction`;
- Synthetic stripped ELF32 now carries **`DT_HASH`** (nbuckets=1,
  `nchain=3`) and a defined `my32func` @ 0x400130 referenced by no
  relocation — assert it is found;
- Real stripped fixtures (`x64_dyn_stripped.elf`, `aarch64_dyn_stripped.elf`,
  both linked with GNU hash by lld) still match their corpus originals on
  all imports — the hash-derived count keeps the relocation naming intact.

### Verification

- Full CTest **67/67 exit 0** (same count — the suite grew by 2 assertions,
  `enigma_test_elf_pltgot` reports 24/24); corpus + determinism regressions
  green (hash sizing only runs in the stripped fallback; binaries with
  section headers are untouched).
- **No commits made - user commits.**

- Updated: 2026-08-20

---

## Track 13 — COFF Object File Loader & ARM64 Relocations (Task 2.4, GP-7088)

**Date**: 2026-08-20. **Status**: COMPLETE (full CTest **68/68 exit 0**, new
`enigma_test_coff_loader` **31/31**). **No commits made - user commits.**

### Scope

Ghidra `CoffLoader`/`CoffArchiveLoader` behavior ported into the single engine
loader (`src/core/BinaryLoader.cpp`, matching the ELF/PE/Mach-O precedent — no
separate `CoffLoader.cpp`; Ghidra's own C++ loader base `CoffLoader` provides
machines 0x14C/0x8664/0xAA64 with MIPS/ARM/PPC extensions).

### Code changes (all in `src/core/BinaryLoader.cpp`)

1. **Detection in `load()`** (`~L105`): `!<arch>\n` prefix → `parseCOFFArchive()`;
   else `isCoffMachine(machine)` (0x8664 x86-64, 0xAA64 ARM64, 0x14C x86-32,
   0x1C0/0x1C4/0x1C2 ARM) + 1 ≤ numSecs < 0x100 + SizeOfOptionalHeader==0 +
   size ≥ 20+40·numSecs → `parseCOFF()`.
2. **`parseCOFFBytes(base, size, baseVa, memberTag)`**: COFF file header, section
   headers (40-byte; long names via `/nnn` string table; cumulative 0x1000-aligned
   layout from baseVa; per-section flags → readable/writable/executable), symbol
   table (18-byte entries, auxiliaries skipped via `NumberOfAuxSymbols@+17`,
   SECTION records (storageClass 3) skipped, defined symbols → `SymbolInfo`
   at `secVa + value` with `isFunction = (type==0x20)` and
   `isExternal = (storageClass==2)`, `secNum==-1` → absolute address = value,
   `secNum==0 && EXTERNAL` → `imports_`), string table for `/nnn` names.
3. **Relocations patched in-memory** (never written to disk; `getRawDataCopy()`
   returns patched bytes): `0x0001` AMD64 ADDR64 + `0x000E` ARM64 ADDR64
   (8-byte absolute), `0x0002` ARM64 ADDR32 (4-byte absolute), `0x0003` ARM64
   BRANCH26 (sign-extended imm26, `newImm = (target - insAddr) >> 2`,
   preserved opcode bits), `0x0004` AMD64 REL32 (`target - (insAddr + 4)`).
   Unresolved externals left untouched (they become imports).
4. **Entry point**: first symbol named `main`/`_main`/`WinMain`/`wmain`/`_WinMain`
   with a defined section → `entryPoint_`.
5. **`parseCOFFArchive()`**: 60-byte `ar` member headers, `"/"` (symbol table) and
   `"//"` (long-name table) members skipped, odd member sizes padded with `'\n'`,
   each member parsed with its own VA block (next base = max section end,
   0x1000-aligned), section names prefixed `memberTag + "_"`, format
   `"COFF Archive"`, arch/bitness taken from the first parsed member.
6. **`populateProgram`**: defined non-function COFF symbols become labels at
   their mapped address (guarded by block existence and `formatName_ == "COFF"`).

### Bugs found & fixed this track

- Test-side: symbol entries must occupy their real table slots (auxiliaries are
  counted in the table) and relocation `r_offset` is section-relative, not
  file-relative (loader adds `cs.rawOff` internally).
- Loader-side: `secName` added `base` twice for archive members (absolute file
  offsets), producing empty section names (`a.obj_` instead of `a.obj_.text`);
  archive members also failed to set arch/bitness because the arch-set
  condition required `formatName_ == "COFF"` while archives pre-set
  `"COFF Archive"`.

### Test

`tests/test_coff_loader.cpp` **31/31**, registered as `enigma_test_coff_loader`:

- Synthetic x64 `.obj`: sections `.text`/`.data`/`.bss` at 0/0x1000/0x2000 with
  correct flags; symbols `_func1` (FUNC @0x10) / `_g_data` (@0x1000); import
  `_printf`; ADDR64 @2 → 0x1000, REL32 @0xD → 0xFFFFFFFF (0x10 − (0xD+4)),
  `.data` ADDR64 → 0x10; `populateProgram` block/label/function assertions.
- Synthetic ARM64 `.obj`: BRANCH26 @0 → 0x14000002, ADDR32 @4 → 0x1000,
  `.data` ADDR64 → 8.
- Two-member `.lib` archive: sections `a.obj_.text`/`b.obj_.text` at 0/0x1000,
  patches @4/@0x1004, imports `_a_ext`/`_b_ext`, format `"COFF Archive"`.

### Known deviations (documented)

- Unresolved COFF externals map to `imports_` with `libraryName="(coff)"` and
  `address=0`; the engine has no EXTERNAL-space import mapping for COFF (register
  note "must map to EXTERNAL space" is a Ghidra-gui concern — deferred with G1).
- Defined data-symbol labels are COFF-only: an all-format variant changed the
  decompiled output of the aarch64/arm32 ELF corpus fixtures (2 leading blank
  lines — a label-derived artifact in the function pipeline), so the loop is
  gated on the COFF formats. Investigate separately if data labels are wanted
  for ELF.
- bigobj (`ANON_OBJECT_HEADER` machine 0x0000) not supported; large object
  files (>127 sections) will not load.
- ghc-lib-style thin archives (member name `/<digits>` into `//` long-name
  table with no embedded payload) are skipped, matching Ghidra's "old-style"
  archive support.

### Verification

- Full CTest **68/68 exit 0**; corpus + determinism regressions green.
- **No commits made - user commits.**

- Updated: 2026-08-20

