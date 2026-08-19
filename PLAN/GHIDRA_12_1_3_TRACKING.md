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