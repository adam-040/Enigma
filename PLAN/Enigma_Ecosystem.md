# Enigma Ecosystem

Design for the plugin system and external import ecosystem. Decisions locked on
2026-08-15: import source = **.gzf**, plugin scope = **both** (IDE DLL plugins +
engine-level registration), packaging = **external DLLs** loaded from a `plugins/`
directory at runtime, with a stable API/ABI so plugins build and release
independently of Enigma itself. The `.gzf` importer is a **native, self-contained
reader** of the Ghidra project DB format (no JSON intermediate, no Ghidra
install/JVM/headless/scripts) — section 8 describes the verified on-disk format.

## 1. Goals

1. **Runtime extensibility**: new importers, loaders, analyzers, exporters, and
   IDE features ship as DLLs dropped into `plugins/`. No Enigma rebuild.
2. **Stable ABI**: the plugin contract is a versioned plain-C surface. No STL/Qt
   types cross the DLL boundary except where the plugin is explicitly an IDE
   plugin built against the same Qt build.
3. **Import pipeline**: `File > Import` supports external formats via importer
   plugins. First importer: a **GzfImportPlugin** that opens Ghidra `.gzf`
   archives and populates `ProgramDB`.
4. **Independent release**: a plugin repo builds against public headers
   (`include/plugin/`), not against Enigma internals.

## 2. Directory layout (final packaging model)

```
enigma.exe
plugins/
  engine/            engine-level plugins (C ABI)   — *.dll + plugin.json
  ide/               Qt6 IDE plugins (QPluginLoader) mostly for GUI — *.dll + plugin.json
```

Discovery order: `plugins/` next to the exe → `ENIGMA_PLUGIN_DIR` env override →
user config dir. Missing/empty `plugins/` is not an error; core features never
depend on a plugin.

## 3. Plugin manifest — `plugin.json`

```json
{
  "id": "enigma.import.gzf",
  "name": "Ghidra .gzf Importer",
  "version": "1.0.0",
  "api": "engine/v1",
  "entry": "enigma_plugin_v1",
  "author": "",
  "description": "Imports Ghidra zip archives"
}
```

- `api` is the compatibility contract: `engine/v1` or `ide/v1`.
- Id mismatch = skip with console warning, never a crash.
- PluginManager validates manifest *before* loading the DLL.

## 4. PluginManager (host side)

`src/plugins/PluginManager.{h,cpp}` + `src/include/plugin/EnigmaPlugin.h`.

- Owned by the engine core (`Engine`); accessible to the GUI via
  `Engine::pluginManager()`.
- `loadAll()`: scan dirs → parse manifests → `LoadLibrary` → resolve entry →
  `onLoad(host)` → record in `loaded_`. `unloadAll()` at shutdown in reverse
  order.
- Every foreign call is wrapped in try/catch; a throwing or failing plugin is
  disabled for the session, never fatal.
- Command slot: `plugins --list`, `--load <path>` (for testing).

## 5. Engine-level registration (platform ABI)

Public contract in `include/plugin/EnigmaPlugin.h` — the only header a plugin
build needs.

```cpp
extern "C" {
  // API version must equal EnigmaPluginHost::kApiVersion (0x1000 for v1)
  struct EnigmaPluginV1 {
    uint32_t api_version;
    const char* plugin_id;            // must match manifest id
    int (*onLoad)(EnigmaPluginHost* host);      // register services; 0 = ok
    int (*onUnload)(EnigmaPluginHost* host);    // optional; 0 = ok
  };
  // Plugin exports exactly one symbol, named by manifest "entry":
  //   extern "C" __declspec(dllexport) EnigmaPluginV1* <entry>();
}
```

`EnigmaPluginHost` is an opaque handle; all calls go through C functions:

```
host_register_importer(host, const EnigmaImporterDef*)   -> int
host_register_analyzer(host, const EnigmaAnalyzerDef*)   -> int
host_register_exporter(host, const EnigmaExporterDef*)   -> int
host_log(host, level, const char* msg)
host_alloc / host_free                               (ownership stays with host)
```

Rules that make the ABI stable:

1. **No C++ types, no exceptions** across the boundary. Structs are C-layout
   with explicit sizes/versions (`uint32_t struct_size` as first field).
2. **Strings** are `const char*` UTF-8, valid for the duration of the call only;
   host copies when it needs them.
3. **Memory**: host allocates everything the plugin hands back; plugin never
   frees host memory and vice versa.
4. **Registration is call-time**: hand the host a filled `EnigmaImporterDef`
   (id, display name, extension list, capability bits, function pointers); the
   host deep-copies it. No symbol tables, no runtime name resolution.
5. Every `Enigma*Def` is versioned; unknown-future-version defs are rejected
   with a warning, not mis-read.

## 6. IDE-level plugins (Qt surface)

- Standard Qt `QPluginLoader` flow: plugin exports a
  `QObject`-derived class implementing `EnigmaIdePlugin` (new, in
  `src/gui/plugins/EnigmaIdePlugin.h`).
- Contract: `QString id()`, `int apiVersion()`, `void init(EnigmaIdeHost*)`.
- `EnigmaIdeHost*` is a `QObject*` on the Qt side exposing stable facade
  methods (dock registration, menu/toolbar insertion, seek/navigation hooks,
  console logging) — mirror of the `BACKEND_API.md` freeze.
- IDE plugins are rebuilt only when the *Qt build* changes; their Qt
  metatype/ABI requirement is documented as a release constraint (same major
  Qt + same compiler family).

## 7. Importer framework

`src/import/ImportManager.{h,cpp}` — registry driven by registered importer
plugins (engine level) plus the built-in `BinaryLoader` importer.

- `importFile(path)` → enumerates registered importers by extension and
  capability, tries in order, first success populates `ProgramDB` (reusing the
  existing `BinaryLoader` → `ProgramDB` population path).
- GUI: `File > Import...` lists available importers and their extensions.
- Zip/gzip handling is done by the host (`host_read_archive`); importers get a
  member list + extraction callbacks — no plugin ships its own unzip. The zip
  layer is shared with the native `.gzf` reader (section 8).

## 8. GzfImportPlugin (native importer, no Ghidra runtime)

**Input**: Ghidra `.gzf` (zip-wrapped Ghidra project directory).

**Design constraint (locked 2026-08-15)**: fully self-contained — no JSON
intermediate, no Ghidra install, no JVM, no `analyzeHeadless`, no scripts, no
external Ghidra runtime. The archive is parsed directly in-engine against the
documented on-disk format (verified by decoding a real `notepad_test.exe`
project DB end-to-end during planning).

### 8.1 Container layer (verified)

`.gzf` = plain zip of a project directory. In-project layout:

```
<proj>.rep/
  project.prp                     XML FILE_INFO (name, type, timestamp)
  idata/~index.dat                VERSION=1; maps file ids -> name + fileId
  idata/~journal.bak              recovery journal (ignored by reader)
  idata/00/<NNNNNNNN>.prp         item metadata XML: CONTENT_TYPE="Program", NAME
  idata/00/~<fileid>.db/
    db.<N>.gbf                    the actual program database
```

### 8.2 Database file (.gbf) format (verified)

All integers big-endian. Header:

| field | bytes | notes |
|-------|-------|-------|
| magic | 8 | ASCII `/01,4),*` = `0x2f30312c34292c2a` |
| fileId | 8 | |
| header version | 4 | |
| blockSize | 4 | 16384 in practice |
| firstFreeId | 4 | |
| numParms | 4 | then `numParms` × `(nameLen:int, name, value:int)` |

Then `blockSize`-byte blocks: `flags(1, bit0=empty), bufferId(4), data(blockSize-5)`.
Buffer 0 = DBParms: `type(1)=9, dataLen(4), version(4), [var/val pairs]`;
MASTER_TABLE_ROOT_BUFFER_ID = first int32 of the pair list.

### 8.3 B-tree node layout (verified)

Node starts with `nodeType(1)`. Types: 0 long-key interior, 1 var-rec leaf,
2 fixed-rec leaf, 3 var-key interior, 4 var-key rec leaf, 5 fixed-key interior,
6 fixed-key var-rec, 7 fixed-key fixed-rec, 9 chained data. KeyCount(4) at
offset 1; long-key leaves add PrevLeafId(4)+NextLeafId(4) (header = 13 bytes).

- **Long-key interior**: `KeyCount × (Key(8) + ChildBufferId(4))` from offset 5
- **Var-rec leaf**: `KeyCount × (Key(8) + RecOffset(4) + Indirect(1))` from offset 13;
  record data at `RecOffset` (fields are exact-size, parse in-place)
- **Fixed-rec leaf**: `KeyCount × (Key(8) + fixed record)`; record size from schema
- **Indirect (chained)**: record starts with a buffer ID; body lives in chained
  buffers (type 9: `type(1), dataLen(4), data`)

### 8.4 Field encodings (verified)

| type | code | storage |
|------|------|---------|
| BYTE | 0 | 1B |
| SHORT | 1 | 2B |
| INT | 2 | 4B |
| LONG | 3 | 8B |
| STRING | 4 | int32 len (−1 = null) + UTF-8 |
| BINARY | 5 | int32 len (−1 = null) + bytes |
| BOOL | 6 | 1B |
| FIXED10 | 7 | 10B |

Sparse columns (SparseRecord): non-sparse fields inline, then `cnt(1),
colIndex(1), value, ...` per non-null sparse field.

### 8.5 Master table → table directory (verified)

Table of tables (VarRecNode at MASTER_TABLE_ROOT_BUFFER_ID; one leaf in
practice). Record schema: `name(String), version(Int), rootBuf(Int),
keyType(Byte), fieldTypes(Binary), fieldNames(String), indexedCol(Int),
maxKey(Long), recCount(Int)`. Real decode of notepad_test.exe (104 tables):

| table | recs | consumed as |
|-------|------|-------------|
| ADDRESS MAP, Memory Blocks (v3), Sub Memory Blocks | 4 / 9 / 10 | address spaces + blocks |
| File Bytes | 1 (200,704 B) | raw file image via chained buffers |
| Instructions (v1) | 35,367 | `Addr` → `{protoId, flags}` |
| Prototypes (v1) | 894 | proto bytes + template address |
| Data | 2,960 | defined data units |
| Comments (v1) + History | 1,004 | EOL/Pre/Post/Plate/Repeatable |
| Function Data (v3) | 794 | return type, purges, local size, flags, calling conv |
| Symbols (v4, sparse) | 4,891 | name, address, namespace, type, flags |
| ContextTable, FROM REFS, TO REFS, Equates, Bookmark(s), Relocations, Function Parameters/Definitions, Trees, Fragment/Module Tables, Range Maps, all data-type tables | | |
| Program | 7 | DataMap: name, language, compiler, image offset, DB version |

Address keys are encoded `addrType(4 bits, 2=relocatable) | baseIndex(28) |
offset(32)`; the ADDRESS MAP table links segments to space addresses. Decode of
a 100%-identical trace: `Program`/`ADDRESS MAP`/`Memory Blocks`/`Function
Data`/`Instructions`/`Symbols`/`Comments`/`File Bytes` all re-read cleanly,
proving the native read is lossless at the storage layer (working prototype:
`%TEMP%\opencode\enigma\ghidra_gbf_decode.py` + `gbf_tables.py`).

### 8.6 Pipeline

1. `importFile("x.gzf")` — built into the engine (`src/import/GzfReader`),
   wrapped by the GzfImportPlugin's C ABI so the engine stays clean.
2. Zip open → locate `<proj>.rep/idata/00/~<fileid>.db/db.<N>.gbf` via
   `~index.dat` + `.prp` CONTENT_TYPE.
3. GbfReader: header/params → buffer map → walk master table → per-table
   readers (all 8 node types + chained + sparse).
4. Adapter layer (mirrors `ghidra/program/database/*Adapter*.java`): translate
   each table record into ProgramDB entities. Order matters: ADDRESS MAP →
   File Bytes → memory blocks → prototypes → instructions → comments →
   functions → symbols → data types/refs/bookmarks/tree.
5. Address keys decoded via ADDRESS MAP (relocatable base index → address
   space) and converted to absolute addresses against the image offset.

Preservation matrix (all present in the DB and consumed): memory, functions
(including thunks + parameters), symbols/names (incl. imported names, labels,
FID/library info), data types (struct/union/enum/typedef/pointer/array +
categories + parent/child), comments (all 5 kinds + history), references
(FROM/TO REFS), equates, bookmarks, relocations, program tree (fragments/
modules + range maps), settings maps, and the Program data map (language/
compiler, used to pick the matching SLEIGH/compiler spec at load).

Why in-engine rather than headless conversion: the format is stable, fully
documented by the DB framework sources (`db/*.java` + `program/database/`),
and verified against a real project; a self-contained reader removes the
Ghidra runtime dependency entirely and keeps import deterministic and fast
(millions of table records stream in O(1) per record).

## 9. Dev convenience vs. release model

- **Release (final)**: plugins built in their own repos against
  `include/plugin/` (a shipped, frozen header set), dropped into `plugins/`.
  Version-matched only via manifest `api` field.
- **Development**: `ENIGMA_BUILD_PLUGINS=ON` (CMake option, default OFF) builds
  bundled plugin projects from `plugins-dev/` *as DLLs* and copies them into
  `build/plugins/engine` — exercising the exact same runtime load path as
  external plugins. No static linking, no hidden compile-time coupling.
- CI matrix for the plugin repo: build against the tagged public headers +
  run its own unit tests; an integration test loads the DLL into the packaged
  Enigma and asserts register/unregister.

## 10. Versioning & compatibility policy

| Layer | Versioning |
|-------|------------|
| Plugin API (`EnigmaPluginHost`, `Enigma*Def`) | `uint32_t` bump on any layout change; host rejects mismatches with a clear log line |
| Manifest `api` | must match host expectation, else skipped |
| Qt IDE plugin | must match installed Qt major (documented at release time) |
| Importer capabilities | capability bits in `EnigmaImporterDef` (e.g. archive member iteration, native `.gzf` decoding) |

Enigma core must always run with **zero plugins installed** — every plugin
feature is additive.

## 11. Roadmap

- **P1 — PluginManager + C ABI host**: `include/plugin/EnigmaPlugin.h`,
  `src/plugins/PluginManager.{h,cpp}`, manifest parsing, `plugins --list/--load`,
  unit tests (fake in-tree test plugin DLL, register/unregister round-trip,
  rejection of mismatched api versions, throwing plugin isolation).
- **P2 — GzfReader core** (in-engine `src/import/`): zip → `~index.dat`/`.prp`
  discovery, GbfReader (header/params/buffers, master table), all 8 node
  types + chained buffers + sparse records, per-field decoding. Verify by
  re-running the planning decoders against the real `notepad_test.exe`/
  `key.exe` tables; unit tests with fixture `.gzf` files.
- **P3 — ProgramDB population** (same milestone, still in-engine): address
  decode via ADDRESS MAP → File Bytes + memory blocks → prototypes +
  instructions → comments → functions → symbols → data types/refs/bookmarks/
  tree; end-to-end import test asserting the preservation matrix in 8.6
  (size, addresses, names, comments, function counts vs. the source tables).
- **P4 — GzfImportPlugin surface** (external repo, engine ABI only): thin C
  ABI wrapper over the engine's `ImportManager` so `.gzf` import works when
  the plugin DLL is present (`plugins/` drop-in), plus integration test.
- **P5 — IDE plugin surface**: `EnigmaIdePlugin` + `EnigmaIdeHost`, one sample
  dock-widget plugin to prove menu/dock/seek hooks end-to-end.
- **P6 — Packaging**: `plugins/` copied by the installer, version-pinned
  manifest policy doc, external-plugin build + test CI template.

## 12. Related design notes

- Reuses the frozen backend surface from `PLAN/BACKEND_API.md` — plugins are
  the first real consumer of that contract.
- Progress tracking for these phases goes in `PLAN/PROGRESS.md` (P1–P6,
  same style as W-series entries).
- Format references (read-only): `ghidra-source code/Ghidra/Framework/DB/
  src/main/java/db/` (`LocalBufferFile.java`, `MasterTable.java`,
  `TableRecord.java`, `NodeMgr.java`, `VarRecNode.java`, `VarKeyRecordNode.java`,
  `SparseRecord.java`, `Schema.java`, `ChainedBuffer.java`) and
  `ghidra-source code/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/
  program/database/` (per-table adapters). Working decode prototypes:
  `%TEMP%\opencode\enigma\ghidra_gbf_decode.py`, `gbf_tables.py`,
  `gbf_strings.py`.