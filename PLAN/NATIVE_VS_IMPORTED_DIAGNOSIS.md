# Native vs Imported Comparison — pass.exe / pass_proj.rep

Date: 2026-08-17. Read-only diagnosis; no code was modified.

Subject: same program analyzed two ways —
- **Native**: Enigma loads `pass.exe` (MinGW x64), analyzes it, decompiles via `ghidra_decompiler` through `AnalysisBridge`.
- **Imported**: Ghidra 12.0.4 project `pass_proj.rep` (DWARF-informed) exported to `.gzf`, re-imported into Enigma, decompiled via the same decompiler core through the GZF bridge.

Comparands were produced by `enigma_dump_functions`, `enigma_decompile_full`, `enigma_gzf_probe`, `enigma_gzf_inspect` (raw records). Every item below is classified as one of:

- **(A) Import defect** — importer reads the `.gzf` incorrectly; fixable in `GzfProgramImporter`.
- **(B) Native analysis difference** — native analyzers produce less/misaligned data; not an import fault.
- **(C) Decompiler / type-recovery difference** — shared decompiler-interface behavior, same on both sides; gap lives in the CLI tool layer or decompiler recovery.
- **(D) Intentional Ghidra-vs-Enigma semantic difference** — the imported program truthfully carries Ghidra's model; native recovers at decompile time.

---

## 1. Function counts and boundaries — (B), no functions genuinely missing

- Native **236** functions, imported **241** functions. Common exact-address matches: **133**.
- **Native-only 103**: every one lies within 0x7F bytes of an imported function start
  (20 at 1–3 bytes, 77 at 4–0x1F, 6 at 0x20–0x7F, 0 beyond). Example:
  native `func_0x14000102f` vs imported `safe_flush` @ 0x140001030 — the native
  function-start search landed on a padding NOP one byte earlier. Same code body.
- **Imported-only 108** =
  - 62 external-space thunk functions at 0x1..0x3E (Ghidra materializes externals as
    functions; native models them only as external symbols) — (D),
  - 17 import stubs (`__setusermatherr` 0x1400112b0, `_unlock` 0x1400112f8,
    `fflush` 0x140011320, and all 14 WinAPI stubs at 0x1400113e0–0x140011450) —
    (B): native creates functions for the 23 MSVCRT stubs it saw referenced but not
    for these,
  - ~29 CRT/internal helpers (`safe_flush`, `__gcc_deregister_frame`, `_setargv`,
    `__mingw_vscanf`, `__pformat_*`, D2A helpers, `__acrt_iob_func`, `wcrtomb`,
    `fallback_IsDBCSLeadByteEx`, ...) whose native counterparts exist a few bytes
    earlier (the 103 off-by-N set) or were missed — (B).

## 2. Signatures / calling conventions — (C)+(D); imported DB strictly richer

Imported DB carries full Ghidra/DWARF signatures, e.g.

```
int  main(int _Argc, char ** _Argv, char ** _Env)            __cdecl
int  __mingw_scanf(char * format)                            __fastcall
char * __gdtoa(FPI *fpi, int be, ULong *bits, int *kindp, int mode,
               int ndigits, int *decpt, char **rve)          (8 params)
float __strtof(char *s, char **sp)                           (2 params)
```

Native DB stores no signatures; the decompiler recovers them at decompile time
(`uint64_t __fastcall main()`, `int32_t __fastcall strcmp(char*, char*)`).
Decompiler rendering of imported `main` is `__stdcall main(undefined8, undefined8)` —
neither the DB's 3-param `__cdecl` nor native's 0-param — because the decompiler
re-derives the prototype from the call site in `__tmainCRTStartup`. Same behavior
would occur for a natively loaded program via the DecompInterface/GUI path — (C).

## 3. Parameters and locals — (A) storage lost (P1 defect); names/types/ordinals fine

Imported params/locals are real DWARF data: `main` has 3 params + 3 locals,
`__mingw_scanf` a `va_list argp`, `__gdtoa` 8 params + 19 named locals, `__strtof`
locals `bits` (ULong[1]) and `expo` (long). Native DB has none — (B).

**DEFECT (P1, (A)): all variable *storage* is lost on Ghidra-12 corpora.**
Ghidra 12 serializes storage as `Stack[-0x4c]:4` / `Register[RAX]:8` (single
colon); `GzfProgramImporter::parseStorage` only understands the pre-12 format
`stack:<hex>:<size>` / `register:<hex>:<size>`, so every record decodes to
BAD_STORAGE. `pass_proj.rep` has 111 storage records — every imported param/local
comes out with `storage=unknown` (probe-verified). The notepad corpus still uses
the old format (`register:00000008:8`), which is why the importer test suite
(283/283) passes.

## 4. Data types — (A) pointer-length defect (P1); minor loss (P3)

- **DEFECT (P1, (A)): pointer lengths are read as an *unsigned* byte.**
  Ghidra stores -1 (0xFF) for "default pointer size" in the Pointers table
  (`[long,long,byte]`, Length column). `readBeNum` is unsigned
  (GzfProgramImporter.cpp:234), so -1 becomes 255; every default-length pointer
  becomes a 255-byte pointer whose display name is `char *2040` (=
  `8 * ptrLength` via `PointerDataType::constructUniqueName`). Verified live in
  the imported DB (e.g. `__gdtoa` signature renders `FPI *2040 *2040`). Effects:
  wrong pointer lengths for pointer-typed data units (computeDataLength fallback),
  GUI type display, and decompiler bridge types. Fidelity tests (36/36) cannot
  catch it — the round-trip compares the imported program against itself.
- **(P3, (A)): the trailing "Return Storage" string column of the Function Data
  table is not read** (schema `[long,int,int,int,byte,byte,string]`); return
  storage is dropped. Cosmetic; nothing depends on it today.

## 5. Decompiler output structure — (C), tool-layer gap shared by native GUI path

Same decompiler core, two wrapper layers. `enigma_decompile_full` (CLI) post-processes
with `resolveStrings` + `applyTypeDatabaseToCallSpecs` + CRT boundary filtering;
the DecompInterface path used by the GUI and the `.gzf` probe does not. The raw
interface therefore renders, for the *same* function `main`:

```
native CLI:    builtin_strncpy(local_0x52,"adam2006",9);
               __mingw_printf("enter the password : ");
               __mingw_scanf("%s",local_0x52 + 10);
               strcmp(local_0x52 + 10,local_0x52);

imported/raw:  local_0x52 = 0x363030326d616461;
               __mingw_printf();                                  // 0 args
               __mingw_scanf(param_1,param_2,local_0x48,0x140013016); // 4 args
               strcmp(param_1,param_2,&local_0x52,local_0x48);    // 4 args
```

The bogus arg counts/constants are the decompiler's recovered prototypes without
the tool layer's TypeDatabase annotation — the same output the GUI would show for a
natively loaded binary (already documented in PROGRESS ~W13/BB). Not an import fault.
Where the imported DB *is* consumed by the decompiler, output is richer and correct:
`_pei386_runtime_relocator` decompiles with the full Ghidra body and the real global
`_was_init`, vs native `ptr_0x1400170a0` and a truncated body (native body discovery
is weaker) — (B)+(D).

## 6. References / XRefs — (D), imported refs are Ghidra truth

Imported FROM REFS 6752 records / TO REFS 2650 records, carried 1:1 with types
(UNCONDITIONAL_CALL, DATA, ...), zero bad refs in earlier verification. Native refs
are rebuilt by analysis; no import defect found on this axis.

## 7. Symbols and names — (D)

Imported: 2371 symbols — real names for 92/133 common functions (DWARF + Ghidra
analysis: `__mingw_scanf`, `_pei386_runtime_relocator`, `safe_flush`, ...) plus
globals (`_was_init`) and strings. Native: `func_0x*` naming with only
MainRecognition renaming (`__mingw_printf`, `__mingw_scanf`, imports). Intentional:
import carries Ghidra's naming; native heuristics are weaker — (B)/(D).

## 8. Thunks / CRT helpers — (B)+(D)

Imported: 60 Thunk Functions records — every import stub (0x1400112b0–0x140011450)
is a thunk function linked to its target, plus 62 external-space thunks. Native:
23 MSVCRT stubs as functions, 17 stubs (incl. all 14 WinAPI) absent, externals not
functions. (B) for the missing stubs, (D) for externals-as-functions.

---

## Priorities

| # | Item | Class | Priority |
|---|------|-------|----------|
| 1 | Variable Storage decode: Ghidra 12 `Stack[-0x4c]:4`/`Register[...]:N` unsupported → all param/local storage lost | (A) import defect | **P1 — FIXED** |
| 2 | Pointers table Length read unsigned: -1 → 255 → `char *2040`, pointer length 255 | (A) import defect | **P1 — FIXED** |
| 3 | Return Storage column of Function Data not read | (A) import defect | P3 |
| 4 | Native function-start precision: 103 starts off by 1–0x7F bytes (padding NOPs/labels) | (B) | P2 |
| 5 | Native misses 17 import-stub functions; ~29 CRT helpers un/under-named; externals modeled differently | (B)/(D) | P2 |
| 6 | Decompiler-interface path lacks TypeDatabase call-site annotation + string resolution (affects both native GUI and imported decompiles) | (C) | P2 |
| 7 | Imported DB signature/convention/name richness vs native decompile-time recovery | (C)/(D) | intentional |

**Resolution (2026-08-19)**: #1 fixed (111/111 records decode to exact
offsets/sizes — negative stack, positive x64 shadow-space home slots
`Stack[0x8..0x20]`, unassigned-as-Ghidra-truth; snapshot reload round-trips
byte-identical) and #2 fixed (signed-byte length, `-1` = language-default
pointer size, no `*2040` names). Follow-up snapshot fix: implicit pointers
(`hasLanguageDependantLength`) serialize length `-1` instead of the resolved
default size so reload rebuilds `void *` (not `void *64`); SnapshotReader
Pass B dedup uses `addDataTypeWithId`'s return (eliminates the reload
use-after-free). #3 remains doc-only (return storage is analytically
redundant). Fidelity 22/22, importer 87/87, CTest 61/61, exit 0.

Remaining genuine fidelity defects are exactly #1–#3; all other differences are
native-analysis quality, shared decompiler-interface behavior, or intended
Ghidra-vs-Enigma semantics.