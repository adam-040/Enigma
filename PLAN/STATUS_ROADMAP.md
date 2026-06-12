# Enigma Engine - Status Roadmap

## Current Position

Enigma is a Java-free, Ghidra-compatible C++ port. The goal is not to rewrite Ghidra from scratch. The goal is to use original Ghidra components directly when they already exist in C/C++, and translate Java-side components to C++ only when needed to remove Java completely.

Enigma is no longer in the early bootstrap stage. The project now has a working full decompiler path through the integrated Ghidra C++ decompiler, plus a growing C++ kernel that mirrors large parts of Ghidra's Java-side model.

The main remaining work is not "make decompilation run." That already works through `enigma_decompile_full`. The remaining work is to make it reliable, well-tested, and rich across many real binaries, while continuing to remove Java-side assumptions from loaders, analyzers, program state, symbols, types, and later UI/plugin layers.

UI and plugin system are intentionally left for the last stage.

## Architecture Principle

- Use original Ghidra C/C++ components directly whenever possible.
- The official first-version decompiler core is `Enigma-Engine/decompiler/`.
- Improve and patch the Ghidra C++ decompiler directly when needed.
- Translate Java components to C++ when they are needed for a Java-free backend.
- Do not replace mature Ghidra components with from-scratch rewrites unless there is a clear technical reason and the user agrees.
- The Capstone/Enigma-native path is useful for support, experiments, and validating Enigma's own p-code model, but it is not the main decompiler path for the first complete version.

## What Is Complete Or Nearly Complete

### Ghidra C++ Decompiler Pipeline
- Status: working.
- Tool: `enigma_decompile_full`.
- Uses the real Ghidra C++ decompiler action tree through `arch->allacts.getCurrent()->perform(*fd)`.
- Produces real structured C output from real binaries.
- Includes mature decompiler passes such as SSA, type recovery, block structuring, dead code elimination, variable merging, and output generation.

Estimated completion: 85-90%.

### SLEIGH Integration
- Compiled SLEIGH specs are included under `Enigma-Engine/sleigh/`.
- The full decompiler path can initialize language specs and lift code through Ghidra's decompiler infrastructure.
- PE/ELF auto-detection can select language IDs for common architectures.

Estimated completion: 80-90%.

### PE/ELF Loaders
- PE32/PE32+ parsing is implemented for sections, imports, exports, relocations, image base, and entry point.
- ELF32/ELF64 parsing is implemented for sections, symbols, dynamic imports, and entry point.
- `enigma_decompile_full` can auto-detect PE/ELF and fall back to raw binary mode.
- Recent fixes handle explicit `-base` rebasing safely.

Estimated completion: 70-80%.

### ProgramDB / Kernel Model
- Program, memory, symbols, references, functions, comments, namespaces, bookmarks, equates, relocations, source files, property maps, and SQLite persistence have substantial coverage.
- Many Java-side Ghidra interfaces have C++ equivalents.

Estimated completion: 70-80%.

### Data Type System
- Most primitive, pointer, array, string, enum, structure, union, typedef, float, complex, alignment, and data type manager pieces are present.
- Type persistence and manager expansion are already advanced.

Estimated completion: 75-85%.

### Function Prototype / ParamList / protorules Base
- ParamList, ParamEntry, ParamListStandard, return parameter lists, PrototypeModel, and many protorule filters/actions are implemented.
- This is a strong foundation for calling convention and function signature recovery work.

Estimated completion: 70-80%.

### Block And Subroutine Models
- Basic/simple block models and several subroutine models are implemented.
- Forward and backward flow analysis exists for subroutine discovery.

Estimated completion: 65-75%.

### CLI Decompiler
- `enigma_decompile_full` is the mature CLI path.
- Supports raw binaries and PE/ELF auto-detection.
- Supports entry/base controls, call-graph following, and output cleanup.

Estimated completion: 65-75%.

## What Is Not Complete Yet

### Enigma-Native / Capstone Pipeline
- Tool: `enigma_decompile`.
- Current flow: Capstone -> p-code mapper -> native `PrintC`.
- Useful for testing Enigma p-code structures and building helper analysis features.
- This is not the main decompiler path for the first version.
- It should not be treated as a replacement for the Ghidra C++ decompiler unless the project explicitly changes direction later.
- Native rules/actions mostly detect patterns and do not yet perform complete transformation/rewrite passes.

Estimated completion as full decompiler replacement: 10-20%.

### Native P-Code Model
- Core p-code structures are advanced.
- Varnodes, ops, blocks, Funcdata-like structures, print support, type propagation pieces, and mapping from Capstone are present.
- The remaining gap is robust transformation, simplification, SSA/heritage quality, and full action/rule semantics.

Estimated completion: 55-65%.

### Analyzer System
- The analyzer framework and registered analyzer set are now substantially ported.
- `PLAN/PROGRESS.md` records 132 registered analyzers after the W131 re-audit, with 132 real implementations and 0 analyzer-only stubs.
- Remaining work is mostly integration depth and real-binary validation: making analyzer output reliably feed ProgramDB, symbols, functions, references, stack data, switch/jump tables, and decompiler quality across PE/ELF/Mach-O samples.
- Treat old dependency-blocker notes as resolved unless a new compile/runtime failure proves otherwise.

Estimated completion: 70-80% for the ported analyzer layer; lower for real-world analysis quality until corpus testing is expanded.

### Disassembler Integration
- Capstone integration exists.
- It is useful, but not yet equivalent to Ghidra's full language/disassembler ecosystem.
- More work is needed for instruction prototypes, context registers, delay slots, architecture quirks, and tight integration with ProgramDB.

Estimated completion: 40-50%.

### Output Quality
- Real C output is produced.
- More work is needed for stable naming, imports, exports, function signatures, local variables, structs, global data, call targets, and type names.
- This is especially important before UI work, because the UI should display high-quality analysis data instead of compensating for weak backend output.

Estimated completion: 50-65%.

### CLI Regression Tests
- Existing test suites are strong for kernel and compile coverage.
- More real CLI tests are needed for `enigma_decompile_full`, especially PE/ELF, imports, exports, rebasing, internal calls, invalid binaries, and multi-function output.

Estimated completion: 45-60%.

### Mach-O Loader
- PE and ELF are the working loader priorities.
- Mach-O is not currently at the same level in the documented status.

Estimated completion: low / not ready.

### UI
- Intentionally deferred.
- No serious work should start here until engine outputs and program state are stable enough to consume.

Estimated completion: 0%.

### Plugin System
- Intentionally deferred.
- Should come after the backend API and UI architecture are more settled.

Estimated completion: 0%.

## Component Completion Table

| Component | Status | Estimated Completion |
|---|---:|---:|
| Ghidra C++ decompiler direct path | Working | 85-90% |
| SLEIGH integration | Working | 80-90% |
| PE/ELF loaders | Working | 70-80% |
| ProgramDB / kernel model | Advanced | 70-80% |
| Data type system | Advanced | 75-85% |
| Symbol/function/reference model | Advanced | 65-75% |
| Persistence / SQLite | Advanced | 65-75% |
| Function prototypes / ParamList / protorules | Advanced | 70-80% |
| Block/subroutine analysis | Advanced foundation | 65-75% |
| Native p-code model | Good foundation | 55-65% |
| Native/Capstone helper pipeline | Experimental/supporting | 10-20% |
| Analyzer system | Advanced port, needs real-binary validation | 70-80% |
| Disassembler integration | Partial | 40-50% |
| CLI tools | Working | 65-75% |
| Tests | Good kernel coverage, weak CLI coverage | 55-65% |
| UI | Deferred | 0% |
| Plugin system | Deferred | 0% |

## How Much Remains

### MVP Without UI/Plugin

Estimated remaining work: 25-35%.

This means a strong backend MVP is within reach. The focus should be stability, real-world binary testing, loader/decompiler integration, and output quality.

### Full Java-Free Ghidra-Like Backend Before UI/Plugin

Estimated remaining work: 45-55%.

This includes not only decompilation, but a broader analyzer ecosystem, richer ProgramDB integration, better function discovery, better symbol/type recovery, and stronger persistence behavior.

### Full Product With UI/Plugin

Not estimated here because UI and plugin system are intentionally deferred. They should be estimated after the backend API shape is stable.

## Recommended Work Order

### 1. Add CLI Regression Tests First

This should be the next priority.

Add automated tests for `enigma_decompile_full` covering:
- raw binary with explicit `-base` and `-entry`.
- PE auto-detection.
- ELF auto-detection.
- explicit `-base` rebase on PE/ELF.
- explicit `-entry` override.
- binary with one internal call.
- binary with multiple reachable internal calls.
- import call that must be skipped safely.
- invalid or unsupported binary fallback behavior.
- output has no duplicate function definitions.
- output keeps C-valid identifiers.

Why first: the full decompiler now works, so regressions in this path are expensive. Lock it down before adding more behavior.

### 2. Test More Real Binaries

After CLI tests, run a small corpus:
- tiny raw x86-64 samples.
- small PE console executable.
- PE with imports.
- PE with multiple internal functions.
- small ELF executable.
- ELF with imports.
- stripped binary.
- binary with switch/jump table.

Record failures as targeted tasks instead of broad rewrites.

### 3. Improve Function And Symbol Naming

Focus on:
- import names.
- export names.
- internal call target names.
- fallback names like `sub_<addr>`.
- duplicate/conflicting symbol names.
- stable formatting across rebased and non-rebased binaries.

Good names make every later UI and analysis feature easier.

### 4. Strengthen Function Discovery

The batch call-graph traversal is useful, but it starts from known calls.

Next improvements:
- discover function starts from symbols.
- discover functions from exports.
- discover functions from entry and call targets.
- avoid import thunks as normal internal functions.
- record non-decompilable functions without crashing.

### 5. Validate Analyzer Layer Around ProgramDB

The analyzer port is now broad enough that the next useful work is validation and wiring quality:
- run analyzers on real PE/ELF/Mach-O samples.
- confirm discovered functions, references, imports, thunks, stack variables, switch tables, comments, bookmarks, and equates land in ProgramDB.
- compare important cases against Ghidra behavior.
- record each mismatch as a targeted fix.

This should happen before UI because the UI should consume analysis results, not invent them.

### 6. Improve Type And Prototype Recovery Integration

The type and ParamList foundations are advanced. The next useful work is integration:
- connect loader ABI/compiler spec to prototype model.
- improve calling convention selection.
- improve return type and parameter storage recovery.
- feed recovered types into decompiler output.
- test across Windows x64 and SysV x64.

### 7. Keep Native/Capstone Pipeline As Supporting Work

Do not prioritize replacing the working Ghidra C++ decompiler path.

Use the native/Capstone pipeline for:
- validating Enigma's own p-code model.
- testing Capstone mapping.
- experimenting with native analysis.
- helper views or diagnostics if useful later.

Only push it toward full decompiler replacement if there is a future explicit decision. The current project direction is to improve the original Ghidra C++ decompiler directly.

### 8. Leave UI And Plugin System Last

Recommended prerequisites before UI:
- stable CLI output.
- stable ProgramDB load/analyze/decompile flow.
- enough analyzer output to display functions, symbols, references, memory map, and decompiled C.
- clear API boundary for frontend/engine communication.

Recommended prerequisites before plugin system:
- stable backend API.
- stable project/database format.
- clear extension points.
- security model for plugin execution.

## Working Rules

- Keep `PLAN/PROGRESS.md` as the official progress file.
- Do not recreate progress files inside `Enigma-Engine/` unless the project policy changes.
- After each functional change, run at least:
  - `cmake --build build-cmake`
  - `ctest --test-dir build-cmake --output-on-failure`
- For decompiler CLI changes, also run at least one direct `enigma_decompile_full` sample.
- Prefer small, testable improvements over large rewrites.
- Use `ghidra-source code/` as the behavioral reference when porting Java-side systems.
- Use original Ghidra C/C++ components directly where available; do not rewrite them just for ownership.
- Keep UI/plugin decisions deferred until backend output and ProgramDB state are reliable.

## Current Recommendation

The best next move is:

1. Add W109/W110 CLI regression tests.
2. Build a small PE/ELF/raw binary sample corpus.
3. Improve naming and call target handling in `enigma_decompile_full`.
4. Then strengthen function discovery and analyzer integration.

This path gives the fastest increase in project reliability without getting distracted by UI or a premature from-scratch decompiler rewrite.
