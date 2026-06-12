# Backend API Freeze Notes

This file defines the backend surface that the first UI/plugin layer should use.
The UI should call stable engine services instead of reaching into decompiler,
loader, storage, or ProgramDB internals directly.

## First UI Surface

1. `loadBinary(path)`
   - Uses `BinaryLoader`.
   - Populates `ProgramDB`.
   - Sets language/compiler IDs, memory blocks, sections, imports, exports,
     symbols, and entry function.

2. `openProject(repoPath)`
   - Uses `Repository` + `WorkingSnapshot::load`.
   - Returns a populated `ProgramDB`.
   - Rebuilds LMDB index if missing.

3. `saveProject(repoPath, program)`
   - Uses `WorkingSnapshot::save`.
   - Must preserve memory bytes, functions, symbols, bookmarks, equates,
     external locations, and storage metadata.

4. `commitProject(repoPath, program, message)`
   - Uses `CommitManager`.
   - Persists a snapshot and compacted ChangeSet.

5. `listFunctions(program)`
   - Use `DecompInterface::getFunctions()` for UI-facing summaries.
   - Do not let UI iterate `FunctionManager` internals directly.

6. `decompileFunction(program, entryAddress)`
   - Uses `DecompInterface::decompileFunction(Address, TaskMonitor*)`.
   - Must return failure, not crash, for addresses outside memory.

7. `decompileFunction(program, function)`
   - Uses `DecompInterface::decompileFunction(Function*, TaskMonitor*)`.
   - Preferred once the UI has a selected function.

8. `renameSymbol` / `renameFunction`
   - Should go through ProgramDB managers and create storage Events.
   - UI must not mutate tables without emitting EventLog/ChangeSet state.

9. `listBranches` / `switchBranch` / `createBranch`
   - Uses `BranchManager`.
   - UI should treat branch state as repository state, not as loose files.

## Current Stable Pieces

- `BinaryLoader` covers PE/ELF/Mach-O import into `ProgramDB`.
- `DecompInterface` bridges `ProgramDB` to the Ghidra C++ decompiler.
- `WorkingSnapshot` now persists loaded memory bytes, so reloaded projects can
  decompile without reloading the original binary.
- Storage phases 1-5 pass: snapshots, EventLog, commits, branches, LMDB index.
- Corpus regression has 8 exact references.

## Deferred Until After UI Starts

- A public C ABI or N-API wrapper.
- Full loader parity for every Ghidra Java loader.
- Conditional-branch exact corpus until output type naming is deterministic.
- AI/LLM features.
