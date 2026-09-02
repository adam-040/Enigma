# GUI-Facing Work Deferred (marked 2026-08-20)

Policy decided 2026-08-20: proceed through the `ENIGMA_ENGINE_GAPS_MASTER_PLAN.md`
backlog backend-first. Every task with a **Direct GUI-Visible Feature** (plan
section 4.1) is listed below with its GUI component. Backend/engine parts are
done as part of each task; the GUI components are deferred and will be done as
one batch after the remaining backend tasks are complete. **No commits made -
user commits.**

## Deferred GUI items (do after backend batch)

| # | Task | GUI component | Target files (GUI) | Backend status |
|---|---|---|---|---|
| G1 | Task 2.4 (GP-7088) | `.obj` / `.lib` format filter in file-open dialog; sections shown in Memory Map / Section Tree | `src/gui/MainWindow.cpp` | backend DONE 2026-08-20 |
| G2 | Task 2.5 (GP-7046) | dyld_shared_cache dylib browser dialog (modal multi-select tree of embedded dylibs, extract/filter) | `src/gui/` new dialog + `src/gui/MainWindow.cpp` | backend pending |
| G3 | Task 2.6 (GP-6502) | PE DVRT & Guard CFG security badges (shield icon on valid indirect-call targets in disassembly; structured Load Config tree in properties) | `src/gui/DisassemblyFieldView.cpp`, `src/gui/ProgramPropertiesDialog.cpp` | DONE 2026-08-22 |
| G4 | Task 2.7 (GP-7124) | Firmware memory map views (sparse blocks for non-contiguous ROM ranges in Memory Map dock / Hex view) — mostly automatic once loader emits sections | `src/gui/` Memory Map dock | backend pending |
| G5 | Task 3.1 (GP-6291/GP-6325) | Go package grouping in FunctionExplorer (tree folders `main`, `runtime`, `fmt`, ...) + Go version/dependencies in ProgramPropertiesDialog | `src/gui/FunctionExplorer.cpp`, `src/gui/ProgramPropertiesDialog.cpp` | backend pending |
| G6 | Task 3.2 (GP-6327) | ObjC "Classes" category in Symbol Tree (classes/protocols/categories/ivars nodes) | `src/gui/` Symbol Tree widget | backend pending |
| G7 | Task 3.3 (GP-6281/GP-6137) | Swift types in Data Types dock + `swiftcall` convention tags — mostly automatic via DataTypeManager once analyzer registers types | verify `src/gui/` Data Types dock | backend pending |
| G8 | Task 3.4 (GP-6108) | Rust v0 clean prototypes in SymbolTree/Listing/Decompiler — automatic once analyzer demangles names | none (verify only) | backend pending |
| G9 | Task 3.5 (GP-6345) | Offcut-string labels (`s_Message_+5`) in Listing / XRefs — automatic once analyzer emits sub-labels | none (verify only) | backend pending |
| G10 | Task 4.1 (GP-5808) | Type conflict diff dialog (side-by-side Old vs New struct, Merge/Overwrite/Rename) in C parser import flow | `src/gui/` new dialog + `src/gui/MainWindow.cpp` | DONE 2026-08-22 |
| G11 | Task 4.2 (GP-7118/GP-7044) | StructureEditorWidget dock (interactive struct/union table editor, live Decompiler refresh) | `src/gui/StructureEditorWidget.h/.cpp`, `src/gui/MainWindow.cpp` | DONE 2026-08-22: typeModified→decompiler wired; typeSelected→status bar; field type picker (QInputDialog with common types); field detail panel (QTableWidget showing offset/size/type/name); size display |
| G12 | Task 4.4 (GP-6766) | MIPS16e display in DisassemblyFieldView (16-bit vs 32-bit mode visual distinction) | `src/gui/DisassemblyFieldView.cpp` | PARTIALLY DONE: isMips16e flag + blue tint + tooltip added (2026-08-22); 16-bit marker in address gutter still pending |