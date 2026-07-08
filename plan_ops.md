Phase 1: Architecture Audit & Feature Matrix
Current Architecture Summary
Data flow (strictly one-way, no write-back):
Binary file (disk)
  → BinaryLoader::rawData_ (in-memory copy)
    → Memory::setBytes() → DefaultMemoryBlock::data_
      → [editing would go here — currently nothing]
        → WorkingSnapshot → FlatBuffers (project format only)
          ✗ NO path back to PE/ELF/Mach-O binary
What exists:
- Memory API — Full setByte/setBytes/setShort/setInt/setLong, createInitializedBlock/UninitializedBlock/removeBlock at data model level (Memory.h:76-92, Memory.cpp:41-182)
- EventLog — 20 event types (RENAME_FUNCTION, CREATE_FUNCTION, ADD_COMMENT, etc.) with undo/redo per event + ProgramChangeSet for low-level change tracking (EventLog.h, Event.h)
- WorkingSnapshot — Full ProgramDB serialization to FlatBuffers (SnapshotWriter.cpp:378 lines) — saves memory blocks + all metadata
- Repository/CommitManager/BranchManager — Project-level versioning infrastructure
- Binary format parsers — PE (full), ELF32/64 (full + symbols/imports), Mach-O 32/64/fat (basic)
- All GUI edit slots declared — 10 empty stubs in MainWindow (lines 1624-1635)
What is missing:
- No hex editing — HexView is display-only; no setByte() calls from GUI
- No binary export — No save() method on BinaryLoader; no QFileDialog::getSaveFileName()
- No assembler — No instruction patching or code cave support
- No patch management — No patch history, conflict detection, patch file import/export
- No scripting — No API, no batch processing
- No structural editing — No PE/ELF header/section editors, no resource editor
- No binary diff — No comparison or patch generation
- No checksum recalc — No PE CheckSum recalculation
Feature Comparison Matrix
#	Capability	Enigma	Ghidra	IDA Pro	Binja	Cutter/Rizin
1	Raw hex editing	❌	✅	✅	✅	✅
2	Byte insertion/removal	❌	✅	✅	✅	✅
3	Fill/NOP selection	❌	✅	✅	✅	✅
4	Instruction patching	❌	✅	✅	✅	✅
5	Built-in assembler	❌	✅	✅	✅	✅
6	Replace instr (preserve CF)	❌	✅	✅	✅	✅
7	Code caves	❌	✅	✅	✅	✅
8	Branch retargeting	❌	✅	✅	✅	✅
9	Function create/delete/split	🔶 API	✅	✅	✅	✅
10	Change function boundaries	❌	✅	✅	✅	✅
11	Rename symbols/functions	🔶 API+Event	✅	✅	✅	✅
12	Rename variables/types/namespaces	🔶 API	✅	✅	✅	✅
13	Edit comments	🔶 API+Event	✅	✅	✅	✅
14	Bookmarks	🔶 API+Event	✅	✅	✅	✅
15	Labels	🔶 API+Event	✅	✅	✅	✅
16	Edit strings	❌	✅	✅	✅	✅
17	Edit numeric constants	❌	✅	✅	✅	✅
18	Edit structs/unions/enums	🔶 API	✅	✅	✅	✅
19	Edit arrays	🔶 API	✅	✅	✅	✅
20	Edit relocations	❌	✅	✅	✅	✅
21	Edit imports	❌	✅	✅	✅	✅
22	Edit exports	❌	✅	✅	✅	✅
23	Edit ELF GOT/PLT	❌	✅	✅	✅	✅
24	Edit PE IAT	❌	✅	✅	✅	✅
25	Edit TLS	❌	✅	✅	✅	✅
26	Edit resources (PE)	❌	✅	✅	✅	✅
27	Edit version info	❌	✅	✅	✅	✅
28	Edit manifest	❌	✅	✅	✅	✅
29	Edit icons	❌	✅	✅	✅	✅
30	Edit certificates	❌	✅	✅	✅	❌
31	Edit ELF notes	❌	✅	✅	✅	✅
32	Edit program headers	❌	✅	✅	✅	✅
33	Edit section headers	❌	✅	✅	✅	✅
34	Add/remove/resize sections	🔶 API	✅	✅	✅	✅
35	Change section permissions	🔶 API	✅	✅	✅	✅
36	Change entry point	❌	✅	✅	✅	✅
37	Change image base	🔶 API	✅	✅	✅	✅
38	Change subsystem	❌	✅	✅	✅	✅
39	Edit file headers	❌	✅	✅	✅	✅
40	Edit loader flags	❌	✅	✅	✅	✅
41	Recalculate checksums	❌	✅	✅	✅	✅
42	Preserve digital signatures	❌	✅	✅	✅	✅
43	Binary diff	❌	✅	✅	✅	✅
44	Apply IPS/BPS/xdelta patches	❌	✅	✅	✅	✅
45	Generate patch files	❌	✅	✅	✅	✅
46	Export modified executable	❌	✅	✅	✅	✅
47	Save patched binary	❌	✅	✅	✅	✅
48	Undo/Redo	🔶 API+UI stubs	✅	✅	✅	✅
49	Patch history	❌	✅	✅	✅	✅
50	Patch manager	❌	✅	✅	✅	✅
51	Patch preview	❌	✅	✅	✅	✅
52	Conflict detection	❌	✅	✅	✅	✅
53	Integrity verification	❌	✅	✅	✅	✅
54	Automatic backup	❌	✅	✅	✅	✅
55	Patch scripting API	❌	✅	✅	✅	✅
56	Batch patching	❌	✅	✅	✅	✅
Legend: ✅ = Complete | 🔶 = Partial (API/event exists, no GUI) | ❌ = Missing
Phase 2: Development Roadmap
Milestone 1 — Core Editing Infrastructure (HIGHEST IMPACT, Estimated: 2-3 weeks)
Purpose: Enable the most fundamental workflow — modify bytes and save the result. This is the minimum viable patching capability.
Deliverable	Effort	Description
1a. Hex editing in HexView	3-4 days	Make HexView editable: click cell → type hex digit → Memory::setByte(). Support overtype mode, cursor movement after edit, modified-cell highlighting (color change or dot).
1b. Fill/NOP selection	1 day	Right-click on hex selection → "Fill with NOP (0x90)" / "Fill with 0x00" / "Fill with value...". Uses Memory::setBytes().
1c. Copy/paste hex bytes	2 days	Copy selected hex bytes as hex string to clipboard; paste from clipboard into selection. Ctrl+C / Ctrl+V in HexView.
1d. Binary export (save to file)	5 days	Add BinaryLoader::save(filePath) that reconstructs the binary from Memory blocks (or rawData_ patched from memory). For PE: recalculate CheckSum, handle section alignment, preserve certificate table if present. For ELF: recalculate section header values. Add "Export Binary..." / "Save As..." to File menu with QFileDialog::getSaveFileName().
1e. Automatic backup	1 day	Before first save, create filename.bak. On "Save As", write clean copy.
Required changes:
- src/gui/HexView.cpp — Add key press handler for hex digit entry, overtype mode, modified-byte tracking, NOP/fill context menu
- src/core/BinaryLoader.cpp — Add save(filePath) method with PE/ELF/Mach-O serialization
- src/include/ghidra/BinaryLoader.h — Add virtual save(filePath) = 0
- src/gui/MainWindow.cpp — Add "Save As...", "Export Binary" menu items, connect slots
- src/main.cpp — Possibly add --save command line flag
Risks:
- PE/ELF format reconstruction is complex (import tables, relocations, section alignment). Start with simple "copy rawData_ with bytes modified at file offsets" approach, then layer format-specific reconstruction.
- Certificate table must be preserved by offset or stripped.
Complexity: Medium-High
Milestone 2 — Edit Menu & Metadata Editing (QUICK WINS, 1-2 weeks)
Purpose: Wire the existing API+EventLog to the GUI. High-value, low-effort features.
Deliverable	Effort	Description
2a. Wire Undo/Redo	1 day	Connect executeWithEvent() to EventLog. Connect Edit→Undo/Redo to eventLog_->undo(program) / eventLog_->redo(program). Enable keyboard shortcuts Ctrl+Z / Ctrl+Shift+Z. Wire updateUndoRedoActions() to enable/disable based on canUndo()/canRedo().
2b. Rename function	1 day	Context menu in disassembly/decompiler → "Rename Function" → QInputDialog::getText() → Function::setName() → RenameFunctionEvent.
2c. Delete function	1 day	Context menu → "Delete Function" → QMessageBox::question() confirm → FunctionManager::removeFunction() → DeleteFunctionEvent.
2d. Add/Remove label	1 day	Context menu → "Add Label" → QInputDialog → SymbolTable::createLabel(). Context → "Remove Label" → SymbolTable::removeSymbolSpecial(). Track with AddSymbolEvent/RemoveSymbolEvent.
2e. Set/Remove comment	1 day	Context menu → "Set Comment" → QInputDialog::getMultiLineText() → CodeUnit::setComment(). Context → "Remove Comment" → clear comment. Track with AddCommentEvent/ModifyCommentEvent/DeleteCommentEvent.
2f. Add/Delete bookmark	1 day	Context menu → "Add Bookmark" → QInputDialog → BookmarkManager::setBookmark(). Context → "Delete Bookmark" → BookmarkManager::removeBookmark(). Track with AddBookmarkEvent/DeleteBookmarkEvent.
Required changes:
- src/gui/MainWindow.cpp — Implement all empty stubs (lines 1624-1635), connect Edit menu actions to slots
- src/gui/FieldView.cpp — Add context menu items for rename/delete/label/comment/bookmark
- src/storage/EventLog.cpp — Verify all event types work correctly
Risks: Minimal. The API and events already exist. This is pure GUI wiring.
Complexity: Low
Milestone 3 — Patch Manager with Transaction Support (2-3 weeks)
Purpose: Track all byte-level modifications with preview, history, and conflict detection.
Deliverable	Effort	Description
3a. ByteChangeEvent + EventLog extension	2 days	New event type for raw byte changes: stores (address, oldBytes, newBytes). Extend EventLog to support byte-level events alongside metadata events.
3b. Modified-byte tracking in HexView	1 day	Highlight modified bytes (different background color, bold, or overdot). Store modification state per byte address.
3c. Patch Manager dialog	3 days	New QDialog — PatchManager. Shows list of all modifications: address, original bytes, new bytes, section, timestamp. Supports: select → jump to address in HexView, revert single change, revert all changes, preview byte diff.
3d. Patch file import/export (IPS)	3 days	IPS format support: export current modifications as .ips patch file. Import IPS patch → show preview → apply or reject. (BPS can follow in a later iteration.)
3e. Conflict detection	2 days	When loading a patch file or reapplying: detect if target bytes at an address don't match expected originals. Show conflict in Patch Manager with options: skip, overwrite, force.
Required changes:
- src/storage/Event.h — Add ByteChangeEvent type
- src/gui/HexView.cpp — Add modified-byte tracking and highlighting
- src/gui/PatchManager.cpp (new) — Patch manager dialog
- src/core/PatchFile.cpp (new) — IPS/BPS patch file reader/writer
- src/gui/MainWindow.cpp — "Patch Manager" menu item, connect signals
Risks:
- IPS patch format has a 16MB address limit (16-bit). BPS or custom format needed for larger binaries.
- Modified-byte state must persist across view rebuilds.
Complexity: Medium
Milestone 4 — Assembly Patching & Code Caves (3-4 weeks)
Purpose: Allow instruction-level patching with a built-in assembler.
Deliverable	Effort	Description
4a. Integrate assembler (Keystone)	3 days	Add Keystone dependency to CMakeLists. Create Assembler class wrapping Keystone for x86/x64 (ARM/RISCV later). assemble(assembly, address, arch, mode) → vector<uint8_t>.
4b. Inline assembly dialog	2 days	Context menu on instruction in disassembly → "Patch Instruction" → QDialog with QPlainTextEdit showing original instruction, input for new assembly. Preview assembled bytes. On accept → Memory::setBytes().
4c. NOP slide / Fill	1 day	Context → "NOP Slide" → fill range with NOPs. "Fill Range..." → dialog with value/pattern.
4d. Code cave finder	3 days	Scan sections for "caves" — runs of zero bytes or NOPs large enough to hold a patch. Show results in a dialog with size, address, section. Insert jump/call to cave address.
4e. Branch retargeting	2 days	Context menu on CALL/JMP → "Retarget to..." → address input. Recalculate relative offset. Validate target address.
Required changes:
- CMakeLists.txt — Add keystone dependency
- src/core/Assembler.h/.cpp (new) — Assembler wrapper
- src/gui/AsmPatchDialog.h/.cpp (new) — Assembly patch dialog
- src/gui/CodeCaveFinder.h/.cpp (new) — Code cave scanner/finder
- src/gui/DisassemblyFieldView.cpp — Context menu for instruction patching
Risks:
- Keystone on Windows may have build challenges (MSVC vs MinGW, static linking)
- Branch offset recalculation needs careful handling for short vs near vs far jumps
- Code caves in non-executable sections won't work without permission changes
Complexity: Medium-High
Milestone 5 — Structured Data Editing (2-3 weeks)
Purpose: Edit data types, structures, strings, and numeric values.
Deliverable	Effort	Description
5a. Edit strings	2 days	HexView/disassembly → detect string → "Edit String" → inline text editor (ASCII/UTF-8/UTF-16). Update bytes on accept.
5b. Edit data type	2 days	Right-click on data → "Edit Data Type" → show type chooser. Data::setDataType().
5c. Structure/Union/Enum editor	5 days	New QDialog showing structure layout as tree. Add/remove/reorder fields. Edit field names, types, offsets. Uses Composite::addComponent/removeComponent, Enum::add/remove.
5d. Edit numeric constants (equates)	1 day	Right-click immediate value → "Edit Equate" → rename/revalue. Uses EquateTable::setName/setValue.
Required changes:
- src/gui/StringEditor.h/.cpp (new) — String editor dialog
- src/gui/StructureEditor.h/.cpp (new) — Structure/Union/Enum editor
- src/gui/HexView.cpp — String editing context menu
- src/gui/FieldView.cpp — Data type/equate context menu
Risks: Structure editor is complex — needs to handle nested structures, arrays, bitfields, packing, alignment.
Complexity: Medium
Milestone 6 — Binary Structural Editing (3-4 weeks)
Purpose: Edit PE/ELF headers, sections, imports, exports, and resources.
Deliverable	Effort	Description
6a. Section header editor	3 days	Dialog showing all sections with editable fields: name, VA, size, file offset, permissions (R/W/X). Add/remove/resize sections. MemoryBlock::setName/setPermissions, BinaryLoader::save() updates headers.
6b. PE header editor	3 days	Dialog/Dock for PE headers: DOS header, NT headers, File header, Optional header. Edit entry point, image base, subsystem, DLL characteristics, etc.
6c. ELF header editor	2 days	Dialog for ELF: e_type, e_machine, e_entry, e_flags, program header flags, section header fields.
6d. Import/Export table editor	3 days	Dialog showing imports by DLL, exports by name. Add/remove entries. Requires updating PE IAT/INT tables or ELF .dynsym/.rela.dyn.
6e. Relocation editor	2 days	Dialog showing all relocations with address, type, symbol. Add/remove.
6f. Checksum recalculation	1 day	BinaryLoader::recalculateChecksum() — PE CheckSum field calculation (sum of words + file size). Call before save.
Required changes:
- src/gui/SectionEditor.h/.cpp (new) — Section editor dialog
- src/gui/PEHeaderEditor.h/.cpp (new) — PE header editor
- src/gui/ELFHeaderEditor.h/.cpp (new) — ELF header editor
- src/gui/ImportExportEditor.h/.cpp (new) — Import/Export editor
- src/core/BinaryLoader.cpp — Add recalculateChecksum(), header modification methods
Risks:
- Editing PE headers requires understanding the full PE format (optional header size varies, data directory entries shift)
- Modifying imports requires rebuilding the import directory table (IAT + INT + import lookup tables)
- Section add/remove requires shifting all subsequent file offsets and updating headers
Complexity: High
Milestone 7 — Scripting & Batch Processing (3-4 weeks)
Purpose: Enable automation via Python scripting and batch patching.
Deliverable	Effort	Description
7a. Python bindings (pybind11)	5 days	Add pybind11 dependency. Bind key classes: ProgramDB, Memory, FunctionManager, SymbolTable, BinaryLoader. Expose setByte(), getByte(), createFunction(), etc.
7b. Script console	3 days	Interactive Python console in ConsoleWidget (or new dock). QPlainTextEdit for input, output displayed inline. Execute python3 embedded interpreter.
7c. Script manager	2 days	Dialog listing scripts in scripts/ directory. Run button, edit button (open in external editor), output in console.
7d. Batch patching	3 days	Load multiple binaries → apply same set of patches (from patch file or script) → export patched binaries. Progress bar, error log.
Required changes:
- CMakeLists.txt — Add pybind11 dependency, Python development libraries
- src/scripting/PythonBindings.cpp (new) — pybind11 module with Enigma bindings
- src/gui/ScriptConsole.h/.cpp (new) — Script console widget
- src/gui/ScriptManager.h/.cpp (new) — Script manager dialog
- src/gui/BatchPatcher.h/.cpp (new) — Batch patching UI
Risks:
- pybind11 + embedded Python adds significant build complexity
- Windows Python embedding requires matching Python version and architecture
- Python GIL management in Qt event loop
Complexity: High
Milestone 8 — Binary Diff & Patch File Generation (2-3 weeks)
Purpose: Compare binaries and generate/apply standard patch formats.
Deliverable	Effort	Description
8a. Binary diff tool	4 days	New dock or dialog: load original + modified → compute byte-level diff → show aligned view with differences highlighted. Sync navigation.
8b. xdelta3 integration	2 days	Add xdelta3 dependency. Generate VCDIFF patches between original and modified. Apply patches to third-party binaries.
8c. BPS patch support	2 days	BPS format reader/writer. Support apply + create.
8d. Patch summary report	1 day	Generate HTML/text report listing all modifications with addresses, old/new bytes, sections.
Required changes:
- CMakeLists.txt — Add xdelta3 dependency
- src/gui/BinaryDiffView.h/.cpp (new) — Binary diff viewer
- src/core/PatchFile.cpp — Add BPS/xdelta support alongside IPS
Risks: Large binary diffs are memory-intensive. Need progress reporting and cancellation.
Complexity: Medium
Milestone 9 — Polish & Integrity (1-2 weeks)
Purpose: Hardening, UX polish, and production readiness.
Deliverable	Effort	Description
9a. Integrity verification	2 days	After save: reload binary, compare bytes, verify checksum. Report mismatches.
9b. Patch preview before save	2 days	Show summary of all changes before final save. Allow review and selective revert.
9c. Keyboard shortcut customization	1 day	QShortcut for all editing actions. Configurable shortcuts (optional: settings file).
9d. Right-click context menus (all views)	2 days	Comprehensive context menus in HexView, DisassemblyFieldView, DecompilerView: copy/paste bytes, fill/NOP, patch instruction, rename, comment, bookmark, label, references.
9e. Documentation & tooltips	2 days	Tooltip strings for all actions. Status bar hints. Brief user guide for patching workflow.
Implementation Strategy
Guiding Principles
1. Never break existing functionality — all changes must preserve existing display, navigation, analysis
2. Modular architecture — each milestone is self-contained with its own new files
3. Reuse existing analysis — use existing Memory::setBytes(), EventLog, BinaryLoader::populateProgram()
4. Progressive disclosure — basic hex editing first, advanced features later
5. Format agnostic where possible — byte-level editing works the same for PE, ELF, Mach-O
Critical Dependencies Order
Milestone 1 (Hex Editing + Export)
  └→ Milestone 2 (Edit Menu)
       └→ Milestone 3 (Patch Manager)
            ├→ Milestone 4 (Assembly Patching)
            ├→ Milestone 5 (Structured Data)
            ├→ Milestone 6 (Structural Editing)
            └→ Milestone 7 (Scripting)
                 └→ Milestone 8 (Diff & Patch Files)
                      └→ Milestone 9 (Polish)
Milestones 2-5 can be developed in parallel after Milestone 1 is complete.
Format Reconstruction Strategy
For Milestone 1d (Binary Export) , the simplest viable approach:
1. Phase A — Copy rawData_ (original file bytes), then apply Memory block modifications by mapping block addresses back to file offsets via SectionInfo::fileOffset. This works for simple byte patches that don't change the file structure.
2. Phase B — For section adds/removes/resizes (Milestone 6), rebuild the PE/ELF headers from scratch using the current SectionInfo data.
3. Phase C — For import/export/relocation edits (Milestone 6), rebuild the corresponding directory tables.
New Files Summary
Milestone	New Files
M1	— (modifications to existing files)
M2	— (modifications to existing files)
M3	PatchManager.h/.cpp, PatchFile.h/.cpp, ByteChangeEvent in Event.h
M4	Assembler.h/.cpp, AsmPatchDialog.h/.cpp, CodeCaveFinder.h/.cpp
M5	StringEditor.h/.cpp, StructureEditor.h/.cpp
M6	SectionEditor.h/.cpp, PEHeaderEditor.h/.cpp, ELFHeaderEditor.h/.cpp, ImportExportEditor.h/.cpp
M7	PythonBindings.cpp, ScriptConsole.h/.cpp, ScriptManager.h/.cpp, BatchPatcher.h/.cpp
M8	BinaryDiffView.h/.cpp
M9	— (modifications to existing files)
Awaiting your approval before implementation begins. Any changes to the priority, scope, or sequence?