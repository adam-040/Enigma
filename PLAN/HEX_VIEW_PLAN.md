# HexView Improvements — Implementation Plan

## Status: IN PROGRESS

## Current State
HexView is a **read-only hex viewer** with context-menu patching. It has:
- Full hex display (address + hex + ASCII columns)
- Cross-view selection sync via SelectionManager
- Dual-column selection (hex + ASCII linked by byteIndex)
- Live PatchMemory overlay visualization (orange)
- Context-menu: Patch Byte, NOP Fill, Patch String
- Keyboard: navigation, Shift-select, Copy, Select All

**Missing**: inline editing, paste, undo, go-to, search, data interpretation, bookmarks, status bar.

---

## Phase 1: Core Editing (HIGH)
**Goal**: User can type hex digits to modify bytes in-place.

### 1a. Local Edit Stack
- `HexEditUndoEntry` struct: `{addr, oldValue, newValue}`
- `QVector<HexEditUndoEntry> undoStack_`, `redoStack_`
- Max 10,000 entries (FIFO discard)
- `pushUndo(addr, oldVal, newVal)` — clears redo stack

### 1b. Inline Hex Editing
- Override `keyPressEvent` in HexView (not FieldView)
- On hex digit key (0-9, a-f, A-F):
  - Find byte token at caret position
  - If caret is on a hex token, modify the nibble under caret
  - Track `editNibble_` (0=high, 1=low) and `editAccumulator_`
  - First nibble: store, move caret right, wait for second
  - Second nibble: commit byte via `patchByte(addr, assembledByte)`
  - Toggle `editNibble_` each keystroke
- On arrow left/right during edit: commit pending nibble, move
- On Escape: cancel edit, revert nibble
- Visual: highlight currently-editing byte with distinct color (yellow)

### 1c. Byte Patching via PatchMemory
- When second nibble committed, call:
  ```
  patchMemory_->applyPatch({newByte}, addr)
  ```
- Push to undo stack
- Emit `byteEdited(addr, newByte)` signal for MainWindow to refresh disasm

### 1d. Paste (Ctrl+V)
- Read clipboard text
- Parse as hex string: strip spaces/0x prefixes, validate [0-9a-fA-F]
- If odd-length, pad leading nibble with 0
- Convert to byte vector
- Starting at caret address, write bytes sequentially
- Push each to undo stack
- Emit `bytesPasted(startAddr, count)`

### 1e. Undo/Redo (Ctrl+Z / Ctrl+Y)
- Pop undo stack, write old values back to PatchMemory
- Push to redo stack
- Refresh hex display at affected addresses
- Emit `undoPerformed(addr, size)` / `redoPerformed(addr, size)`

### Files Modified
- `src/gui/HexView.h` — undo stack, edit state, signals, methods
- `src/gui/HexView.cpp` — keyPressEvent, paste, undo/redo, paint editing highlight

---

## Phase 2: Navigation (HIGH)
**Goal**: Go to any address, search for hex/string patterns.

### 2a. Go to Address (Ctrl+G)
- `QInputDialog::getText` with hex input
- Validate: parse as uint64_t, check `containsAddress(addr)`
- If valid: `seek(addr)`, emit `seekRequested(addr)`
- Add to context menu: "Go to Address..."

### 2b. Search / Find (Ctrl+F)
- Non-modal `HexSearchBar` widget (embedded in HexView or as floating toolbar)
- Search modes: Hex pattern, ASCII text, wildcard (`??` or `*`)
- Incremental search (search as user types)
- Match highlighting: `highlightMatches_` vector of `(line, byteStart, byteEnd)`
- F3 / Enter = Find Next, Shift+F3 = Find Previous
- Navigate to first match, select matched range
- Status: "Match 3 of 17" in search bar

### Files Modified
- `src/gui/HexView.h/.cpp` — Ctrl+G, Ctrl+F, search state
- `src/gui/HexSearchBar.h/.cpp` — **NEW** search widget
- `src/gui/MainWindow.cpp` — connect new signals

---

## Phase 3: Data Tools (MEDIUM)
**Goal**: Interpret bytes as types, copy in multiple formats, bookmark addresses.

### 3a. Interpret Selection As Type
- Context menu: "Interpret As →"
  - Int8, Int16, Int32, Int64 (little-endian)
  - UInt8, UInt16, UInt32, UInt64
  - Float (32-bit IEEE), Double (64-bit IEEE)
  - ASCII string (null-terminated)
- Shows result in a tooltip or small popup
- Uses current selection range (must be exact size for type)

### 3b. Copy As Hex / C Array
- Context menu: "Copy As →"
  - "Hex String": `48 89 E5 48 83 EC 20`
  - "C Array": `uint8_t data[] = { 0x48, 0x89, 0xE5 };`
  - "Python Bytes": `b'\x48\x89\xe5'`
- Uses byte selection range (not text selection)

### 3c. Bookmarks
- `QVector<uint64_t> bookmarks_`
- Ctrl+D: toggle bookmark at caret address
- Context menu: "Toggle Bookmark"
- Bookmarked addresses shown with bookmark glyph in gutter
- Navigate bookmarks: Ctrl+Up/Down among bookmarks

### Files Modified
- `src/gui/HexView.h/.cpp` — bookmark storage, interpret/copy-as methods
- `src/gui/HexView.cpp` — context menu additions, tooltip for interpretation

---

## Phase 4: UI Polish (MEDIUM)
**Goal**: Status bar, overwrite/insert toggle, find & replace.

### 4a. Status Bar
- Show at bottom of HexView viewport (or MainWindow status bar):
  - Current offset: `Offset: 0x00401000`
  - Selection size: `Selection: 16 bytes`
  - Edit mode: `Overwrite` / `Insert`
  - Patch count: `4 patches`
- Updated on caret move, selection change, edit

### 4b. Overwrite / Insert Toggle
- `InsertMode mode_ = Overwrite`
- Insert mode: typing shifts bytes right, pasting inserts
- Toggle via Insert key or toolbar button
- Visual: caret shape changes (block = overwrite, line = insert)

### 4c. Find & Replace
- Extend HexSearchBar with Replace field
- Replace: replace current match with new bytes
- Replace All: replace all matches
- Supports hex and text patterns

### Files Modified
- `src/gui/HexView.h/.cpp` — mode enum, status updates
- `src/gui/HexSearchBar.h/.cpp` — replace UI
- `src/gui/MainWindow.cpp` — status bar connection

---

## Phase 5: Build Verification
- Run full build: `cmake --build build`
- Run all tests: `ctest --test-dir build`
- Verify 54/54 CTest suites pass
- Verify no regressions in existing hex view behavior

---

## Architecture Notes

### Key Constraint: PatchMemory is Read-Only for setByte()
All byte writes go through `PatchMemory::applyPatch(bytes, addr)` which is the overlay mechanism. The hex view never calls `setByte()` directly (it throws). Instead:
1. HexView accumulates edit → emits signal
2. MainWindow handler calls `patchManager_->addPatch(BytePatch(addr, {newByte}))`
3. PatchManager applies to PatchMemory overlay
4. PatchMemory's `onBytesChanged_` callback triggers view refresh

### Edit Flow
```
User types hex digit
  → HexView::keyPressEvent
  → accumulate nibble
  → if nibble complete:
      emit byteEditRequested(addr, assembledByte)
      → MainWindow lambda:
          auto patch = make_unique<BytePatch>(addr, vector{newByte})
          patchManager_->addPatch(std::move(patch))
          disasmView_->buildFullIndex()  // refresh disasm
          hexView_->viewport()->update() // refresh hex display
```

### Undo Flow
```
User presses Ctrl+Z
  → HexView::undoLastEdit()
  → pop undoStack_
  → patchMemory_->applyPatch({oldValue}, addr)
  → push to redoStack_
  → viewport()->update()
```

### Search Architecture
```
HexSearchBar (QWidget, parent=HexView)
  ├── QLineEdit for pattern
  ├── QComboBox for mode (Hex/Text/Wildcard)
  ├── Buttons: Find Prev, Find Next, Close
  └── Label: "Match 3 of 17"
```

### File Inventory
| File | Action | Purpose |
|------|--------|---------|
| `src/gui/HexView.h` | Modify | Add undo, edit state, search, bookmarks, signals |
| `src/gui/HexView.cpp` | Modify | keyPressEvent, paste, undo/redo, paint editing, search, context menu |
| `src/gui/HexSearchBar.h` | **New** | Search bar widget |
| `src/gui/HexSearchBar.cpp` | **New** | Search bar implementation |
| `src/gui/MainWindow.cpp` | Modify | Connect new HexView signals |
| `src/gui/MainWindow.h` | Modify | Add status bar updates if needed |
| `CMakeLists.txt` | Modify | Add HexSearchBar.cpp |

---

## Risk Assessment
- **Low risk**: All new features are additive — no existing code paths broken
- **Medium risk**: keyPressEvent override must not interfere with FieldView's navigation
- **Mitigation**: Only intercept hex digit keys and Ctrl shortcuts; pass all other keys to FieldView::keyPressEvent

---

## Estimated Effort
- Phase 1: ~300 lines (core editing)
- Phase 2: ~250 lines (navigation)
- Phase 3: ~200 lines (data tools)
- Phase 4: ~150 lines (UI polish)
- Phase 5: ~50 lines (test verification)
- **Total**: ~950 lines across 5-6 files
