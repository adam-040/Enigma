# Enigma Engine — Plan & Progress

## Goal

Build a production-grade reverse engineering IDE with:
- Polymorphic TypeDatabase system (Windows/Linux/MacOS)
- Qt-Advanced-Docking-System layout
- Bidirectional navigation sync across Disassembly, Decompiler, Hex views
- Full-window divided drop zones for dock widget placement

---

## Build System

- **Platform**: MSYS2/MINGW64, g++ 15.2.0, C++17
- **Build tool**: `make` (`D:/msys64/usr/bin/make.exe`), `cmake` (`D:/msys64/mingw64/bin/cmake.exe`)
- **Build dir**: `build/` (Ninja, Debug config)
- **Test binaries**: `test_binaries/notepad_test.exe`, `test_binaries/shell32_test.dll`
- **Python 3.11**: `C:/Users/pc/AppData/Local/Programs/Python/Python311/python.exe`

---

## Constraints

- Zero regressions on function-detection test suite
- All changes compile under MSYS2/MinGW64 with C++17
- TypeDatabase: abstract base, concrete per platform, table hardcoded in C++
- Qt Widgets primary UI; ADS for layout; QGraphicsView for CFG; QAbstractScrollArea for disassembly long-term
- No QML dependency in core workspace
- No global QSS/Palette; no `ads--` internal class styling
- ADS via FetchContent (static build), not MSYS2 package

---

## Done

### Stress-Test Pipeline & .pdata Fixes
- **All 10 stress files** (kernel32, ntdll, user32, gdi32, advapi32, shell32, ole32, comctl32, ws2_32, mshtml) pipeline-audited with function/instruction counts, timing, peak memory (max 2.2 GB of 7.8 GB)
- **CSV dumps** all verified — counts match audits
- **Ghidra comparison** baseline established (kernel32, ntdll, user32)
- **4 .pdata fixes** in `FunctionStartAnalyzer.cpp` — fixed ordering/splitting oversize .pdata bodies
- **3 genuine missing functions captured** (kernel32 `0x180017448`, ntdll 1, user32 1)

### Noise-Reduction Phase (Phases 4-5)
- **3 noise sources identified and fixed**:
  - `DataSectionFunctionScannerAnalyzer.cpp`: `isAtFunctionBoundary()` accepts only `0xCC`/`0xC3`/`0xE9`/`0xEB` (removed `0x90`/`0x00`); added `isPlausibleFunctionPrologue()` rejecting `0x00`/`0xFF`/`0xCC`; capped Phase 2 .rdata scan
  - `FunctionStartDataPostAnalyzer.cpp`: first-byte validation + boundary check
  - `FunctionStartAnalyzer.cpp`: multi-byte NOP (`0F 1F`) and REX-prefix XOR-zero (`45 33 C0/C9/D2/DB`) rejection in pattern/trigger matching
- `AggressiveRecoveryAnalyzer.cpp` inspected — `.pdata` scoring is a hint-only constant, no action needed

### Noise-Reduction Results
| Binary | Before (extras) | After (extras) | func_data before | func_data after |
|--------|----------------|----------------|-----------------|----------------|
| kernel32 | ~993 | **495** | ~504 | **3 (0.6%)** |
| user32 | ~725 | **697** | ~5 | **5 (0.7%)** |
| ntdll | ~2,143 | **1,614** | ~493 | **22 (1.4%)** |

- Remaining extras dominated by `func_pdata` (legitimate .pdata entries Ghidra doesn't split)
- Phase 4 sampling validated 72% of extras are genuine functions with Capstone vs Ghidra cross-reference

### Tooling Created
- `tools/classify_extras.py`, `tools/investigate_missing.py`, `tools/compare_function_lists.py`, `tools/check_pdata.py`
- `tools/phase4_sampling.py`, `tools/phase5_funcstart.py`, `tools/phase5c_preceding.py`
- `test_binaries/phase4_report.html`, `test_binaries/phase4_summary.md`

### TypeDatabase Infrastructure
- `TypeDatabase.h` (abstract base), `WindowsTypeDatabase.cpp` (~376 + `#include wintype_siggen.inc`), `LinuxTypeDatabase`/`MacOSTypeDatabase` stubs
- `TypeDatabaseFactory.cpp` with `detectPlatform()` + `createTypeDatabaseForPlatform()`
- Bridge integration in `DecompInterface::Impl` and `AnalysisBridge`

### Table Expansion
- `tools/gen_signatures.py` expanded from 950 → 1487 entries across 20+ DLL sections
- Call-site annotation hook `applyTypeDatabaseToCallSpecs()` in `enigma_decompile_full.cpp`
- Bridge stats: notepad 53 types applied, shell32 298 types applied (was 0)

### Regression Tests
- All 3050/3054 pass (same 4 pre-existing failures)
- No new regressions

### Project Cleanup
- Removed `tmp/` (~60 MB), `root build/` (empty), `duplicate include/` (1.8 MB), nested `include/` dirs, `builds/` (1.28 GB stale artifacts), temp files, logs, CSV snapshots, `.bak` backups

### ADS Dock Layout
- `ads::CDockManager` replaces QDockWidget/QSplitter/QTabWidget
- Explorer → Left (NoDockWidgetFeatures), Disassembly → Center, Decompiler → Right (tab 1), Hex → Right (tab 2), Console → Bottom
- FetchContent fetches `Qt-Advanced-Docking-System` v4.5.0, static build, linked as `ads::qtadvanceddocking-qt6`
- Removed centralTabs_ reference in `onNavigateBack()`

### Drop Zone UX
- `CDockOverlayCross::cursorLocation()` rewritten to use **full-window proportional division**:
  - Left 25% → LeftDock
  - Right 25% → RightDock
  - Top 25% → TopDock
  - Bottom 25% → BottomDock
  - Center → CenterDock (tab)
- Compass arrows hidden via `qproperty-iconColors` (all channels = `#00000000`)
- Drag threshold increased from 1.5× → 4× `QApplication::startDragDistance()` (~40px before undock)
- QSS: 1px splitters, no borders, thin dock area

### View Menu Toggles
- Disassembly/Decompiler/Hex QActions: checkable, connected to `toggleView()`/`setDockWidgetFocused()`
- `viewToggled` signal keeps menu check state in sync when closing via X button

### Console
- Title bar hidden via `CDockAreaWidget::setDockAreaFlag(HideSingleWidgetTitleBar)`

### Explorer Tree View
- A-Z sorting enabled by default (Name column, ascending)
- Address column: monospace Consolas 9pt, right-aligned
- Category headers bold
- Tooltips on every entry
- Filter box with clear button

### Navigation Sync (`NavigationCoordinator`)
- **`src/gui/NavigationCoordinator.{h,cpp}`**: single mediator for cross-view navigation. `registerView(QWidget*, int skipBit, Applier)` / `unregisterView(QWidget*)` / `isRegistered(QWidget*)`; `navigate(const NavigationEvent&, int skipMask = 0)` broadcasts to every registered view except `originView` and any view whose `skipBit & skipMask`; stores `lastEvent()` and emits `navigated`. Registration is idempotent (re-registering replaces the applier).
- **`src/gui/NavigationEvent.h`**: `TokenKind` enum + `NavigationEvent { address (exact byte), endAddress, tokenText, tokenKind, originView, valid }`.
- **View contract** (FieldView, DisassemblyFieldView, HexView, DecompilerView via FieldView): the originating view sets its own local state first (e.g. in `mouseReleaseEvent`/`keyPressEvent`), then calls `navigateAll(endAddr?, tokenText?, kind)` to broadcast with `originView = this`. Each view implements `applyNavigationEvent(ev)` landing on the exact address it can represent:
  - **HexView**: byte-exact — `lineForAddress(addr)` + `byteIndex = addr - line.addr` + 2-char selection at the exact byte column.
  - **DisassemblyFieldView**: instruction-exact — `rowForAddress(addr)` (binary search on model, FunctionHeader walk) + token match via `rowTokens`.
  - **DecompilerView**: statement-exact — decompiler `Line.addr = statementAddr`, token `.addr` from opAddresses; nearest-line landing, `currentAddr_ = ev.address`.
- **MainWindow hub**: owns `navCoord_`, registers disasm (`NavSkip_Disasm`=1), decomp (`NavSkip_Decompile`=2), hex (`NavSkip_Hex`=4); `onNavigationEvent` updates the status/info labels only (no re-broadcast). `doNavigate()` STEP8 does the single `navCoord_->navigate(ev, navSkipFlags_)` broadcast. `NAV_SKIP` env still honored via `navSkipFlags_`.
- **Removed**: `CutterSeekable` (interface + setSyncState/syncState), `SelectionManager`, `SelectionState`, `cursorAddressChanged` signal, `cursorSyncTimer_`/pending-sync coalescing, `seekToAddress` (use `seek`), direct `disasmView_->seek()`/`hexView_->seek()` calls from MainWindow (now coordinator events). Local `seek()` remains a non-broadcasting local scroll (HexSearchBar, bookmarks).
- **All navigation entry points are on the same sync wave**: view clicks/double-clicks/keyboard, minimap (`navigateRequested`), string table, patch list, function explorer (`functionSelected` → `navigateTo`), hex search matches (`HexSearchBar::navigateRequested`), bookmarks (`seekRequested` → `navigateTo`), patch/undo/redo/assemble rebuilds, `navigateTo`/back/forward. `HexSearchBar` keeps its local `hexView_->seek(addr)` for immediate hex caret positioning, then emits `navigateRequested` so the whole wave follows.
- **Adding a new view** (future work): subclass `FieldView` (or implement `applyNavigationEvent` for a non-QWidget seat) and call `setNavigationCoordinator(nav, skipBit)` once — it is automatically on the same sync wave via the mediator. Never wire per-view `seek()` chains in MainWindow; broadcast through the coordinator instead.

### Other ADS Source Changes (build tree)
- `DockOverlay.cpp:880` — `CDockOverlayCross::cursorLocation()` → full-window proportional drop zones
- `DockManager.cpp:1265` — `startDragDistance()` multiplier 1.5 → 4

---

## In Progress
- (none)

## Blocked / Deferred
- Custom Hex view (QAbstractScrollArea) — done, but could be enhanced further
- Custom Disassembly view (QAbstractScrollArea) — deferred
- Custom Decompiler view (replace QScintilla) — deferred
- Dock locking (global lock/unlock) — deferred
- Dark theme / palette — deferred

---

## Next Steps

1. **Persistent layout save/restore** — `CDockManager::saveState()`/`restoreState()`
2. **Address-range scrollbar** in DisassemblyView
3. **Dock locking** — global lock/unlock per dock widget
4. **Custom disassembly rendering** — QAbstractScrollArea replacement
5. **Custom decompiler highlighting** — replace QScintilla
6. **CFG view** — QGraphicsView integration

---

## Relevant Files

| Path | Purpose |
|---|---|
| `src/gui/NavigationCoordinator.h/.cpp` | Navigation mediator (register/navigate/skip-mask) |
| `src/gui/NavigationEvent.h` | `TokenKind` + exact-address `NavigationEvent` |
| `src/gui/MainWindow.h/.cpp` | Main window, menu, coordinator hub, dock layout |
| `src/gui/HexView.h/.cpp` | Hex view with byte-exact navigation |
| `src/gui/DisassemblyFieldView.h/.cpp` | Disassembly view with instruction-exact navigation |
| `src/gui/FieldView.h/.cpp` | Base view (shared landing, DecompilerView inherits) |
| `src/gui/DecompilerView.h/.cpp` | Decompiler view with statement-exact navigation |
| `src/gui/FunctionExplorer.h/.cpp` | Explorer tree view |
| `src/gui/ConsoleWidget.h/.cpp` | Console widget |
| `src/include/ghidra/CutterSeekable.h` | *(same as gui/...)* |
| `src/core/WindowsTypeDatabase.cpp` | Windows type DB (~376 + `wintype_siggen.inc`) |
| `src/core/wintype_siggen.inc` | Auto-generated 1487-entry sig table |
| `src/core/TypeDatabaseFactory.cpp` | Platform detection + factory |
| `tools/gen_signatures.py` | Signature generator |
| `tools/enigma_decompile_full.cpp` | Call-site type annotation hook |
| `CMakeLists.txt` | Build config, ADS FetchContent |
| `build-cmake/_deps/qtadvanceddocking-build/` | ADS build tree (patched source) |
| `build-cmake/_deps/qtadvanceddocking-src/src/DockOverlay.cpp` | Patched cursorLocation (full-window zones) |
| `build-cmake/_deps/qtadvanceddocking-src/src/DockManager.cpp` | Patched startDragDistance (4× multiplier) |
