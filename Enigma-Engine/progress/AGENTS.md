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
- **Build dir**: `build-cmake/` (MSYS Makefiles)
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

### Navigation Sync (`CutterSeekable`)
- **`src/include/gui/CutterSeekable.h`**: pure virtual interface (`seek`, `currentAddress`, `setSyncState`, `syncState`)
- **HexView**: implements `CutterSeekable`, single-click seeks + highlights current byte, emits `seekRequested`
- **DisassemblyView**: implements `CutterSeekable`, parses address→line map from assembly text, seek scrolls + highlights with `ExtraSelection`, double-click emits `seekRequested`
- **DecompilerView**: implements `CutterSeekable`, parses `// 0xADDR` annotations from Ghidra C output, seek scrolls + highlights
- **MainWindow hub**: `seekAll()` iterates synced views and calls `seek()`; `onAddressSeeked()` handles history + forwards to `seekAll()`; `navigateTo()` and `onNavigateBack()` call `seekAll()` after updating view data

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
| `src/include/gui/CutterSeekable.h` | Navigation sync interface |
| `src/gui/MainWindow.h/.cpp` | Main window, menu, seek hub, dock layout |
| `src/gui/HexView.h/.cpp` | Hex view with seek/click support |
| `src/gui/DisassemblyView.h/.cpp` | Disassembly view with seek/highlight |
| `src/gui/DecompilerView.h/.cpp` | Decompiler view with seek/highlight |
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
