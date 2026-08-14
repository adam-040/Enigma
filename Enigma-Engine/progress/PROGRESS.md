# Enigma Engine Progress

Single-line-per-event changelog of significant changes.

## 2026-08-14 — CFA Gutter: Randomly Cut Arrowheads (separator order + landing buffer)

- **Root cause**: (a) the 1px margin separator (`fillRect(cfaMarginPx_,0,1,·)`) was painted AFTER the gutter, so it overwrote the apex column of every arrowhead whose tip lands at the text boundary — heads looked chopped; (b) landings on the viewport's first/last rows land at `y = ±9..10px` depending on scroll alignment, so their triangles were half-clipped or fully hidden — the "randomly cut / missing" heads while scrolling
- **Fixes**: separator is now painted BEFORE the CFG gutter pass (its hairline role is preserved; arrowheads end flush at x47 with the hairline intact at x48 — 1px-of-clean separation, verified at single-pixel resolution); draw-list eligibility excludes landing rows at the window edges (`toRow <= firstRow || toRow >= lastRow-1`) so triangles are never bisected by the viewport boundary
- **Verification**: offscreen harness fine-strip dump (x38..56, y step 1) shows each landing's triangle as exactly `#`/`~` slivers from base (x41) to apex column x47, with the entry line solid into the head and the separator column untouched; NO triangles protrude past the viewport top/bottom
- 69/69 CFG assertions, 55/55 CTest, GUI relaunched on `pass.exe`

## 2026-08-14 — CFA Gutter: Fix Floating Arrowheads + Missing Arrows (pixel-verified)

- **Root cause 1 (floating heads)**: conditional routes were drawn entirely dashed; the final dash run ends mid-air, leaving the filled triangle detached from the line. Pass B now dashes only the horizontal exit + vertical traversal; the **final horizontal entry approach is SOLID** (`QPainterPath` trunk + solid pen), so every arrowhead connects flush to its line — no floating tips
- **Root cause 2 (missing arrows)**: draw-list eligibility demanded both endpoints inside the *center* function's scope; scrolling so `main` (0x1400014b0) was on screen produced a completely empty gutter (the window center fell in a 32-byte neighbour function) and inbound/cross-function landings never rendered. `rebuildCfaDrawList` eligibility is now **destination-row visible in the viewport** (`toAddr ∈ [viewTop, viewBot]`) with per-window span-priority coloring: every visible landing gets its arrow, including inbound jumps clipped at the window top, while long jumps that merely cross the window (off-screen destination) no longer draw — anti-spaghetti preserved
- **Verification**: offscreen render harness (`%TEMP%\opencode\enigma\shots.exe`) renders the view on `pass.exe` and dumps the real gutter pixels as ASCII art. Before/after: `main` window empty → landings at rows 246/262 present; w01 dense dash-only patterns → solid entries with full 7px triangles (`#######`); w03's long crossing vertical replaced by 4 well-spaced lanes. Temp `CFA_DEBUG` dump added/removed
- 69/69 CFG assertions, 55/55 CTest, GUI rebuilt + relaunched on `pass.exe`

## 2026-08-14 — CFA Gutter: Bounding-Box Safety, Integer Pixel Alignment, Clean Arrowheads

- **Clip safety margin**: `paintEvent` now checks whether the frame's exposed region fully contains the CFG margin strip `[0, cfaMarginPx_ + kCfaSafetyPad]`; if any sliver of it is outside the update region it is re-queued (`viewport()->update(strip)`), so the exposed-region clip can never slice the outer edge of a thick line, the separator, or an arrowhead tip that straddles a partial-update boundary
- **Integer pixel alignment**: `cfaRoute` y-centers now go through `qRound(row*cellH - scrollY + cellH/2.0)`; every route vertex is a clean integer pixel — no sub-pixel lines, no 1px clipping artifacts
- **Clean arrowhead coordinates**: triangle replaced with an integer `QPolygon` (was `QPolygonF` with half-pixel vertices) — `kCfaHeadW` made even (7→6) so `y ± headW/2` is integer; apex stays exactly at `route.back()` (the end of the horizontal entry), base square behind it along the entry, so the head attaches flush with zero overlap and nothing renders partially hidden
- `kCfaSafetyPad = 4` constant added; GUI rebuilt, relaunched on `pass.exe`; CFG tests still 69/69

## 2026-08-14 — CFA Gutter: Track Lifetime & Recycling (Function-Scope Interval Coloring)

- **Interval graph coloring with recycling**: `assignTracks` now implements full interval lifetime semantics — each track's occupant is tracked by its vertical span `[minRow,maxRow]` and a column is reused the instant a previous occupant terminates (`lastEnd < start`), so non-conflicting jumps share columns inside one function. Also fixed a latent cap bug: the outermost track's occupancy was never consulted (`t < kCFAMaxTracks-1`), allowing overlap on lane 3; the sweep now checks all `kCFAMaxTracks` and clamps to the outermost lane only for genuine 4+ concurrency
- **Spanning priority & grouping**: processing order changed from start-row priority to **shorter-span-first** ordering (tie-break: start, end, fromRow, toAddr — still fully deterministic/order-independent). Short jumps hug the text boundary on inner lanes 0/1; long-spanning jumps are pushed further left to outer tracks, and mutually-exclusive long jumps share those outer columns
- **Function-scope lane stability**: the renderer no longer re-colors the per-window subset on every scroll. `rebuildCfaDrawList` now allocates lanes ONCE per visible-function range over *all* intra-function jumps (`scopeLanes_` map, keyed by `scopeLanesStart_/End_`), then the per-window draw list only *culls* against the viewport — columns stay rock-stable while scrolling and recycle function-wide, shrinking the parallel-track count in the margin
- **Breathing room**: with recycling + span priority, typical functions render 1–3 widely separated columns (42/32/22 lanes, 10px pitch) instead of dense stacks; cleared in `buildCFG` alongside the stale selection
- Tests: `test_disasm_cfg.cpp` — "earlier-starting keeps inner lane" superseded by "shorter-spanning edge keeps inner lane"; new block asserts two mutually-exclusive short jumps share lane 0 while a long jump overlapping both sits on lane 1 → **69/69**; CTest **55/55**; GUI relaunched on `pass.exe`

## 2026-08-14 — CFA Gutter: Strict Sharp Orthogonal, Solid Black, Redesigned Arrowheads

- **Pure 90° routing restored**: `cfaRoute` is back to 4 points — horizontal exit, vertical traversal, horizontal entry; the chamfered diagonal pilot was dropped. All corners meet with `Qt::MiterJoin` (route pens set `FlatCap` + `MiterJoin`, cosmetic device-pixel width for crispness); no curves, rounding, or smoothing anywhere
- **Generous track spacing**: `kCfaLaneInset` 40→42, `kCfaNestStep` 8→10 — lanes now sit 10px apart (42/32/22/12) so overlapping vertical runs keep a clear, distinct gap and never visually merge within the 48px isolated margin
- **Solid black styling**: `EditorTheme::cfaColor` tints dropped from the gutter entirely — all routing lines, arrowheads, return stop-tabs (now square, not rounded) and computed-`?` stubs render in solid `Qt::black` (opaque); conditional edges keep their dash pattern for legibility
- **Arrowhead redesign**: clean isosceles triangle, `kCfaHeadLen/W` 6→7, apex placed exactly at `route.back()` — the end of the horizontal entry segment — square base behind it along the entry, so head and line connect flush with zero clutter; selected-head state still traced dynamically
- **Interactivity preserved**: single-click `selectEdge` still highlights the active jump in distinct neon green (thicker pen, round-free sharp style); double-click still runs the 260ms `OutCubic` scroll animation centered on the destination
- Builds clean; GUI relaunched on `pass.exe` (engine untouched — CFG 66/66 and CTest 55/55 still green from prior run)

## 2026-08-14 — CFA Gutter: Polish (AA + Chamfered Arrowhead) & Interaction (Hit/Select/Animated Nav)

- **Anti-aliasing**: `paintEvent` enables `QPainter::Antialiasing` up front so edge lines and arrowheads render crisp instead of jagged
- **Chamfered entry**: `cfaRoute` is now a 5-point path — orthogonal V-traversal is preserved, but the vertical run stops `kCfaChamfer`(5px) shy of the target and a short diagonal slope leads the final horizontal segment into the row, so the filled triangle arrowhead (`route.back()`) appears to float off the angled tip rather than gluing flat to the instruction
- **`QPainterPathStroker` hit-test**: `edgeAt` now strokes each drawn route with a wide (~8px) round-cap stroke and tests `stroke.contains(pos)`, backing it with a closest-segment tie-break — users no longer need to click a hairline route; still confined to the CFG margin
- **Single-click selection**: gutter `mousePressEvent` now *selects* rather than instantly jumps — `selectEdge(edge)` stores `selectedEdge_` (a `cfg->edges()` pointer, cleared in `buildCFG`) and repaints that jump in glowing neon green (`0x00ff9f`, opaque, +1px width, round caps, solid even if conditional) while all other tracks stay muted
- **Animated double-click**: `mouseDoubleClickEvent` gutter branch drives `QPropertyAnimation` on the vertical scrollbar value (260ms, `OutCubic`) to smoothly center the destination row; on finish `finishNavTo` lands `currentRow_/currentAddr_` and emits `cursorAddressChanged(destAddr)` (no `seekRequested` re-broadcast, so the coordinator's synchronous re-navigate can't interrupt the glide). Stale slides are disconnected/dropped via a `scrollAnim_ == anim` guard
- Builds clean; `enigma_test_disasm_cfg` 66/66, CTest 55/55; GUI relaunched on `pass.exe`

## 2026-08-14 — CFA Gutter: Scope Filtering + Viewport Culling (anti-spaghetti)

- **Pipeline architecture** in `DisassemblyFieldView`: rendering now runs *scope filter → viewport cull → dynamic track sweep*, producing a per-window draw list (`CfaDrawItem{edge*, lane}`) cached against `[window first/last row]` and rebuilt only when either changes (`ensureCfaDrawList`/`rebuildCfaDrawList`). `paintEvent`, `paintCfaGutter` and `edgeAt` all operate on this cache, so off-screen/out-of-function lines are never even computed
- **Intra-function scoping**: `funcRangeFor(addr)` derives the visible function's `[start,end]` from the sorted function-entry addresses collected in `buildCFG` (unbounded when none known); the scope anchor is the viewport-center row. An edge is drawn only when BOTH `fromAddr` and `toAddr` fall in that range
- **External-branch rejection**: `Return`, `Call`, `ComputedCall` and `Computed` edges never render as tracks; calls are dropped entirely, returns keep a scoped local stop-tab, and unresolved in-function computed jumps a short dashed `?` stub — none produce a long crossing line
- **Viewport intersection (culling)**: the visible vertical address range `[rowToAddress(first), rowToAddress(last)]` rejects edges entirely above/below the window before routing
- **Dynamic track reallocation**: the per-frame sweep is now a shared, order-independent engine helper `cfg::assignTracks(const std::vector<const CfaEdge*>&)` (public in `cfg/DisassemblyCFG.h`, `kCFAMaxTracks=4`); `build` Pass 3 was refactored to call it for build-time lane metadata, and the renderer calls it on the *filtered subset only* — so fewer live edges compete for tracks, letting the margin slim 64→48px
- Tests: `test_disasm_cfg.cpp` + assignTracks order-independence (per-edge-pointer) — 66/66 assertions; 55/55 CTest suites pass, `enigma_gui` builds clean

## 2026-08-14 — CFA Gutter: Wide Isolated Margin + Bolder Arrows

- **Strictly isolated, wider CFG margin**: `kCfaMarginDefault` 38→64px (runtime `setCfaMargin` clamp now `[56, 240]`); `kCfaLaneInset` 28→52, `kCfaNestStep` 6→8 → track columns 52/44/36/28 with wide breathing room
- **Background isolation**: block tints, block separators and the caret-line highlight are all clamped to start at the margin edge (`paintBlockBackdrop` and the caret-line fill now use `cfaMarginPx_`), so the margin stays a pure untouched background; nothing bleeds into it
- **Subtle separator**: a single extremely faint 1px vertical line (`0xdce1e8`) at the margin edge drawn *last* in `paintEvent`, guaranteeing no tint/highlight/line ever covers it — a clean visual border between margin and text
- **Bolder arrows**: `kCfaLineWidth` 1→2px (all pens: routes, return stub, unresolved dash) while keeping the muted translucent palette (`kCfaAlpha=165`); hit tolerance 5→6px
- Preserved as designed: dynamic global track sweep (no overlap), orthogonal 3-segment routing, solid/dashed distinction, triangle arrowheads into destinations
- Verified: 55/55 CTest suites pass, `enigma_gui` builds clean

## 2026-08-14 — CFA Gutter: Dedicated Margin + Dynamic Track Assignment

- **Dedicated adjustable margin**: the left margin (`kCfaMarginDefault=38`, runtime-adjustable via new `DisassemblyFieldView::setCfaMargin(int)`, clamped to `[kCfaMinMargin, 160]`) is reserved solely for CFG graphics — the disassembly text always offsets past it (`cfaMarginPx_ + leftPadding`), and the patch marker moved out of the arrow space to the margin/text boundary; all gutter-derived code (caret column, hit-test, tooltips, gutter click) uses the live margin
- **Dynamic track-assignment (overlap prevention)**: `DisassemblyCFG::build` Pass 3 rewritten from a per-block static lane sort into a global greedy sweep — edges are ordered by (span start, span end, source row, target address) and each gets the lowest track whose previous occupant has ended; edges whose vertical spans overlap can never share a track, even across *different* blocks (the per-block scheme could collide), disjoint edges reuse the innermost track (hug the text), past the 4-track cap the outermost track is shared
- **Orthogonal flow + directional clarity**: unchanged 3-segment `QPainterPath` routes (horizontal exit → vertical traversal → horizontal entry), horizontal segments cleanly bridge text boundary (`cfaMarginPx_`) to the track columns (`laneX = kCfaLaneInset - lane*kCfaNestStep` → 28/22/16/10), triangle arrowheads enlarged 5→6px for visibility
- **Visual distinction**: 1px solid unconditional/call vs `Qt::DashLine` conditional, translucent muted palette (steel blue/gray-blue/violet/red at `kCfaAlpha=165`) retained
- Tests: `test_disasm_cfg.cpp` + section 13 (overlapping spans → distinct lanes, earlier-starting edge inner, track cap, disjoint spans reuse lane 0) — 64/64 assertions; 55/55 CTest suites pass, `enigma_gui` builds clean

## 2026-08-14 — CFA Gutter: Ghidra-Style Orthogonal Arrows

- Replaced the sharp-angled "hydra" routes with exact Ghidra-style rendering: each edge is an orthogonal 3-segment `QPainterPath` (horizontal exit from the source row at the text boundary → vertical traversal → horizontal entry back to the text boundary at the target row), with a small solid `QPolygonF` triangle arrowhead at the tip of the entry segment pointing into the destination
- 1px `FlatCap` pens: solid for unconditional/call edges, `Qt::DashLine` for conditional; colors muted + semi-transparent (`kCfaAlpha=165`) light blue/gray family (`EditorTheme::cfaColor`: steel blue / gray-blue / violet / muted red); gutter slimmed 60→34px
- Nesting-level algorithm: CFG builder assigns per-block lanes 0..3 ordered by target row (lane 0 = shallowest/nearest); `laneX(lane) = kCfaLaneInset - lane * kCfaNestStep` shifts the traversal column 6px left per nesting level (26/20/14/8), so overlapping edges never share an X; `static_assert` keeps lane 3 clear of the patch-marker strip
- Return edges: short stub + filled rounded stop tab; unresolved (computed) edges: dashed stub + bold `?`; `edgeAt` hit-testing unchanged over the new orthogonal polylines (gutter click → jump, hover → tooltip intact)
- Verified: 55/55 CTest suites pass, `enigma_gui` builds clean

## 2026-08-14 — CFA Gutter: Configurable Geometry + Larger Arrows

- All arrow geometry centralized in one tunable constexpr block in `DisassemblyFieldView.h` (gutter 18→34px, `kCfaLaneInset=5`/`kCfaLaneStep=6` breathing room between lanes, `kCfaLineWidth=3`, `kCfaHeadW=7`/`kCfaHeadH=4` arrowhead, `kCfaTickLen=5` source tick, `kCfaStopW=3` return stop, `kCfaHitX=5`/`kCfaHitY=3` hit-test) with a `static_assert` that the widest lane + head fits inside the gutter
- Gutter painter upgraded: 3px round-cap stems, larger filled arrowheads, filled rounded return-stop tab (was a 1px line tick), bold `?` for unresolved edges; `laneX(lane)` now derives purely from the config block
- Clarity: edge colors deepened/vivid (blue `0x1f5fc8`, teal `0x0a8f8f`, purple `0x943cd9`, red `0xc82f23`), block separator `0xd0d6e0`→`0xb8c2d0`, odd-block tint `0xecf1f7`→`0xe9f0f8`
- Verified: 55/55 CTest suites pass, `enigma_gui` builds clean

## 2026-08-14 — Disassembly CFG (Control-Flow Arrows + Basic Blocks)

- New engine-side CFG model `src/cfg/DisassemblyCFG.cpp` + `src/include/cfg/DisassemblyCFG.h` (pure engine type, no Qt): `CfgInsn`, `EdgeKind{Unconditional,Conditional,Call,Return,Computed,ComputedCall}`, `CfaEdge{fromAddr,toAddr,fromRow,toRow,kind,lane}`, `CfgBlock{startAddr,endAddr,firstRow,lastRow,index,outEdges}`, `DisassemblyCFG::build(insns, functionEntries)` with leader-based segmentation, `parseDirectTarget` (rejects `[qword ptr ...]`/registers/`0x0`), ≤4 lane assignment (call below jcc), `blockAtRow()`
- `tests/test_disasm_cfg.cpp` (12 sections: parse, classification, diamond, loop back-edge, cross-function call, computed, nested ifs, function-entry split, out-of-list target, empty input, lanes, edgeKindName) — 59/59 assertions, registered in `CMakeLists.txt` as `enigma_test_disasm_cfg`
- GUI integration in `DisassemblyFieldView.{h,cpp}`: `buildCFG()` from the decoded-instruction view cache; `paintBlockBackdrop` (subtle parity tints + thin separator lines) and `paintCfaGutter` (vertical line + source tick + arrowhead per lane) drawn after first/last-row computation; gutter width 12→18
- Clickable/hoverable edges: `edgeAt` (nearest-span ±3px x / ±2px y), gutter click → `jumpToAddress(e->toAddr)` via `seek()` + `emit seekRequested(...)` + SelectionState; hover → PointingHandCursor + tooltip `<kind>: 0xfrom -> 0xto`; dashed unresolved edges with '?' for computed/indirect targets
- `EditorTheme.{h,cpp}`: `cfaColor(EdgeKind)` (unconditional blue / conditional teal / call green / return red), `blockTint(parity)`, `blockSeparatorColor()`; CALL-green token color re-added
- `SelectionState.h`: `TokenKind::Call` re-added
- **Build fix**: `src/symbol/Listing.cpp` was a legacy duplicate of `src/listing/Listing.cpp` — both compiled into `libenigma_engine.a` as the same member name `Listing.cpp.obj`, causing `multiple definition of ghidra::Listing::*` at link for tests pulling both members. Deleted `src/symbol/Listing.cpp` (the `src/listing/` impl is canonical: matches `Listing.h` `perfCounters_` member, `getMinAddress()`, null-guards)
- Verified: 55/55 CTest suites pass (incl. `enigma_test_disasm_cfg` 59/59 + previously-unbuilt `enigma_test_decomp_interface`), `ninja` builds all 74 targets clean

## 2026-08-14 — GUI Decompiler Type Bridge (Alpha 0.2.0)

- `DecompInterface::openProgram` runs the full `AnalysisBridge` pipeline in try/catch — `bridgeFunctions`, `bridgeTypes`, `bridgeImportSignatures`, `bridgeNoReturnFlags`, `bridgeLabels`, `bridgeReadOnlyRanges` — with platform TypeDatabase chosen from `getExecutableFormat()` (PE→Windows, ELF→Linux, Mach-O/FAT/PEF→MacOS); GUI decompiler now matches CLI behavior
- `AnalysisBridge::resolveTypeName`: new string-pointer branch maps `const char*`/`char*`/`LPCSTR`/`LPSTR`/`PCSTR`/`PSTR`/`LPCCH`/`LPCH` → `char*` and `wchar_t*`/`LPCWSTR`/`LPWSTR`/`PCWSTR`/`PWSTR`/`LPCWCH`/`LPWCH` → `wchar16*` via cached core types (`findByName`, 1/2-byte INT fallback)
- Variadic imports: virtual `TypeDatabase::isVariadic()` (default false) + `getVariadicTable()` in WindowsTypeDatabase (printf/scanf/sprintf/snprintf/fprintf + `_s`/wide/`v`-variants); `bridgeImportSignatures` sets `firstVarArgSlot = paramTypes.size()` → prototypes render `char *param_1,...`
- `MainWindow::onAnalysisFinished` re-bridges decompiler post-analysis: `decompCache_.clear()` + `decompInterface_->refreshFunctionSymbols()` in try/catch
- Verified on pass.exe (before/after harness): `main(char *param_1, char *param_2)`, `__mingw_printf(param_1)`, `__mingw_scanf(param_1)`, `strcmp(param_1, param_2)` — was `__mingw_printf()` 0 args / 4-arg `strcmp`; CLI output matches
- Drawbacks/footnotes: none — 54/54 CTest suites pass, GUI + CLI build clean

## 2026-08-14 — SVG Icon High-DPI Rendering

- `MainWindow::loadSvgIcon` renders SVG vectors directly at device-pixel resolution: pixmap sized `size × devicePixelRatioF()` tagged with the DPR → Qt blits 1:1, zero rasterization/scaling artifacts (removed 2x-supersample + `smooth` downscale that blurred on high-DPI)
- Icon design, size (16 px), position, spacing, layout unchanged; offscreen DPR-2 harness: +18% avg edge sharpness across 5 toolbar icons; PNG pairs in `%TEMP%\opencode\iconcheck\`
- Added missing `src/gui/icons/app_icon.png` placeholder (referenced by `resources.qrc`, was breaking the `enigma_gui` build)

## 2026-07-07 — Pretty-Printing Overhaul (2nd pass)

- **Space before `(`**: `function_call` token `spacing` 0→1 → `func(...)` → `func (...)`
- **Function pointer calls**: `opCallind()` checks if callee (constant/COPY/CAST) resolves to a known function symbol → emits `func_0xADDR()` instead of `(*cast)ptr_0xADDR()`
- **Blank lines between blocks**: `emitBlockGraph()` adds `tagLine()` between consecutive top-level blocks
- **Condition wrapping**: `emitBlockCondition()` adds `spaces(0,4)` break opportunities after `(`, before `&&`/`||`, and before `)` in `if`/`while` conditions
- **Parameter list wrapping**: `emitPrototypeInputs()` adds `spaces(1,8)` break after commas in function signatures
- `prettyprint.hh`: `indentincrement` 2→4 (4-space indent); `maxlinesize` 100→90 (tighter wrapping)
- `printc.cc`: all logical, comparison, bitwise, and arithmetic operators got `bump=4` for continuation indent on line wrap
- All 52/52 tests pass

## 2026-07-07 — Syntax Highlighting Improvements

- **Operator color**: `printlanguage.cc:emitOp` — all binary and unary_prefix operators changed from `no_color` to `special_color`
- **Field/bitfield color**: `printc.cc` — all `fieldtoken` tokens changed from `no_color` to `var_color` (6 field, 6 bitfield)
- **CppHighlighter**: added decompiler-specific patterns:
  - Calling conventions (`__stdcall`, etc.) → keyword blue
  - Decompiler types (`int4`, `uint4`, `float8`, `code`, etc.) → teal bold
  - Function refs (`func_0x...`, `thunk_0x...`, `code_0x...`) → yellow
  - Data/variable refs (`local_0x...`, `ptr_0x...`, `data_0x...`, etc.) → light blue
  - Parameters (`param_1`, ...) → orange
  - Register args (`arg_eax`, `out_rcx`, ...) → purple
  - Temp variables (`v_0`, `v_1`, ...) → light blue
- All tests pass

## 2026-07-07 — Automatic Naming Convention Overhaul

- `AutoNaming.h` created — central `name(prefix, addr)` / `nameVal(prefix, val)` formatter
- `SymbolUtilities.{h,cpp}`: prefixes updated — `FUN_`→`func_`, `DAT_`→`data_`, `LAB_`→`label_`, `SUB_`→`func_`, `UNK_`→`unk_`, `EXT_`→`ext_`, `OFF_`→`off_`, `Ordinal_`→`ord_`
- `FunctionManager.cpp`, `DecompInterface.cpp`: `FUN_` → `func_`, `FUN_ENTRY` → `entry`
- 12 discovery/analyzer files: all `sub_`, `func_start_`, `func_call_`, `func_gap_`, `func_data_`, `func_sweep_`, `thunk_`, `data_func_`, `exception_func_` unified to `func_0xADDR` / `thunk_0xADDR`
- `database.cc::buildVariableName`: 7 naming paths rewritten — `unaff_0x`, `local_0x`, `ptr_0x`, `arg_`, `param_`, `out_`, `v_`
- `varmap.cc::ScopeLocal::buildVariableName`: `auStack_`/`uStack_` → `local_0x`
- `printc.cc` (4 functions): `RAM0x...`→`ptr_0x...`, `code_r0x...`→`code_0x...`, `Ram0x...`→`ptr_0x...`, `function_`→`func_`
- `enigma_decompile_full.cpp`: removed `FUN_ENTRY`→`entry` post-processing
- `AnalysisBridge.cpp`, `FidAnalyzer.cpp`, `MainRecognitionAnalyzer.cpp`: prefix checks updated
- `tests/test_compile.cpp`: 14 W74.SymUtil prefix expectations updated
- `tests/test_batch_x.cpp`: `"FUN_"` → `"func_0x"`
- `tests/test_cli_regression.py`: 9 regex patterns updated
- `tests/corpus/expected/*.c`: all 16 regenerated — output sizes dropped ~10%
- All 52/52 tests pass (100%)

## 2026-07-?? — Noise-Reduction Phase

- `DataSectionFunctionScannerAnalyzer.cpp`: `isAtFunctionBoundary()` accepts only `0xCC`/`0xC3`/`0xE9`/`0xEB`; `isPlausibleFunctionPrologue()` rejects `0x00`/`0xFF`/`0xCC`; Phase 2 .rdata scan capped at `MAX_FOUND`
- `FunctionStartDataPostAnalyzer.cpp`: first-byte + boundary validation for data-ref functions
- `FunctionStartAnalyzer.cpp`: multi-byte NOP (`0F 1F`) and REX-prefix XOR-zero (`45 33 C0/C9/D2/DB`) rejection
- Results: kernel32 extras 993→495, ntdll 2143→1614, user32 725→697; `func_data` extras ≤1.4% of all extras
- `AggressiveRecoveryAnalyzer.cpp` inspected — .pdata scoring is hint-only, no action needed

## Earlier

- Stress-test pipeline: all 10 system DLLs audited (function/instruction counts, timing, peak memory)
- 4 .pdata ordering/splitting fixes in `FunctionStartAnalyzer.cpp`
- Ghidra comparison baseline established for kernel32, ntdll, user32
- Tooling: `classify_extras.py`, `investigate_missing.py`, `compare_function_lists.py`, `check_pdata.py`, `phase4_sampling.py`, `phase5_funcstart.py`, `phase5c_preceding.py`
- TypeDatabase: abstract base + WindowsTypeDatabase (~3200 signatures across 20+ DLL sections) + Linux/MacOS stubs + factory
- Call-site type annotation in `enigma_decompile_full.cpp` (notepad 53 types, shell32 298 types)
- Project cleanup: removed `tmp/`, `root build/`, `duplicate include/`, `builds/` (1.28 GB), temp files, logs, CSVs, `.bak` backups
- ADS dock layout: Explorer/Disassembly/Decompiler/Hex/Console; FetchContent + static build
- Full-window proportional drop zones (25% per edge, center tabs); compass arrows hidden; drag threshold 4×
- View menu toggles for Disassembly/Decompiler/Hex with sync on close
- Console: title bar hidden via `HideSingleWidgetTitleBar`
- Explorer tree: A-Z sort, address column monospace, tooltips, filter box
- `NavigationCoordinator` unified sync: single mediator (`registerView`/`navigate` with `skipMask`), exact-byte `NavigationEvent`, origin-guarded; Hex byte-exact / Disassembly instruction-exact / Decompiler statement-exact landing
- `seekAll()` hub replaced by coordinator STEP8 broadcast in `doNavigate`; `onNavigationEvent` updates status labels only; `NAV_SKIP` env isolation preserved
- Removed `CutterSeekable`, `SelectionManager`, `SelectionState`, `cursorAddressChanged`, `cursorSyncTimer_` coalescing, `seekToAddress`; deleted stray `src/symbol/Listing.cpp` (duplicate `ghidra::Listing` in engine archive)
- All entry points on one sync wave: views, minimap, string table, patch list, function explorer, hex search matches (`HexSearchBar::navigateRequested`), bookmarks, patch/undo/redo/assemble, navigateTo/back/forward
- Offscreen harness (temp: `test_navigation.exe`) 17/17: exact microlanding, mid-instruction byte exactness, skip masks, origin-guard, re-registration, lastEvent
