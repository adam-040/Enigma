# NOTEPAD REGRESSION REPORT

## Summary

| Metric        | Baseline | Regressed | Restored |
|---------------|----------|-----------|----------|
| Matching      | 497      | 496       | **497**  |
| Extra         | 146      | 42        | **146**  |
| Missing       | 1        | 2         | **1**    |

## Missing Functions

### FUN_140011890 (0x140011890)

**Status:** Previously matched, disappeared, now restored.

**Cause:** `collect4ByteRVAs()` was modified to skip `.rdata` sections. This function has **0 eight-byte** `.rdata` references but **1 four-byte RVA** in `.rdata`. Phase 2 only scans 8-byte values, so the function fell through the cracks.

**Resolution:** Removed `.rdata` from the skip list in `collect4ByteRVAs()`. Reverting to the original behavior where `.rdata` is scanned for 4-byte RVAs.

### FUN_140022b70 (0x140022b70)

**Status:** Previously matched, disappeared, now restored.

**Cause:** `scanCandidates()` was given an `isInFunctionRanges()` check that was **not present** in the original vtable-run pass. This function has **4 eight-byte** `.rdata` references (valid vtable entry) but falls inside a pre-computed function body range. The old code only checked `getFunctionAt()` + `isUndefined()`, both of which pass correctly for this address.

**Resolution:** Removed `isInFunctionRanges()` from `scanCandidates()`. The existing `getFunctionAt()`, `getFunctionContaining()`, and `isUndefined()` checks provide sufficient safety.

## Root Cause

Two changes to `DataSectionFunctionScannerAnalyzer.cpp` during the Phase 2 refactoring:

| Change | File:Line | Effect |
|--------|-----------|--------|
| Added `.rdata` to skip list in `collect4ByteRVAs()` | line 177 | Lost 4-byte RVA targets in `.rdata` |
| Added `isInFunctionRanges()` guard in `scanCandidates()` | line 275 | Rejected vtable targets inside existing function bodies |

Both have been reverted. Canary restored.
