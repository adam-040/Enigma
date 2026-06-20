# FEATURE BISECTION REPORT

## Feature Toggles

### 1. Two-phase DataSectionFunctionScanner

| State | Notepad (match/extra/miss) | Shell32 (match/miss adj) | Extra |
|-------|---------------------------|--------------------------|-------|
| OLD (single-phase) | 497/146/1 | 30,232/761 (714) | 7,309 |
| NEW (two-phase, pre-fix) | **496/42/2** ❌ | **30,212/781 (710)** | 8,542 |
| NEW (two-phase, post-fix) | **497/146/1** ✅ | **30,233/760 (713)** | 7,309 |

**Status:** ENABLED ✅

**Justification:** Two-phase split is correct. The regressions were caused by implementation bugs (documented below), not the two-phase architecture. After fixing both bugs, the two-phase scanner outperforms the old single-phase (+1 shell32 matching, same extras, same notepad).

### 2. Unlimited `.rdata` scanning

| State | Shell32 matching | Shell32 extra |
|-------|-----------------|---------------|
| Capped (MAX_FOUND=10000) | baseline | baseline |
| Unlimited (Phase 2) | **+2,584 found** | same |

**Status:** ENABLED ✅

**Justification:** Unlimited `.rdata` scanning found 2,584 additional function targets. No cap means no vtable targets are missed. Filtering uses the same safety checks (`getFunctionAt`, `getFunctionContaining`, `isUndefined`, first-byte != 0xCC) as the capped pass.

### 3. Vtable pointer recovery

| State | Shell32 extra | Notes |
|-------|--------------|-------|
| Old (runs-of-3+) | baseline | Required 3+ consecutive .rdata entries |
| New (all .rdata) | **same** | Accepts single/double entries too |

**Status:** ENABLED ✅

**Justification:** The run-of-3 requirement was overly conservative. Any `.rdata` 8-byte pointer to `.text` is strong deterministic evidence (COM vtable, RTTI, export table). The safety checks prevent false positives.

### 4. New gap bridging logic

| State | Notepad (match/extra/miss) | Shell32 (match/miss adj) | Shell32 extra |
|-------|---------------------------|--------------------------|---------------|
| Old (speculative) | N/A (removed) | N/A (removed) | N/A |
| New (reference-required) | 497/146/1 | 30,233/760 (713) | 7,309 |

**Status:** ENABLED ✅

**Justification:** Reference-required gap bridging is safe (zero false positives by construction). It scans gaps for CALL rel32 targets and creates functions only when a CALL reference exists.

### 5. Reference-required gap bridging

Same as #4.

### 6. Scanner limit modifications

| Change | Effect |
|--------|--------|
| MAX_FOUND 500 → 2000 → 10000 | Progressive improvement |
| Removed cap for `.rdata` (Phase 2) | +2,584 additional vtable functions |

**Status:** OPTIONAL — limits are now per-phase with `.rdata` being unlimited.

## Regression Root Causes (from implementation bugs)

Both regressions were introduced during the two-phase refactoring:

1. **Bug A** (`.rdata` 4-byte RVA skip): When `.rdata` was excluded from `collect8BytePointers()`, it was also incorrectly excluded from `collect4ByteRVAs()`. This lost functions referenced only by 4-byte RVAs in `.rdata`. **Fixed** by removing `.rdata` from the skip list in `collect4ByteRVAs()`.

2. **Bug B** (`isInFunctionRanges` overfilter): The new `scanCandidates()` lambda added an `isInFunctionRanges()` check that was not in the original vtable-run pass. This rejected valid vtable targets whose addresses fell inside pre-computed function body ranges (stale ranges from before Phase 1). **Fixed** by removing `isInFunctionRanges()` from `scanCandidates()`.

## Final Verdict

| Feature | Status | Justification |
|---------|--------|--------------|
| Two-phase scanner | ENABLED | Correct architecture after bug fixes |
| Unlimited `.rdata` | ENABLED | Finds all vtable targets |
| Vtable pointer recovery | ENABLED | Accepts all `.rdata` → `.text` pointers |
| Reference-required gap bridging | ENABLED | Zero FP by construction |
| Scanner limits (MAX_FOUND) | OPTIONAL | 10,000 for non-.rdata; unlimited for `.rdata` |
