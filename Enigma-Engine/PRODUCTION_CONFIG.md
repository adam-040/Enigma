# PRODUCTION CONFIGURATION

## Feature States

| Feature | State | Justification |
|---------|-------|---------------|
| Two-phase DataSectionFunctionScanner | **ENABLED** | Correct architecture; Phase 1 (non-.rdata, capped 10k) + Phase 2 (.rdata, unlimited). After bug fixes, outperforms old single-phase. |
| Unlimited `.rdata` scanning | **ENABLED** | All `.rdata` 8-byte pointers to `.text` are strong deterministic evidence. No cap needed. |
| `collect4ByteRVAs` from `.rdata` | **ENABLED** | Restored: `.rdata` may contain 4-byte RVA references to functions not referenced by 8-byte pointers. |
| Vtable pointer recovery | **ENABLED** | Accepts all `.rdata`→`.text` pointer targets without run-of-3 requirement. Safety: `getFunctionAt` + `getFunctionContaining` + `isUndefined` + first-byte≠0xCC. |
| Gap bridging window | **ENABLED (128 bytes)** | Reference-required (CALL rel32 targets only). Window 128 eliminates 3 FPs vs 256 while preserving full recall. |
| Reference-required gap bridging | **ENABLED** | Zero false positives by construction (only creates functions at CALL rel32 target addresses). |
| MAX_FOUND limit for non-.rdata | **ENABLED (10,000)** | Conservative cap for `.data`, `.idata`, `.rsrc` sections where pointers may be spurious. |
| MAX_FOUND limit for `.rdata` | **DISABLED** (unlimited) | `.rdata` pointers are strong evidence. No cap needed. |
| Speculative gap bridging | **DISABLED** | Removed due to 99.996% FP rate (26,485 FPs for 1 TP). |
| ML/confidence systems | **DISABLED** | Not implemented. Not needed — current deterministic approach achieves 97.5%+ recall. |
| `.pdata` function recovery | **ENABLED** | Authoritative: reads PE `.pdata` → `func_pdata_0x...`. |
| Tail-call wrapper detection | **ENABLED** | Scans CALL rel32 targets, accepts sequences ending in JMP/RET (no embedded CALL). Reference-required. |

## Current Performance

| Metric | Notepad | Shell32 |
|--------|---------|---------|
| Matching | 497 | 30,233 |
| Extra | 146 | 7,309 |
| Missing | 1 | 760 (713 adjusted) |
| Recall | 99.8% | 97.5% (97.7% adjusted) |

## Gate Status

| Gate | Requirement | Current | Pass? |
|------|------------|---------|-------|
| Notepad canary | 497 matching / 1 missing | 497 / 1 | ✅ |
| Shell32 adjusted recall | ≥ 97.5% | 97.7% | ✅ |
| No analyzer hangs | No timeout or crash | None observed | ✅ |
| Deterministic | Same binary → same output | Verified (2× run identical) | ✅ |
