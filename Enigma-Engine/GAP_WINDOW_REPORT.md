# GAP WINDOW REPORT

## Test Results

Gap bridging window controls the maximum gap size (in bytes) between two function bodies that will be scanned for CALL targets.

| Window | Notepad (match/extra/miss) | Shell32 matching | Shell32 extra | Shell32 missing (adj) |
|--------|---------------------------|-----------------|---------------|-----------------------|
| 256    | 497/146/1                 | 30,233          | 7,309         | 760 (713)             |
| 128    | 497/146/1                 | 30,233          | 7,306         | 760 (713)             |
| 64     | 497/146/1                 | 30,233          | 7,306         | 760 (713)             |

## Analysis

- **Notepad is unaffected** by gap window size in all tested configurations (497/146/1).
- **Shell32 recall is identical** across all three windows (30,233 matching, 760 missing).
- **Shell32 extras differ:** 
  - Window 256: 7,309 (3 additional false positives)
  - Window 128: 7,306 
  - Window 64: 7,306

The 3 extra functions at window 256 are false positives created in gaps between 128-256 bytes. These are likely data alignment gaps or padding where random byte sequences happen to match CALL rel32 patterns pointing to other functions.

## Recommendation

**Default gap window: 128 bytes.**

| Window | Reasoning |
|--------|-----------|
| 64     | Too restrictive — same as 128 but might fail on legitimate larger gaps |
| **128** | **Optimal** — eliminates 3 FPs vs 256 while preserving full recall |
| 256    | Acceptable but 3 extra FPs with no recall benefit |

Window 128 is the safest production default: it matches the recall of 256 while eliminating 3 false positives, and is less restrictive than 64 for legitimate function sequences.
