# Enigma Diff System

## Overview

The Diff system is responsible for describing changes between analysis states.

Unlike traditional source control systems, Enigma does not primarily compute differences by comparing entire project states.

Instead:

```text
Changes are recorded when they happen.
```

This makes most diffs effectively free.

The system is designed around the same principles as the storage architecture:

- ProgramDB is the runtime state
- Event Log powers Undo/Redo
- Snapshots restore state
- ChangeSets describe state transitions
- Commits preserve history
- Branches create independent timelines

---

# 1. Goals

The Diff system must support:

- Undo / Redo
- Commit comparison
- Branch comparison
- Change inspection
- History visualization
- Future collaboration features
- Future merge support

While avoiding:

- Full ProgramDB scans
- CFG re-analysis
- Graph hashing
- Expensive project comparisons
- Repository-wide rescans

---

# 2. Core Principle

Traditional systems:

```text
State A
    ↓
Compare
    ↓
State B
    ↓
Generate Diff
```

Enigma:

```text
State A
    ↓
Record Changes
    ↓
State B
```

The changes already exist.

Therefore:

```text
Diff is mostly recorded, not computed.
```

---

# 3. Event-Based Diff

## Definition

Every user modification generates an Event.

Examples:

```text
RenameSymbol
RenameFunction
ChangeType
AddComment
DeleteComment
CreateStructure
ModifyStructure
CreateEnum
RenameField
```

Example:

```text
RenameFunction(
    address=0x401000,
    old="sub_401000",
    new="main"
)
```

---

# 4. Event Log

## Purpose

Track modifications during an active session.

The Event Log powers:

- Undo
- Redo
- Change tracking
- Commit generation

Example:

```text
Change #1
Change #2
Change #3
...
```

The Event Log exists only while the project is open.

When Enigma closes:

```text
Event Log is discarded
```

Therefore:

```text
Event Log is NOT permanent history.
```

---

# 5. ChangeSets

## Definition

A ChangeSet is the permanent diff representation stored inside a commit.

A ChangeSet is generated from the Event Log when a commit is created.

```text
Session Events
      ↓
Compaction
      ↓
ChangeSet
      ↓
Store in Commit
```

---

## Purpose

Used for:

- Commit comparison
- Branch comparison
- Change inspection
- History visualization
- Future collaboration
- Future merge support

---

## Example

Session:

```text
Rename A → B
Rename B → C
Rename C → D
```

Stored ChangeSet:

```text
Rename A → D
```

Only the final meaningful result is preserved.

This keeps history clean and compact.

---

# 6. Diff Sources

Enigma uses three different diff sources.

---

## 1. Event Diff

Used during active editing.

```text
User Action
      ↓
Event Log
      ↓
Undo / Redo
```

Characteristics:

- Session-only
- Extremely fast
- Not persistent

---

## 2. ChangeSet Diff

Used for repository history.

```text
Commit
      ↓
ChangeSet
      ↓
Diff Information
```

Characteristics:

- Permanent
- Stored in commits
- Used for history inspection

---

## 3. Structural Diff

Used only when repository history does not exist.

Examples:

```text
Binary A
vs
Binary B

Project A
vs
Project B

External Imports
```

Characteristics:

- Expensive
- Fallback mechanism
- Not the default workflow

---

# 7. Complexity

Traditional Structural Diff:

```text
O(N)
```

Where:

```text
N = entire project size
```

May require:

- Graph traversal
- CFG comparison
- Symbol comparison
- Metadata comparison

---

Enigma Change-Based Diff:

```text
O(K)
```

Where:

```text
K = actual changes
```

Example:

```text
Project:
10,000 Functions

Modified:
1 Function Name

Cost:
1 Recorded Change
```

Not:

```text
10,000 Function Comparisons
```

---

# 8. Undo / Redo

Undo:

```text
Apply inverse event
```

Redo:

```text
Replay event
```

Example:

```text
Rename:
sub_401000
    →
main
```

Undo:

```text
main
    →
sub_401000
```

No diff calculation required.

---

# 9. Commit Comparison

## Purpose

Show the user:

```text
What changed between Commit A and Commit B?
```

---

## Method

If commits share history:

```text
Commit A
      ↓
ChangeSets
      ↓
Commit B
```

The diff is reconstructed from the ChangeSets stored in commits.

---

## Example Output

```text
+ Renamed 4 functions
+ Added 2 structures
+ Changed 7 types
+ Added 12 comments
```

No snapshot scanning is required.

---

# 10. Branch Comparison

Example:

```text
main

A → B → C

experimental

A → D → E
```

To compare:

```text
C vs E
```

Find:

```text
Common Ancestor = A
```

Then compare:

```text
A → C ChangeSets

vs

A → E ChangeSets
```

This produces a branch diff.

---

# 11. Commit Metadata

Every commit stores metadata describing its modifications.

Example:

```text
Commit
├── Commit ID
├── Parent
├── Snapshot
├── Timestamp
├── Message
├── Branch
└── ChangeSet
```

The ChangeSet may contain:

```text
Modified Functions
Modified Symbols
Modified Types
Modified Structures
Modified Comments
Modified References
```

This allows instant summaries without opening snapshots.

Example:

```text
Commit: "Recovered networking layer"

Changes:

- 14 renamed functions
- 6 new structures
- 3 type corrections
- 12 added comments
```

---

# 12. When Real Diff Is Needed

Most repository diffs use ChangeSets.

However some situations have no shared history.

Examples:

```text
Different binaries

Malware v1
vs
Malware v2

Imported projects

Independent repositories
```

In these cases:

```text
Structural Diff
```

may be required.

---

# 13. Advanced Binary Diff (Future)

Future versions may support:

- CFG Diff
- Function Similarity
- Semantic Matching
- Binary Version Comparison
- Structural Graph Comparison

Similar to:

- BinDiff
- Diaphora

This system is independent from repository history.

---

# 14. Relationship to Storage System

```text
ProgramDB
      ↓
User Changes
      ↓
Event Log
      ↓
Undo / Redo

Commit Creation
      ↓
Compact Events
      ↓
Generate ChangeSet
      ↓
Store in Commit

Repository History
      ↓
Diff Information

Snapshots
      ↓
State Recovery
```

---

# 15. Design Principles

## Principle 1

Record changes once.

---

## Principle 2

Never scan the entire project when unnecessary.

---

## Principle 3

Events are the source of runtime change tracking.

---

## Principle 4

ChangeSets are the source of permanent diff information.

---

## Principle 5

Commit history should expose changes instantly.

---

## Principle 6

Event Logs are temporary.

ChangeSets are permanent.

---

## Principle 7

Snapshots restore state.

ChangeSets describe state transitions.

---

## Principle 8

Structural Diff is a fallback, not the default workflow.

---

## Principle 9

Repository history should scale with actual changes, not project size.

---

# Final Formula

```text
User Changes
      ↓
Events
      ↓
Undo / Redo

Events
      ↓
Compaction
      ↓
ChangeSet
      ↓
Commit

ChangeSets
      ↓
Diff Information

Snapshots
      ↓
State Recovery

Branches
      ↓
Parallel Timelines
```

Or simply:

```text
Enigma does not discover changes.

Enigma remembers changes.
```