# Enigma Storage Architecture

## Overview

Enigma uses a repository-based storage architecture specifically designed for reverse engineering workflows.

The design separates:

- Runtime state
- Persistence
- Version history
- Undo/Redo
- Search and indexing

The goals are:

- Fast analysis
- Fast loading
- Safe persistence
- Versioned history
- Branching support
- Rebuildable indexes
- Collaboration-ready architecture

---

# Core User Operations

Enigma exposes three distinct user operations:

```text
Save
Commit
Branch
```

Each serves a different purpose.

---

## Save

Purpose:

```text
Keep current progress.
```

Behavior:

```text
ProgramDB
    ↓
working.fbs
```

Characteristics:

- Fast
- Overwrites current working state
- Does not create history
- Does not create commits
- Does not create branches

Equivalent to:

```text
Ctrl + S
```

---

## Commit

Purpose:

```text
Create a permanent history checkpoint.
```

Behavior:

```text
working.fbs
      ↓
snapshot.fbs
      ↓
new commit
```

Characteristics:

- Permanent
- Immutable
- Restorable
- Appears in history
- Can be used as a future branch point

Example:

```text
A → B → C → D
```

---

## Branch

Purpose:

```text
Create a new independent analysis timeline.
```

Behavior:

```text
Existing Commit
        ↓
Create Branch
        ↓
Independent Future History
```

Example:

```text
main

A → B → C
```

Create Branch from C:

```text
main

A → B → C

experimental

          C → D → E
```

Characteristics:

- Independent future commits
- Independent analysis path
- Safe experimentation
- Does not affect original branch

---

# Architecture

```text
Repository
│
├── Metadata
├── Branches
├── Commits
├── Working Snapshot
├── Binary Information
└── Index Cache (LMDB)

Runtime
│
├── ProgramDB
└── Event Log
```

---

# Initial Import

When a binary is opened for the first time:

```text
Binary File
      ↓
Loader
      ↓
Create ProgramDB
      ↓
Initial Analysis
      ↓
First Save
      ↓
Create Working Snapshot
      ↓
Create Repository
```

After the repository exists, all future loads originate from snapshots.

---

# Crash Safety

To prevent corruption during crashes or power loss:

```text
ProgramDB
      ↓
working.fbs.tmp
      ↓
fsync()
      ↓
rename()
      ↓
working.fbs
```

If a crash occurs before rename:

```text
working.fbs
```

remains valid.

This guarantees atomic snapshot replacement.

---

# 1. ProgramDB (Runtime Layer)

## Purpose

ProgramDB is the active reverse engineering model loaded into memory.

It is the only structure used by:

- Analysis engine
- Decompiler
- UI
- Scripting system
- Plugins

## Storage

Stored entirely in RAM.

## Contains

- Functions
- Instructions
- Basic Blocks
- CFG
- Data Types
- Symbols
- Comments
- Analysis Metadata
- References
- User Annotations

## Rules

ProgramDB is never queried directly from persistent storage.

Project Open:

```text
Snapshot
    ↓
ProgramDB
```

Project Save:

```text
ProgramDB
    ↓
Snapshot
```

ProgramDB is always the live working state.

---

# 2. Event Log (Undo / Redo Layer)

## Purpose

Provides instantaneous Undo and Redo.

## Design

Append-only event stream.

Every user action creates an event.

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

## Usage

Undo:

```text
Reverse last event
```

Redo:

```text
Replay event
```

## Lifetime

Temporary.

Exists only while the project is open.

When a commit is created:

```text
Event Log
      ↓
Generate ChangeSet
      ↓
Store in Commit Metadata
```

The Event Log itself remains session-local.

After Enigma closes:

```text
Event Log is discarded
```

Undo history is therefore session-based.

Commit history remains permanent.

## Important

Event Log is NOT version history.

Event Log exists only for interactive editing.

---

# 3. Snapshot System

## Purpose

Persistent storage of complete analysis state.

## Format

FlatBuffers

## Why FlatBuffers

- Fast serialization
- Fast deserialization
- Stable binary format
- mmap friendly
- Zero-copy friendly
- Versionable schema

## Snapshot Contents

Full ProgramDB state:

- Functions
- Instructions
- CFG
- Symbols
- Types
- Comments
- References
- Analysis Metadata
- User Data

## Properties

- Immutable
- Self-contained
- Restorable
- Independent

A snapshot always represents a complete project state.

---

# 4. Save System

## Purpose

Store current progress without creating history.

## Behavior

```text
ProgramDB
      ↓
working.fbs
```

## Characteristics

- Fast
- Overwrites previous working state
- Does not create commit history
- Does not create branches

Result:

```text
working.fbs
```

always contains the latest working state.

---

# 5. Commit System

## Purpose

Create permanent repository history.

## Definition

A commit is a repository history node.

Each commit owns:

- A complete immutable snapshot
- A ChangeSet describing modifications since the previous commit

## Structure

```text
Commit
├── Commit ID
├── Parent Commit
├── Snapshot Reference
├── Timestamp
├── Message
├── Branch
└── ChangeSet
```

Example:

```text
Commit A
    ↓
Commit B
    ↓
Commit C
```

---

## What a Commit Actually Is

A commit is a complete independent copy of the project state.

Not a patch.

Not a delta.

Not a replay chain.

Example:

```text
commits/

abc123/
├── snapshot.fbs
└── changeset.bin

def456/
├── snapshot.fbs
└── changeset.bin

ghi789/
├── snapshot.fbs
└── changeset.bin
```

Each commit can be loaded independently.

No previous commit is required.

---

## ChangeSet

A ChangeSet is generated from the session Event Log.

Examples:

```text
Renamed Functions
Changed Types
Added Comments
Deleted Comments
Created Structures
Modified Structures
```

Purpose:

- Commit comparison
- Branch comparison
- Change summaries
- Future collaboration
- Future merge support

ChangeSets are NOT used for restoring projects.

Snapshots are always used for restoration.

---

## Commit Creation

```text
ProgramDB
      ↓
Create Snapshot
      ↓
Generate ChangeSet
      ↓
Create Commit
      ↓
Update Branch History
```

---

## Restoring a Commit

```text
Select Commit
      ↓
Load snapshot.fbs
      ↓
Rebuild ProgramDB
      ↓
Replace working.fbs
      ↓
Ready
```

No replay.

No dependency chains.

No reconstruction.

---

## Characteristics

- Immutable
- Permanent
- Restorable
- Branchable
- Collaboration-ready

---

# 6. Branch System

## Purpose

Allow multiple independent analysis paths.

## Definition

A branch is an independent timeline created from an existing commit.

Example:

```text
main

A → B → C
         \
          D → E
            experimental
```

## Branch Creation

```text
Select Commit
      ↓
Create Branch
      ↓
New Branch Pointer
      ↓
Independent Future History
```

Example:

```text
main

A → B → C → D
```

Create branch from B:

```text
main

A → B → C → D

research

A → B → X → Y
```

## Properties

- Independent history
- Independent future commits
- Independent analysis paths
- Safe experimentation
- No impact on original branch

## Use Cases

- Alternative type recovery
- Malware analysis hypotheses
- Experimental analysis
- Team workflows
- Research branches

---

# 7. Repository

## Purpose

Container for the complete project.

## Example Layout

```text
project.enigma/
│
├── metadata/
│   ├── project.fbs
│   └── branches.fbs
│
├── working/
│   └── working.fbs
│
├── commits/
│   ├── abc123/
│   │   ├── snapshot.fbs
│   │   └── changeset.bin
│   │
│   └── def456/
│       ├── snapshot.fbs
│       └── changeset.bin
│
├── index/
│   └── lmdb/
│
└── binary/
    └── target.exe
```

## Analogy

Similar to Git.

However:

Enigma stores analysis state rather than source code.

---

# 8. Metadata Layer

## Purpose

Store repository information.

## Contains

- Project name
- Binary information
- Architecture
- Image base
- Creation time
- Commit graph
- Branch pointers
- User preferences

## Format

FlatBuffers or small binary format.

---

# 9. Index Layer (LMDB)

## Purpose

Acceleration layer only.

LMDB is never a source of truth.

## Contains

- XRefs
- Symbol Index
- String Index
- Search Data
- Address Mappings

## Usage

Fast:

- Search
- Navigation
- Symbol Lookup
- Cross References

## Important

If LMDB is deleted:

```text
No project data is lost.
```

Recovery:

```text
Snapshot
      ↓
Rebuild Index
      ↓
Ready
```

## Principle

```text
Snapshots = Truth

LMDB = Cache
```

---

# 10. Loading Process

Normal Project Open:

```text
Open Project
      ↓
Load Snapshot
      ↓
Rebuild ProgramDB
      ↓
Load LMDB
      ↓
Ready
```

If LMDB does not exist:

```text
Load Snapshot
      ↓
Rebuild Index
      ↓
Ready
```

---

# 11. Saving Process

Save:

```text
ProgramDB
      ↓
working.fbs
```

Commit:

```text
ProgramDB
      ↓
Snapshot
      ↓
ChangeSet
      ↓
Commit
      ↓
Update Branch
```

Branch:

```text
Existing Commit
      ↓
Create Branch
      ↓
Independent Timeline
```

---

# 12. Design Principles

## Principle 1

ProgramDB is the runtime truth.

## Principle 2

Snapshots are the persistent truth.

## Principle 3

Commits are repository history.

## Principle 4

Branches are independent analysis timelines.

## Principle 5

LMDB is only an acceleration cache.

## Principle 6

Undo/Redo is handled exclusively by Event Log.

## Principle 7

Snapshots restore state.

ChangeSets describe changes.

## Principle 8

A commit must always be loadable independently.

## Principle 9

Save, Commit, and Branch are separate operations with separate responsibilities.

---

# Final Formula

```text
ProgramDB
    +
Event Log
    +
FlatBuffers Snapshots
    +
ChangeSets
    +
Commit History
    +
Branches
    +
LMDB Cache

=

Enigma Storage System
```