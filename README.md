# Enigma Engine

A ground-up C++ reimplementation of Ghidra's analytical core, built to eliminate the JVM dependency and enable deep AI integration.

---

## What is this?

Ghidra is a reverse engineering framework built by the NSA in Java. Enigma is a native C++ rewrite of its analysis pipeline — same capabilities, no JVM, no Gradle, no Java runtime required.

The goal is a self-contained binary analysis engine that can be embedded, extended, and integrated with AI systems directly, without bridges or wrappers.

---

## Current State

The project is in active development. The core analysis pipeline is functional:

- PE and ELF binary loading
- x86/x64 disassembly via Capstone
- Pcode IR generation (Ghidra's decompiler C++ library, integrated as a static library)
- Function detection with ~97% recall on real Windows binaries vs Ghidra
- C decompiled output from real binaries
- Type recovery with Windows API signature seeding (1400+ prototypes)
- Custom repository-based project persistence (FlatBuffers snapshots, LMDB index, git-like commits and branches)
- Qt-based GUI with Disassembly, Decompiler, and Hex views

---

## Architecture

```
Binary (PE/ELF)
    ↓
BinaryLoader          — parses sections, imports, exports, .pdata
    ↓
Capstone Disassembler — decodes instructions
    ↓
Pcode Engine          — Ghidra's C++ decompiler library (taken as-is)
    ↓
Analysis Pipeline     — function detection, type recovery, cross-references
    ↓
Program Model         — functions, symbols, types, memory (387 headers, 119 .cpp)
    ↓
Storage               — FlatBuffers snapshots + LMDB index + git-like commits
    ↓
Qt GUI                — Disassembly / Decompiler / Hex / Explorer
```

### What is original vs what is taken from Ghidra

| Component | Source |
|---|---|
| Decompiler engine (~150K lines) | Ghidra C++ library — taken as-is |
| Sleigh processor specs | Ghidra — taken as-is |
| Program model, type system, memory | Java → C++ port (original work) |
| Analysis pipeline, function detection | Original C++ implementation |
| Binary loader | Original (PE/ELF parser, LIEF-ready) |
| Storage system | Original (FlatBuffers + LMDB + commits) |
| GUI | Original (Qt6) |

---

## Building

**Requirements:**
- C++17 compiler (GCC 11+ or Clang 13+)
- CMake 3.20+
- Qt 6.x
- Capstone, SQLite3, LMDB (via MSYS2/vcpkg)

```bash
git clone https://github.com/adam-040/Enigma.git
cd Enigma/enigma-engine
cmake -B build-cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake
```

---

## Function Detection — Benchmark vs Ghidra

Tested on real Windows binaries:

| Binary | Enigma | Ghidra | Recall |
|---|---|---|---|
| notepad.exe | 623 | 498 | 98%+ |
| shell32.dll | 30,233 | 30,993 | 97.55% |
| kernel32.dll | 3,763 | ~3,800 | ~99% |

---

## Roadmap

- [ ] LIEF integration for full PE/ELF/Mach-O parsing
- [ ] Improve decompiler output quality (struct recovery, better type inference)
- [ ] GUI stability and navigation
- [ ] AI integration — function naming, type inference, pattern recognition

---

## License

This project is separate from [Ghidra](https://github.com/NationalSecurityAgency/ghidra), licensed under **Apache License 2.0**.
