/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/AllBytesHashCalculator.h"
#include "ghidra/Instruction.h"
#include "ghidra/Program.h"
#include "ghidra/Memory.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/SimpleCRC32.h"
#include <vector>
#include <cstdint>

namespace ghidra {

int AllBytesHashCalculator::calcHash(int startHash, Instruction* inst) {
    int len = inst->getLength();
    std::vector<uint8_t> bytes(len);
    int read = inst->getProgram()->getMemory()->getBytes(inst->getAddress(), bytes.data(), len);
    if (read < len) {
        throw MemoryAccessException("Could not read all instruction bytes");
    }
    for (int i = 0; i < len; ++i) {
        startHash = SimpleCRC32::hashOneByte(startHash, bytes[i]);
    }
    return startHash;
}

} // namespace ghidra
