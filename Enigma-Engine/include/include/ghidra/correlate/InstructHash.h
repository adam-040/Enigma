/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <vector>
#include <unordered_map>
#include "ghidra/correlate/Hash.h"

namespace ghidra {

class Instruction;
class Block;
class HashEntry;

class InstructHash {
public:
    bool isMatched;
    int index;
    Block* block;
    Instruction* instruction;
    std::vector<Hash> nGrams;
    std::unordered_map<Hash, HashEntry*> hashEntries;

    InstructHash(Instruction* inst, Block* bl, int ind);
    InstructHash() = default;

    Block* getBlock() const { return block; }
    bool allUnknown(int length);
    void clearSort();
    void clearNGrams(int sz);
};

} // namespace ghidra
