/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/Block.h"

namespace ghidra {

InstructHash::InstructHash(Instruction* inst, Block* bl, int ind)
    : isMatched(false), index(ind), block(bl), instruction(inst), nGrams(0) {
}

bool InstructHash::allUnknown(int length) {
    return block->allUnknown(index, length);
}

void InstructHash::clearSort() {
    hashEntries.clear();
}

void InstructHash::clearNGrams(int sz) {
    nGrams.assign(sz, Hash());
}

} // namespace ghidra
