/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/DisambiguateByBytes.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashStore.h"
#include "ghidra/correlate/AllBytesHashCalculator.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/CancelledException.h"

namespace ghidra {

std::vector<Hash> DisambiguateByBytes::calcHashes(InstructHash* instHash, int matchSize, HashStore* store) {
    std::vector<Hash> res;
    AllBytesHashCalculator hashCalc;
    Block* block = instHash->getBlock();
    int val = block->hashGram(matchSize, instHash, &hashCalc);
    res.push_back(Hash(val, 1));
    return res;
}

} // namespace ghidra
