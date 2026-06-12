/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/DisambiguateByChild.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashStore.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/block/CodeBlockReference.h"
#include "ghidra/block/CodeBlockReferenceIterator.h"
#include "ghidra/CancelledException.h"

namespace ghidra {

static const int EXIT_BLOCK_HASH = 0x6a7b8c9d;

std::vector<Hash> DisambiguateByChild::calcHashes(InstructHash* instHash, int matchSize, HashStore* store) {
    std::vector<Hash> res;
    Block* block = instHash->getBlock();
    CodeBlockReferenceIterator* iter = block->origBlock->getDestinations(*store->getMonitor());
    int count = 0;
    while (iter->hasNext()) {
        CodeBlockReference* ref = iter->next();
        count += 1;
        Block* destBlock = store->getBlock(ref->getDestinationAddress());
        if (destBlock != nullptr && destBlock->getMatchHash() != 0) {
            res.push_back(Hash(destBlock->getMatchHash(), 1));
        }
    }
    delete iter;
    if (count == 0) {
        res.push_back(Hash(EXIT_BLOCK_HASH, 1));
    }
    return res;
}

} // namespace ghidra
