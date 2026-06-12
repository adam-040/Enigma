/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/DisambiguateByParent.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashStore.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/block/CodeBlockReference.h"
#include "ghidra/block/CodeBlockReferenceIterator.h"
#include "ghidra/CancelledException.h"

namespace ghidra {

static const int ENTRY_BLOCK_HASH = 0x9a8b7c6d;

std::vector<Hash> DisambiguateByParent::calcHashes(InstructHash* instHash, int matchSize, HashStore* store) {
    std::vector<Hash> res;
    Block* block = instHash->getBlock();
    CodeBlockReferenceIterator* iter = block->origBlock->getSources(*store->getMonitor());
    int count = 0;
    while (iter->hasNext()) {
        CodeBlockReference* ref = iter->next();
        count += 1;
        Block* srcBlock = store->getBlock(ref->getSourceAddress());
        if (srcBlock != nullptr && srcBlock->getMatchHash() != 0) {
            res.push_back(Hash(srcBlock->getMatchHash(), 1));
        }
    }
    delete iter;
    if (count == 0) {
        res.push_back(Hash(ENTRY_BLOCK_HASH, 1));
    }
    return res;
}

} // namespace ghidra
