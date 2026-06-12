/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/DisambiguateByParentWithOrder.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashStore.h"
#include "ghidra/Address.h"
#include "ghidra/AddressSetView.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/block/CodeBlockReference.h"
#include "ghidra/block/CodeBlockReferenceIterator.h"
#include "ghidra/SimpleCRC32.h"
#include "ghidra/CancelledException.h"

namespace ghidra {

std::vector<Hash> DisambiguateByParentWithOrder::calcHashes(InstructHash* instHash, int matchSize, HashStore* store) {
    std::vector<Hash> res;
    Block* block = instHash->getBlock();
    CodeBlockReferenceIterator* iter = block->origBlock->getSources(*store->getMonitor());
    Address startAddr = block->origBlock->getMinAddress();
    while (iter->hasNext()) {
        CodeBlockReference* ref = iter->next();
        Block* srcBlock = store->getBlock(ref->getSourceAddress());
        if (srcBlock != nullptr && srcBlock->getMatchHash() != 0) {
            CodeBlockReferenceIterator* srcIter = srcBlock->origBlock->getDestinations(*store->getMonitor());
            int totalcount = 0;
            int count = 0;
            while (srcIter->hasNext()) {
                Address addr = srcIter->next()->getDestinationAddress();
                totalcount += 1;
                if (addr.compareTo(startAddr) < 0)
                    count += 1;
            }
            delete srcIter;
            if (totalcount <= 1) continue;
            count = SimpleCRC32::hashOneByte(srcBlock->getMatchHash(), count);
            res.push_back(Hash(count, 1));
        }
    }
    delete iter;
    return res;
}

} // namespace ghidra
