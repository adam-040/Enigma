/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/CodeBlockCache.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressRange.h>
#include <memory>
#include <algorithm>

namespace ghidra {

void CodeBlockCache::addCodeBlock(CodeBlock* block, const AddressSetView& addrSet) {
    blockToAddrs_[block] = AddressSet(addrSet);

    std::unique_ptr<AddressRangeIterator> iter(addrSet.getAddressRanges());
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Address end = range.getMaxAddress();
        while (addr.compareTo(end) <= 0) {
            addrToBlock_.insert(std::make_pair(addr, block));
            addr = addr.add(1);
        }
    }
}

void CodeBlockCache::removeCodeBlock(CodeBlock* block) {
    auto it = blockToAddrs_.find(block);
    if (it == blockToAddrs_.end()) {
        return;
    }

    const AddressSet& addrSet = it->second;
    std::unique_ptr<AddressRangeIterator> iter(addrSet.getAddressRanges());
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Address end = range.getMaxAddress();
        while (addr.compareTo(end) <= 0) {
            auto rangeIt = addrToBlock_.equal_range(addr);
            for (auto mmIt = rangeIt.first; mmIt != rangeIt.second; ) {
                if (mmIt->second == block) {
                    mmIt = addrToBlock_.erase(mmIt);
                } else {
                    ++mmIt;
                }
            }
            addr = addr.add(1);
        }
    }

    blockToAddrs_.erase(it);
}

CodeBlock* CodeBlockCache::getFirstCodeBlockContaining(const Address& addr) const {
    auto it = addrToBlock_.find(addr);
    if (it != addrToBlock_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<CodeBlock*> CodeBlockCache::getCodeBlocksContaining(const Address& addr) const {
    std::vector<CodeBlock*> result;
    auto range = addrToBlock_.equal_range(addr);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }
    return result;
}

void CodeBlockCache::clear() {
    addrToBlock_.clear();
    blockToAddrs_.clear();
}

} // namespace ghidra
