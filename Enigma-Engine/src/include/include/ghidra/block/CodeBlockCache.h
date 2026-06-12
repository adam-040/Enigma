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

#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <map>
#include <vector>
#include <memory>

namespace ghidra {

class CodeBlock;

/**
 * CodeBlockCache maintains a mapping between addresses and CodeBlock objects.
 * Simplified C++ implementation of the Java AddressObjectMap-based cache.
 * Translated from: ghidra.program.model.block.CodeBlockCache
 */
class CodeBlockCache {
private:
    std::multimap<Address, CodeBlock*> addrToBlock_;
    std::map<CodeBlock*, AddressSet> blockToAddrs_;

public:
    CodeBlockCache() = default;
    ~CodeBlockCache() = default;

    void addCodeBlock(CodeBlock* block, const AddressSetView& addrSet);
    void removeCodeBlock(CodeBlock* block);

    CodeBlock* getFirstCodeBlockContaining(const Address& addr) const;
    std::vector<CodeBlock*> getCodeBlocksContaining(const Address& addr) const;

    using BlockMap = std::map<CodeBlock*, AddressSet>;

    void clear();
    int size() const { return static_cast<int>(blockToAddrs_.size()); }
    const BlockMap& getBlockMap() const { return blockToAddrs_; }
};

} // namespace ghidra
