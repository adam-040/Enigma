/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionSet.cpp
/// \brief Set of instructions organized as a graph of basic blocks
#include <ghidra/InstructionSet.h>
#include <stdexcept>

namespace ghidra {

InstructionSet::InstructionSet() {}

void InstructionSet::addBlock(InstructionBlock* block) {
    if (!block) return;
    if (block->isEmpty()) {
        emptyBlocks_.push_back(block);
        return;
    }
    if (block->isFlowStart()) {
        startAddresses_.insert(block->getStartAddress());
    }
    blockMap_[block->getStartAddress()] = block;
    addressSet_.addRange(block->getStartAddress(), block->getMaxAddress());
    instructionCount_ += block->getInstructionCount();
}

InstructionBlock* InstructionSet::getInstructionBlockContaining(const Address& address) const {
    auto it = blockMap_.find(address);
    if (it != blockMap_.end()) {
        Address blockStart = it->first;
        Address blockMax = it->second->getMaxAddress();
        if (address >= blockStart && address <= blockMax) {
            return it->second;
        }
    }
    for (auto& pair : blockMap_) {
        if (address >= pair.first && address <= pair.second->getMaxAddress()) {
            return pair.second;
        }
    }
    return nullptr;
}

Instruction* InstructionSet::getInstructionAt(const Address& address) const {
    auto* block = getInstructionBlockContaining(address);
    return block ? block->getInstructionAt(address) : nullptr;
}

bool InstructionSet::containsBlockAt(const Address& blockAddr) const {
    return blockMap_.find(blockAddr) != blockMap_.end();
}

bool InstructionSet::intersects(const Address& minAddress, const Address& maxAddress) const {
    return addressSet_.intersects(minAddress, maxAddress);
}

std::vector<InstructionBlock*> InstructionSet::getBlocks() const {
    std::vector<InstructionBlock*> blocks;
    blocks.reserve(blockMap_.size());
    for (auto& pair : blockMap_) {
        blocks.push_back(pair.second);
    }
    return blocks;
}

std::string InstructionSet::toString() const {
    return "InstructionSet";
}

} // namespace ghidra
