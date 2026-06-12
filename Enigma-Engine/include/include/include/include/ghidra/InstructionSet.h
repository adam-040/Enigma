/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionSet.h
/// \brief Set of instructions organized as a graph of basic blocks
/// Translated from: ghidra.program.model.lang.InstructionSet
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/InstructionBlock.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <set>

namespace ghidra {

class Instruction;

class InstructionSet {
public:
    InstructionSet();

    void addBlock(InstructionBlock* block);

    InstructionBlock* getInstructionBlockContaining(const Address& address) const;
    Instruction* getInstructionAt(const Address& address) const;

    Address getMinAddress() const { return addressSet_.getMinAddress(); }
    const AddressSet& getAddressSet() const { return addressSet_; }
    int getInstructionCount() const { return instructionCount_; }

    bool containsBlockAt(const Address& blockAddr) const;
    bool intersects(const Address& minAddress, const Address& maxAddress) const;

    std::vector<InstructionBlock*> getBlocks() const;
    std::vector<InstructionBlock*>& getEmptyBlocks() { return emptyBlocks_; }

    std::string toString() const;

private:
    std::unordered_map<Address, InstructionBlock*> blockMap_;
    std::set<Address> startAddresses_;
    std::vector<InstructionBlock*> emptyBlocks_;
    AddressSet addressSet_;
    int instructionCount_ = 0;
};

} // namespace ghidra
