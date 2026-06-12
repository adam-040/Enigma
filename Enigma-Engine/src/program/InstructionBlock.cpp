/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionBlock.cpp
/// \brief Block of instructions for disassembly flow tracking
#include <ghidra/InstructionBlock.h>
#include <sstream>
#include <stdexcept>

namespace ghidra {

InstructionBlock::InstructionBlock(const Address& startAddr)
    : startAddr_(startAddr) {}

void InstructionBlock::addInstruction(Instruction* instruction) {
    Address instrMinAddr = instruction->getAddress();
    if (instructionMap_.empty()) {
        if (instrMinAddr != startAddr_) {
            throw std::invalid_argument("First instruction to block had unexpected address");
        }
    } else if (!maxAddress_.isSuccessor(instrMinAddr)) {
        throw std::invalid_argument("Newly added instruction is not the immediate successor");
    }
    instructionMap_[instrMinAddr] = instruction;
    lastInstructionAddress_ = instrMinAddr;
    maxAddress_ = instruction->getMaxAddress();
}

Instruction* InstructionBlock::getInstructionAt(const Address& address) const {
    auto it = instructionMap_.find(address);
    return (it != instructionMap_.end()) ? it->second : nullptr;
}

void InstructionBlock::addBlockFlow(const InstructionBlockFlow& blockFlow) {
    blockFlows_.push_back(blockFlow);
}

void InstructionBlock::addBranchFlow(const Address& destinationAddress) {
    flowAddresses_.push_back(destinationAddress);
}

std::string InstructionBlock::toString() const {
    std::ostringstream ss;
    ss << "[ " << startAddr_.toString();
    if (maxAddress_.isValid()) ss << "-" << maxAddress_.toString();
    else ss << ": <empty>";
    ss << "]";
    return ss.str();
}

} // namespace ghidra
