/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionBlock.h
/// \brief Block of instructions for disassembly flow tracking
/// Translated from: ghidra.program.model.lang.InstructionBlock
#pragma once

#include <ghidra/Address.h>
#include <ghidra/InstructionBlockFlow.h>
#include <ghidra/Instruction.h>
#include <vector>
#include <unordered_map>
#include <memory>

namespace ghidra {

class InstructionBlock {
public:
    explicit InstructionBlock(const Address& startAddr);

    Address getStartAddress() const { return startAddr_; }
    Address getMaxAddress() const { return maxAddress_.isValid() ? maxAddress_ : startAddr_; }
    Address getFlowFromAddress() const { return flowFrom_; }
    Address getLastInstructionAddress() const { return lastInstructionAddress_; }
    Address getFallThrough() const { return fallthroughAddress_; }

    void setFlowFromAddress(const Address& addr) { flowFrom_ = addr; }
    void setFallThrough(const Address& addr) { fallthroughAddress_ = addr; }
    void setStartOfFlow(bool isStart) { isStartOfFlow_ = isStart; }
    bool isFlowStart() const { return isStartOfFlow_; }

    void addInstruction(Instruction* instruction);
    Instruction* getInstructionAt(const Address& address) const;

    void addBlockFlow(const InstructionBlockFlow& blockFlow);
    void addBranchFlow(const Address& destinationAddress);

    const std::vector<Address>& getBranchFlows() const { return flowAddresses_; }
    const std::vector<InstructionBlockFlow>& getBlockFlows() const { return blockFlows_; }

    bool isEmpty() const { return instructionMap_.empty(); }
    int getInstructionCount() const { return static_cast<int>(instructionMap_.size()); }

    int getInstructionsAddedCount() const { return instructionsAddedCount_; }
    void setInstructionsAddedCount(int count) { instructionsAddedCount_ = count; }

    bool hasInstructionError() const { return false; }

    std::string toString() const;

    const std::unordered_map<Address, Instruction*>& getInstructions() const { return instructionMap_; }

private:
    Address startAddr_;
    Address maxAddress_;
    Address flowFrom_;
    Address lastInstructionAddress_;
    Address fallthroughAddress_;

    bool isStartOfFlow_ = false;
    int instructionsAddedCount_ = 0;

    std::unordered_map<Address, Instruction*> instructionMap_;
    std::vector<Address> flowAddresses_;
    std::vector<InstructionBlockFlow> blockFlows_;
};

} // namespace ghidra
