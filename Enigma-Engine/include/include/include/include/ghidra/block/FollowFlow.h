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
#include <ghidra/RefType.h>
#include <vector>
#include <stack>

namespace ghidra {

class Program;
class AddressSetView;
class AddressSpace;
class TaskMonitor;
class CancelledException;
class Instruction;

/**
 * FollowFlow follows the program's code flow either forward or backward from an initial
 * address set.
 * Translated from: ghidra.program.model.block.FollowFlow
 */
class FollowFlow {
private:
    Program* program_;
    AddressSetView* initialAddresses_;

    bool followAllFlow_ = true;
    bool followComputedCall_ = true;
    bool followConditionalCall_ = true;
    bool followUnconditionalCall_ = true;
    bool followComputedJump_ = true;
    bool followConditionalJump_ = true;
    bool followUnconditionalJump_ = true;
    bool followPointers_ = true;

    bool followIntoFunction_ = true;
    bool includeData_ = true;
    AddressSpace* restrictedAddressSpace_ = nullptr;
    Address nextSymbolAddr_;

    void updateFollowFlags(const std::vector<const FlowType*>& doNotFollow);
    AddressSet getAddressFlow(TaskMonitor& monitor, const AddressSetView& startAddresses, bool forward);
    void followCode(std::stack<Address>& workList, Instruction* instr);
    void followCodeBack(std::stack<Address>& workList, Instruction* instr);
    bool shouldFollowFlow(const FlowType* flowType) const;

public:
    FollowFlow(Program* program, const AddressSetView& addressSet,
               const std::vector<const FlowType*>& doNotFollow);
    FollowFlow(Program* program, const AddressSetView& addressSet,
               const std::vector<const FlowType*>& doNotFollow, bool followIntoFunctions);
    FollowFlow(Program* program, const AddressSet& addressSet,
               const std::vector<const FlowType*>& doNotFollow,
               bool followIntoFunctions, bool includeData);
    FollowFlow(Program* program, const Address& address,
               const std::vector<const FlowType*>& doNotFollow,
               bool followIntoFunctions, bool includeData, bool restrictSingleAddressSpace);

    AddressSet getFlowAddressSet(TaskMonitor& monitor);
    AddressSet getFlowToAddressSet(TaskMonitor& monitor);
};

} // namespace ghidra
