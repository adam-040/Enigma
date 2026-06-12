/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/FollowFlow.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <memory>
#include <algorithm>

namespace ghidra {

FollowFlow::FollowFlow(Program* program, const AddressSetView& addressSet,
                       const std::vector<const FlowType*>& doNotFollow)
    : program_(program), initialAddresses_(const_cast<AddressSetView*>(&addressSet)) {
    updateFollowFlags(doNotFollow);
}

FollowFlow::FollowFlow(Program* program, const AddressSetView& addressSet,
                       const std::vector<const FlowType*>& doNotFollow, bool followIntoFunctions)
    : program_(program), initialAddresses_(const_cast<AddressSetView*>(&addressSet)),
      followIntoFunction_(followIntoFunctions) {
    updateFollowFlags(doNotFollow);
}

FollowFlow::FollowFlow(Program* program, const AddressSet& addressSet,
                       const std::vector<const FlowType*>& doNotFollow,
                       bool followIntoFunctions, bool includeData)
    : program_(program), initialAddresses_(const_cast<AddressSetView*>(
          static_cast<const AddressSetView*>(&addressSet))),
      followIntoFunction_(followIntoFunctions), includeData_(includeData) {
    updateFollowFlags(doNotFollow);
}

FollowFlow::FollowFlow(Program* program, const Address& address,
                       const std::vector<const FlowType*>& doNotFollow,
                       bool followIntoFunctions, bool includeData, bool restrictSingleAddressSpace)
    : program_(program),
      initialAddresses_(new AddressSet(address, address)),
      followIntoFunction_(followIntoFunctions), includeData_(includeData) {
    if (restrictSingleAddressSpace) {
        restrictedAddressSpace_ = address.getAddressSpace();
    }
    updateFollowFlags(doNotFollow);
}

void FollowFlow::updateFollowFlags(const std::vector<const FlowType*>& doNotFollowFlows) {
    if (doNotFollowFlows.empty()) {
        return;
    }
    followAllFlow_ = false;
    for (const FlowType* flowType : doNotFollowFlows) {
        if (*flowType == RefTypes::COMPUTED_CALL) {
            followComputedCall_ = false;
        }
        else if (*flowType == RefTypes::CONDITIONAL_CALL) {
            followConditionalCall_ = false;
        }
        else if (*flowType == RefTypes::UNCONDITIONAL_CALL) {
            followUnconditionalCall_ = false;
        }
        else if (*flowType == RefTypes::COMPUTED_JUMP) {
            followComputedJump_ = false;
        }
        else if (*flowType == RefTypes::CONDITIONAL_JUMP) {
            followConditionalJump_ = false;
        }
        else if (*flowType == RefTypes::UNCONDITIONAL_JUMP) {
            followUnconditionalJump_ = false;
        }
        else if (*flowType == RefTypes::INDIRECTION) {
            followPointers_ = false;
        }
    }
}

AddressSet FollowFlow::getFlowAddressSet(TaskMonitor& monitor) {
    return getAddressFlow(monitor, *initialAddresses_, true);
}

AddressSet FollowFlow::getFlowToAddressSet(TaskMonitor& monitor) {
    return getAddressFlow(monitor, *initialAddresses_, false);
}

AddressSet FollowFlow::getAddressFlow(TaskMonitor& monitor, const AddressSetView& startAddresses,
                                       bool forward) {
    AddressSet addressSet;
    AddressSet visitedAddrs;

    if (startAddresses.getNumAddresses() <= 0) {
        return addressSet;
    }

    std::stack<Address> workList;
    std::unique_ptr<AddressRangeIterator> rangeIter(startAddresses.getAddressRanges(true));
    while (rangeIter->hasNext()) {
        const AddressRange& range = rangeIter->next();
        Address addr = range.getMinAddress();
        Address end = range.getMaxAddress();
        while (addr.compareTo(end) <= 0) {
            workList.push(addr);
            addr = addr.add(1);
        }
    }

    while (!workList.empty() && !monitor.isCancelled()) {
        Address addr = workList.top();
        workList.pop();

        if (visitedAddrs.contains(addr)) {
            continue;
        }
        visitedAddrs.add(addr);

        Instruction* instr = program_->getListing()->getInstructionContaining(addr);
        if (instr != nullptr) {
            addressSet.addRange(instr->getAddress(), instr->getMaxAddress());

            if (forward) {
                followCode(workList, instr);
            } else {
                followCodeBack(workList, instr);
            }
            continue;
        }

        if (includeData_) {
            Data* data = program_->getListing()->getDataContaining(addr);
            if (data != nullptr) {
                addressSet.addRange(data->getAddress(), data->getMaxAddress());
            }
        }
    }

    return addressSet;
}

void FollowFlow::followCode(std::stack<Address>& workList, Instruction* instr) {
    const std::vector<Reference*>& refsFrom = instr->getReferencesFrom();
    for (Reference* ref : refsFrom) {
        if (ref == nullptr) continue;
        const FlowType* flowType = dynamic_cast<const FlowType*>(ref->getReferenceType());
        if (flowType != nullptr && shouldFollowFlow(flowType)) {
            workList.push(ref->getToAddress());
        }
    }

    Address fallThrough = instr->getFallThrough();
    if (fallThrough.isValid()) {
        workList.push(fallThrough);
    }
}

void FollowFlow::followCodeBack(std::stack<Address>& workList, Instruction* instr) {
    const std::vector<Reference*>& refsTo = instr->getReferencesTo();
    for (Reference* ref : refsTo) {
        if (ref == nullptr) continue;
        const FlowType* flowType = dynamic_cast<const FlowType*>(ref->getReferenceType());
        if (flowType != nullptr && shouldFollowFlow(flowType)) {
            workList.push(ref->getFromAddress());
        }
    }
}

bool FollowFlow::shouldFollowFlow(const FlowType* flowType) const {
    if (followAllFlow_) return true;
    if ((*flowType == RefTypes::COMPUTED_CALL && !followComputedCall_) ||
        (*flowType == RefTypes::COMPUTED_JUMP && !followComputedJump_) ||
        (*flowType == RefTypes::CONDITIONAL_JUMP && !followConditionalJump_) ||
        (*flowType == RefTypes::UNCONDITIONAL_JUMP && !followUnconditionalJump_) ||
        (*flowType == RefTypes::CONDITIONAL_CALL && !followConditionalCall_) ||
        (*flowType == RefTypes::UNCONDITIONAL_CALL && !followUnconditionalCall_) ||
        (*flowType == RefTypes::INDIRECTION && !followPointers_)) {
        return false;
    }
    return true;
}

} // namespace ghidra
