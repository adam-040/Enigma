/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/IsolatedEntrySubModel.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <list>
#include <memory>

namespace ghidra {

IsolatedEntrySubModel::IsolatedEntrySubModel(Program* program)
    : OverlapCodeSubModel(program) {
}

IsolatedEntrySubModel::IsolatedEntrySubModel(Program* program, bool includeExternals)
    : OverlapCodeSubModel(program, includeExternals) {
}

CodeBlock* IsolatedEntrySubModel::doGetSubroutine(Address mStartAddr, TaskMonitor& monitor) {
    CodeBlock* mSub = modelM_->getCodeBlockAt(mStartAddr, monitor);
    if (mSub == nullptr) {
        return nullptr;
    }

    Address* mEntryPts = mSub->getStartAddresses();
    std::vector<Address> startSet;
    if (mEntryPts != nullptr) {
        for (int i = 0; mEntryPts[i].isValid(); ++i) {
            if (!(mStartAddr == mEntryPts[i])) {
                startSet.push_back(mEntryPts[i]);
            }
        }
        delete[] mEntryPts;
    }

    AddressSet addrSet;
    std::list<Address> todoList;
    todoList.push_back(mStartAddr);

    Listing* listing = program_->getListing();
    if (listing == nullptr) {
        return nullptr;
    }

    while (!todoList.empty()) {
        if (monitor.isCancelled()) {
            throw CancelledException();
        }

        Address a = todoList.back();
        todoList.pop_back();

        if (addrSet.contains(a)) {
            continue;
        }

        bool isStart = false;
        for (const Address& sa : startSet) {
            if (a == sa) {
                isStart = true;
                break;
            }
        }
        if (isStart) {
            continue;
        }

        Instruction* instr = listing->getInstructionAt(a);
        if (instr == nullptr) {
            continue;
        }

        addrSet.addRange(instr->getAddress(), instr->getMaxAddress());

        // Follow fallthrough
        Address fallThrough = instr->getFallThrough();
        if (fallThrough.isValid()) {
            todoList.push_back(fallThrough);
        }

        // Follow jump and fallthrough references
        const auto& refs = instr->getReferencesFrom();
        for (Reference* ref : refs) {
            if (ref == nullptr) continue;
            const RefType* refType = ref->getReferenceType();
            if (refType != nullptr && (refType->isJump() || refType->isFallthrough())) {
                todoList.push_back(ref->getToAddress());
            }
        }
    }

    if (addrSet.isEmpty()) {
        return nullptr;
    }

    return createSub(&addrSet, mStartAddr);
}

} // namespace ghidra
