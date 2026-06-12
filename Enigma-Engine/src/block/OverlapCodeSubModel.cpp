/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/OverlapCodeSubModel.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/block/SubroutineSourceReferenceIterator.h>
#include <ghidra/block/SubroutineDestReferenceIterator.h>
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

OverlapCodeSubModel::OverlapCodeSubModel(Program* program)
    : MultEntSubModel(program) {
    listing_ = program_->getListing();
    modelM_ = new MultEntSubModel(program);
}

OverlapCodeSubModel::OverlapCodeSubModel(Program* program, bool includeExternals)
    : MultEntSubModel(program, includeExternals) {
    listing_ = program_->getListing();
    modelM_ = new MultEntSubModel(program, includeExternals);
}

CodeBlock* OverlapCodeSubModel::findSubroutine(Address addr, TaskMonitor& monitor) {
    return getSubroutine(addr, monitor);
}

CodeBlock* OverlapCodeSubModel::getSubroutine(Address addr, TaskMonitor& monitor) {
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        CodeBlock* cached = subCache_.getFirstCodeBlockContaining(addr);
        if (cached != nullptr) {
            return cached;
        }
    }

    CodeBlock* mSub = modelM_->getFirstCodeBlockContaining(addr, monitor);
    if (mSub == nullptr) {
        return nullptr;
    }

    Address mStartAddr = mSub->getFirstStartAddress();
    CodeBlock* sub = doGetSubroutine(mStartAddr, monitor);

    if (sub != nullptr) {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        AddressSetView* subSet = sub->getAddressSet();
        if (subSet != nullptr) {
            subCache_.addCodeBlock(sub, *subSet);
        }
    }

    return sub;
}

CodeBlock* OverlapCodeSubModel::doGetSubroutine(Address mStartAddr, TaskMonitor& monitor) {
    AddressSet addrSet;
    std::list<Address> todoList;
    todoList.push_back(mStartAddr);

    while (!todoList.empty()) {
        if (monitor.isCancelled()) {
            throw CancelledException();
        }

        Address a = todoList.back();
        todoList.pop_back();

        if (addrSet.contains(a)) {
            continue;
        }

        Instruction* instr = listing_->getInstructionAt(a);
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

CodeBlockIterator OverlapCodeSubModel::getSubroutines(TaskMonitor& monitor) {
    return MultEntSubModel::getSubroutines(monitor);
}

CodeBlockIterator OverlapCodeSubModel::getDestinations(CodeBlock* block, TaskMonitor& monitor) {
    std::vector<CodeBlock*> results;
    SubroutineDestReferenceIterator iter(block, monitor);
    while (iter.hasNext()) {
        CodeBlockReference* ref = iter.next();
        if (ref != nullptr) {
            CodeBlock* destBlock = ref->getDestinationBlock();
            if (destBlock != nullptr) {
                results.push_back(destBlock);
            }
        }
    }
    return CodeBlockIterator(results);
}

CodeBlockIterator OverlapCodeSubModel::getSources(CodeBlock* block, TaskMonitor& monitor) {
    std::vector<CodeBlock*> results;
    SubroutineSourceReferenceIterator iter(block, monitor);
    while (iter.hasNext()) {
        CodeBlockReference* ref = iter.next();
        if (ref != nullptr) {
            CodeBlock* srcBlock = ref->getSourceBlock();
            if (srcBlock != nullptr) {
                results.push_back(srcBlock);
            }
        }
    }
    return CodeBlockIterator(results);
}

int OverlapCodeSubModel::getNumDestinations(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineDestReferenceIterator::getNumDestinations(block, monitor);
}

int OverlapCodeSubModel::getNumSources(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineSourceReferenceIterator::getNumSources(block, monitor);
}

CodeBlock* OverlapCodeSubModel::createSub(AddressSet* addrSet, Address entryAddr) {
    CodeBlockImpl* block = new CodeBlockImpl(this, program_, "overlap_sub", *addrSet);
    block->addStartAddress(entryAddr);
    return block;
}

} // namespace ghidra
