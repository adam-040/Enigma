/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/PartitionCodeSubModel.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/SubroutineSourceReferenceIterator.h>
#include <ghidra/block/SubroutineDestReferenceIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>

namespace ghidra {

PartitionCodeSubModel::PartitionCodeSubModel(Program* program)
    : OverlapCodeSubModel(program) {
}

PartitionCodeSubModel::PartitionCodeSubModel(Program* program, bool includeExternals)
    : OverlapCodeSubModel(program, includeExternals) {
}

CodeBlock* PartitionCodeSubModel::getSubroutine(Address addr, TaskMonitor& monitor) {
    return OverlapCodeSubModel::getSubroutine(addr, monitor);
}

CodeBlockIterator PartitionCodeSubModel::getSubroutines(TaskMonitor& monitor) {
    return OverlapCodeSubModel::getSubroutines(monitor);
}

CodeBlockIterator PartitionCodeSubModel::getDestinations(CodeBlock* block, TaskMonitor& monitor) {
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

CodeBlockIterator PartitionCodeSubModel::getSources(CodeBlock* block, TaskMonitor& monitor) {
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

int PartitionCodeSubModel::getNumDestinations(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineDestReferenceIterator::getNumDestinations(block, monitor);
}

int PartitionCodeSubModel::getNumSources(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineSourceReferenceIterator::getNumSources(block, monitor);
}

CodeBlock* PartitionCodeSubModel::doGetSubroutine(Address mStartAddr, TaskMonitor& monitor) {
    return OverlapCodeSubModel::doGetSubroutine(mStartAddr, monitor);
}

CodeBlock* PartitionCodeSubModel::findSubroutine(Address addr, TaskMonitor& monitor) {
    return getSubroutine(addr, monitor);
}

} // namespace ghidra
