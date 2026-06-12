/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SimpleBlockModel.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/SimpleBlockIterator.h>
#include <ghidra/block/SimpleSourceReferenceIterator.h>
#include <ghidra/block/SimpleDestReferenceIterator.h>
#include <ghidra/block/SubroutineSourceReferenceIterator.h>
#include <ghidra/block/SubroutineDestReferenceIterator.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Program.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <algorithm>

namespace ghidra {

SimpleBlockModel::SimpleBlockModel(Program* program, const std::string& name)
    : program_(program), name_(name) {
}

SimpleBlockModel::SimpleBlockModel(Program* program, const std::string& name, bool overlapAllowed)
    : program_(program), name_(name), overlapAllowed_(overlapAllowed) {
}

CodeBlock* SimpleBlockModel::createNewBlock(CodeBlockModel* model, Program* program,
                                             const std::string& name,
                                             const AddressSetView& addrSet) const {
    return new CodeBlockImpl(model, program, name, addrSet);
}

CodeBlock* SimpleBlockModel::getCodeBlockAt(Address addr, TaskMonitor& monitor) {
    return cache_.getFirstCodeBlockContaining(addr);
}

CodeBlock* SimpleBlockModel::getFirstCodeBlockContaining(Address addr, TaskMonitor& monitor) {
    return cache_.getFirstCodeBlockContaining(addr);
}

CodeBlock* SimpleBlockModel::getCodeBlockContaining(Address addr, TaskMonitor& monitor) {
    return cache_.getFirstCodeBlockContaining(addr);
}

CodeBlockIterator SimpleBlockModel::getCodeBlocksContaining(Address addr, TaskMonitor& monitor) {
    std::vector<CodeBlock*> blocks = cache_.getCodeBlocksContaining(addr);
    return SimpleBlockIterator(this, blocks);
}

CodeBlockIterator SimpleBlockModel::getCodeBlocksContaining(CodeBlock* block, TaskMonitor& monitor) {
    if (block == nullptr) {
        return CodeBlockIterator();
    }
    Address minAddr = block->getMinAddress();
    if (!minAddr.isValid()) {
        return CodeBlockIterator();
    }
    return getCodeBlocksContaining(minAddr, monitor);
}

CodeBlockIterator SimpleBlockModel::getCodeBlocksContaining(const AddressSetView& addrSet,
                                                             TaskMonitor& monitor) {
    std::vector<CodeBlock*> allBlocks;
    AddressSet covered;
    std::unique_ptr<AddressRangeIterator> iter(addrSet.getAddressRanges());
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Address end = range.getMaxAddress();
        while (addr.compareTo(end) <= 0) {
            if (covered.contains(addr)) {
                addr = addr.add(1);
                continue;
            }
            CodeBlock* block = cache_.getFirstCodeBlockContaining(addr);
            if (block != nullptr) {
                AddressSetView* blockSet = block->getAddressSet();
                if (blockSet != nullptr) {
                    covered.add(*blockSet);
                }
                if (std::find(allBlocks.begin(), allBlocks.end(), block) == allBlocks.end()) {
                    allBlocks.push_back(block);
                }
            }
            addr = addr.add(1);
        }
    }
    return SimpleBlockIterator(this, allBlocks);
}

CodeBlock** SimpleBlockModel::getCodeBlocksContaining(Address addr, TaskMonitor& monitor, int& count) {
    std::vector<CodeBlock*> blocks = cache_.getCodeBlocksContaining(addr);
    count = static_cast<int>(blocks.size());
    if (count == 0) {
        return nullptr;
    }
    CodeBlock** arr = new CodeBlock*[count];
    for (int i = 0; i < count; ++i) {
        arr[i] = blocks[i];
    }
    return arr;
}

CodeBlockIterator SimpleBlockModel::getCodeBlocks(TaskMonitor& monitor) {
    std::vector<CodeBlock*> allBlocks;
    for (auto& entry : cache_.getBlockMap()) {
        allBlocks.push_back(entry.first);
    }
    return SimpleBlockIterator(this, allBlocks);
}

CodeBlock* SimpleBlockModel::createSimpleDataBlock(Address start, Address end) {
    return new CodeBlockImpl(this, program_, "DATA", AddressSet(start, end));
}

bool SimpleBlockModel::hasEndOfBlockFlow(Instruction* instr) {
    FlowType* flowType = instr->getFlowType();
    if (flowType == nullptr) {
        return false;
    }
    if (*flowType == RefTypes::FALL_THROUGH) {
        return false;
    }
    if (*flowType == RefTypes::COMPUTED_JUMP) {
        return false;
    }
    if (*flowType == RefTypes::CALL_TERMINATOR) {
        return false;
    }
    return flowType->isCall() || flowType->isJump();
}

CodeBlockIterator SimpleBlockModel::getDestinations(CodeBlock* block, TaskMonitor& monitor) {
    SimpleDestReferenceIterator refIter(block, true, monitor);
    std::vector<CodeBlock*> destBlocks;
    while (refIter.hasNext()) {
        CodeBlockReference* ref = refIter.next();
        CodeBlock* dest = ref->getDestinationBlock();
        if (dest != nullptr &&
            std::find(destBlocks.begin(), destBlocks.end(), dest) == destBlocks.end()) {
            destBlocks.push_back(dest);
        }
    }
    return CodeBlockIterator(destBlocks);
}

CodeBlockIterator SimpleBlockModel::getSources(CodeBlock* block, TaskMonitor& monitor) {
    SimpleSourceReferenceIterator refIter(block, true, monitor);
    std::vector<CodeBlock*> srcBlocks;
    while (refIter.hasNext()) {
        CodeBlockReference* ref = refIter.next();
        CodeBlock* src = ref->getSourceBlock();
        if (src != nullptr &&
            std::find(srcBlocks.begin(), srcBlocks.end(), src) == srcBlocks.end()) {
            srcBlocks.push_back(src);
        }
    }
    return CodeBlockIterator(srcBlocks);
}

int SimpleBlockModel::getNumDestinations(CodeBlock* block, TaskMonitor& monitor) {
    return SimpleDestReferenceIterator::getNumDestinations(block, true, monitor);
}

int SimpleBlockModel::getNumSources(CodeBlock* block, TaskMonitor& monitor) {
    return SimpleSourceReferenceIterator::getNumSources(block, true, monitor);
}

AddressSet* SimpleBlockModel::getAddressSet() const {
    AddressSet* result = new AddressSet();
    for (auto& entry : cache_.getBlockMap()) {
        result->add(entry.second);
    }
    return result;
}

CodeBlock* SimpleBlockModel::createBlock(CodeBlock* parent, Address start) {
    (void)parent;
    return new CodeBlockImpl(this, program_, "unnamed", AddressSet(start, start));
}

void SimpleBlockModel::addBlock(CodeBlock* block, const AddressSetView& addrSet) {
    cache_.addCodeBlock(block, addrSet);
}

void SimpleBlockModel::removeBlock(CodeBlock* block) {
    cache_.removeCodeBlock(block);
}

void SimpleBlockModel::clearCache() {
    cache_.clear();
}

} // namespace ghidra
