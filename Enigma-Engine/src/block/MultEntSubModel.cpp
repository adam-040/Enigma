/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/MultEntSubModel.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/block/SubroutineSourceReferenceIterator.h>
#include <ghidra/block/SubroutineDestReferenceIterator.h>
#include <ghidra/block/MultEntSubIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <list>
#include <memory>
#include <algorithm>

namespace ghidra {

MultEntSubModel::MultEntSubModel(Program* program)
    : program_(program) {
    basicBlockModel_ = nullptr;
}

MultEntSubModel::MultEntSubModel(Program* program, bool includeExternals)
    : program_(program), includeExternals_(includeExternals) {
    basicBlockModel_ = nullptr;
}

int MultEntSubModel::getCodeBlockCount() const {
    return foundSubs_.size();
}

CodeBlock* MultEntSubModel::getCodeBlockAt(Address addr, TaskMonitor& monitor) {
    if (!addr.isValid()) {
        return nullptr;
    }
    CodeBlock* block = getSubFromCache(addr);
    if (block == nullptr) {
        block = findSubroutine(addr, monitor);
    }
    if (block != nullptr) {
        Address* entPts = block->getStartAddresses();
        if (entPts != nullptr) {
            for (int i = 0; entPts[i].isValid(); ++i) {
                if (addr == entPts[i]) {
                    delete[] entPts;
                    return block;
                }
            }
            delete[] entPts;
        }
    }
    return nullptr;
}

CodeBlock* MultEntSubModel::getFirstCodeBlockContaining(Address addr, TaskMonitor& monitor) {
    CodeBlock* block = getSubFromCache(addr);
    if (block == nullptr) {
        block = findSubroutine(addr, monitor);
    }
    return block;
}

CodeBlock* MultEntSubModel::getCodeBlockContaining(Address addr, TaskMonitor& monitor) {
    return getFirstCodeBlockContaining(addr, monitor);
}

CodeBlockIterator MultEntSubModel::getCodeBlocksContaining(Address addr, TaskMonitor& monitor) {
    std::vector<CodeBlock*> blocks;
    CodeBlock* block = findSubroutine(addr, monitor);
    if (block != nullptr) {
        blocks.push_back(block);
    }
    return MultEntSubIterator(blocks);
}

CodeBlockIterator MultEntSubModel::getCodeBlocksContaining(CodeBlock* block, TaskMonitor& monitor) {
    (void)block;
    (void)monitor;
    return CodeBlockIterator();
}

CodeBlockIterator MultEntSubModel::getCodeBlocksContaining(const AddressSetView& addrSet,
                                                             TaskMonitor& monitor) {
    std::vector<CodeBlock*> blocks;
    std::unique_ptr<AddressRangeIterator> iter(addrSet.getAddressRanges());
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Address end = range.getMaxAddress();
        while (addr.compareTo(end) <= 0) {
            CodeBlock* block = findSubroutine(addr, monitor);
            if (block != nullptr) {
                if (std::find(blocks.begin(), blocks.end(), block) == blocks.end()) {
                    blocks.push_back(block);
                }
            }
            addr = addr.add(1);
        }
    }
    return MultEntSubIterator(blocks);
}

CodeBlock** MultEntSubModel::getCodeBlocksContaining(Address addr, TaskMonitor& monitor, int& count) {
    CodeBlock* block = findSubroutine(addr, monitor);
    if (block == nullptr) {
        count = 0;
        return nullptr;
    }
    count = 1;
    CodeBlock** arr = new CodeBlock*[1];
    arr[0] = block;
    return arr;
}

CodeBlockIterator MultEntSubModel::getCodeBlocks(TaskMonitor& monitor) {
    return getSubroutines(monitor);
}

CodeBlockIterator MultEntSubModel::getDestinations(CodeBlock* block, TaskMonitor& monitor) {
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

CodeBlockIterator MultEntSubModel::getSources(CodeBlock* block, TaskMonitor& monitor) {
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

int MultEntSubModel::getNumDestinations(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineDestReferenceIterator::getNumDestinations(block, monitor);
}

int MultEntSubModel::getNumSources(CodeBlock* block, TaskMonitor& monitor) {
    return SubroutineSourceReferenceIterator::getNumSources(block, monitor);
}

CodeBlockModel* MultEntSubModel::getBasicBlockModel() const {
    return basicBlockModel_;
}

AddressSet* MultEntSubModel::getAddressSet() const {
    return new AddressSet();
}

CodeBlock* MultEntSubModel::createBlock(CodeBlock* parent, Address start) {
    (void)parent;
    return new CodeBlockImpl(this, program_, "sub", AddressSet(start, start));
}

CodeBlock* MultEntSubModel::findSubroutine(Address addr, TaskMonitor& monitor) {
    CodeBlock* cached = getSubFromCache(addr);
    if (cached != nullptr) {
        return cached;
    }

    if (addr.isExternalAddress()) {
        return nullptr;
    }

    Listing* listing = program_->getListing();
    if (listing == nullptr) {
        return nullptr;
    }
    ReferenceManager* refMgr = program_->getReferenceManager();

    AddressSet addrSet;
    std::list<Address> todoList;
    std::list<Address> processedOrigins;
    std::vector<Address> entryPtList;
    todoList.push_back(addr);

    while (!todoList.empty() || !processedOrigins.empty()) {
        if (monitor.isCancelled()) {
            throw CancelledException();
        }

        // When forward queue is empty, process backward flow from collected blocks
        if (todoList.empty()) {
            while (todoList.empty() && !processedOrigins.empty()) {
                Address originAddr = processedOrigins.front();
                processedOrigins.pop_front();

                bool isSource = true;
                bool isEntry = false;

                std::vector<Reference*> refsTo = refMgr->getReferencesTo(originAddr);
                for (Reference* ref : refsTo) {
                    if (ref == nullptr) continue;
                    isSource = false;
                    const RefType* refType = ref->getReferenceType();
                    if (refType->isJump() || refType->isFallthrough()) {
                        todoList.push_back(ref->getFromAddress());
                    } else if (refType->isCall()) {
                        isEntry = true;
                    }
                }

                if (isSource || isEntry) {
                    entryPtList.push_back(originAddr);
                }
            }
            continue;
        }

        Address a = todoList.front();
        todoList.pop_front();

        if (addrSet.contains(a)) {
            continue;
        }

        Instruction* instr = listing->getInstructionAt(a);
        if (instr == nullptr) {
            continue;
        }

        addrSet.addRange(instr->getAddress(), instr->getMaxAddress());
        processedOrigins.push_back(a);

        // Follow fallthrough
        Address fallThrough = instr->getFallThrough();
        if (fallThrough.isValid()) {
            todoList.push_back(fallThrough);
        }

        // Follow jump references
        const std::vector<Reference*>& refs = instr->getReferencesFrom();
        for (Reference* ref : refs) {
            if (ref == nullptr) continue;
            const RefType* refType = ref->getReferenceType();
            if (refType != nullptr && refType->isJump()) {
                todoList.push_back(ref->getToAddress());
            }
        }
    }

    if (addrSet.isEmpty()) {
        return nullptr;
    }

    if (entryPtList.empty()) {
        entryPtList.push_back(addrSet.getMinAddress());
    }

    CodeBlockImpl* block = new CodeBlockImpl(this, program_, "MSub", addrSet);
    for (const Address& ep : entryPtList) {
        block->addStartAddress(ep);
    }
    foundSubs_.addCodeBlock(block, addrSet);
    return block;
}

CodeBlock* MultEntSubModel::createSub(AddressSet* addrSet, Address entryAddr) {
    CodeBlockImpl* block = new CodeBlockImpl(this, program_, "sub", *addrSet);
    block->addStartAddress(entryAddr);
    return block;
}

CodeBlock* MultEntSubModel::getSubroutine(Address addr, TaskMonitor& monitor) {
    return findSubroutine(addr, monitor);
}

CodeBlockIterator MultEntSubModel::getSubroutines(TaskMonitor& monitor) {
    Listing* listing = program_->getListing();
    Memory* memory = program_->getMemory();
    if (listing == nullptr || memory == nullptr) {
        return CodeBlockIterator();
    }

    // Build AddressSet from all memory blocks
    AddressSet fullSet;
    std::vector<MemoryBlock*> blocks = memory->getBlocks();
    for (MemoryBlock* block : blocks) {
        if (block != nullptr) {
            fullSet.addRange(block->getStart(), block->getEnd());
        }
    }

    return getSubroutines(fullSet, monitor);
}

CodeBlockIterator MultEntSubModel::getSubroutines(const AddressSetView& addrSet, TaskMonitor& monitor) {
    std::vector<CodeBlock*> subs;
    AddressSet covered;

    Listing* listing = program_->getListing();
    if (listing == nullptr) {
        return CodeBlockIterator(subs);
    }

    std::vector<Instruction*> instrs = listing->getInstructions(addrSet);
    for (Instruction* instr : instrs) {
        if (monitor.isCancelled()) {
            throw CancelledException();
        }
        if (instr == nullptr) continue;

        Address addr = instr->getAddress();
        if (covered.contains(addr)) {
            continue;
        }

        CodeBlock* sub = findSubroutine(addr, monitor);
        if (sub != nullptr) {
            AddressSetView* subSet = sub->getAddressSet();
            if (subSet != nullptr) {
                covered.add(*subSet);
            }
            if (std::find(subs.begin(), subs.end(), sub) == subs.end()) {
                subs.push_back(sub);
            }
        }
    }

    return MultEntSubIterator(subs);
}

CodeBlock* MultEntSubModel::getSubFromCache(const Address& addr) {
    return foundSubs_.getFirstCodeBlockContaining(addr);
}

} // namespace ghidra
