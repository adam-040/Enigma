/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SimpleSourceReferenceIterator.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/SimpleBlockModel.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/Listing.h>
#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>

namespace ghidra {

SimpleSourceReferenceIterator::SimpleSourceReferenceIterator(CodeBlock* block,
                                                             bool followIndirectFlows,
                                                             TaskMonitor& monitor) {
    getSources(block, &refs_, followIndirectFlows, monitor);
}

int SimpleSourceReferenceIterator::getNumSources(CodeBlock* block, bool followIndirectFlows,
                                                  TaskMonitor& monitor) {
    return getSources(block, nullptr, followIndirectFlows, monitor);
}

int SimpleSourceReferenceIterator::getSources(CodeBlock* block,
                                              std::vector<CodeBlockReference*>* refQueue,
                                              bool followIndirectFlows, TaskMonitor& monitor) {
    if (block == nullptr) {
        return 0;
    }

    CodeBlockModel* m = block->getModel();
    SimpleBlockModel* model = dynamic_cast<SimpleBlockModel*>(m);
    if (model == nullptr) {
        return 0;
    }

    Address start = block->getMinAddress();
    if (!start.isValid()) {
        return 0;
    }

    int count = 0;
    Listing* listing = model->getProgram()->getListing();
    Instruction* instr = listing->getInstructionAt(start);
    ReferenceManager* refMgr = model->getProgram()->getReferenceManager();

    // Check references to all entry points
    Address* entryPts = block->getStartAddresses();
    int numEntryPts = 0;
    if (entryPts != nullptr) {
        while (entryPts[numEntryPts].isValid()) {
            ++numEntryPts;
        }
    }

    for (int n = 0; n < numEntryPts; n++) {
        std::vector<Reference*> refs = refMgr->getReferencesTo(entryPts[n]);
        for (auto* ref : refs) {
            if (monitor.isCancelled()) {
                delete[] entryPts;
                return count;
            }

            const RefType* refType = ref->getReferenceType();

            // Handle FlowType reference
            if (refType->isFlow()) {
                queueReference(refQueue, block, entryPts[n],
                               ref->getFromAddress(),
                               static_cast<const FlowType*>(refType));
                ++count;
            }
            // Handle possible indirection
            else if (followIndirectFlows && (instr != nullptr || start.isExternalAddress())) {
                int cnt = followIndirection(block, refQueue, ref, monitor);
                count += cnt;
            }
        }
    }
    delete[] entryPts;

    // Get single fall-from address for instruction block
    if (instr != nullptr) {
        Address fallAddr = instr->getFallFrom();
        if (fallAddr.isValid()) {
            queueReference(refQueue, block, start, fallAddr, &RefTypes::FALL_THROUGH);
            ++count;
        }
    }

    return count;
}

int SimpleSourceReferenceIterator::followIndirection(
    CodeBlock* destBlock, std::vector<CodeBlockReference*>* refQueue,
    Reference* destRef, TaskMonitor& monitor) {

    SimpleBlockModel* model = dynamic_cast<SimpleBlockModel*>(destBlock->getModel());
    if (model == nullptr) return 0;

    Address addr = destRef->getFromAddress();
    Listing* listing = model->getProgram()->getListing();
    Data* data = listing->getDefinedDataContaining(addr);
    if (data == nullptr) return 0;

    int cnt = 0;
    int offset = static_cast<int>(addr.subtract(data->getAddress()));
    Data* primitive = data->getPrimitiveAt(offset);
    if (primitive != nullptr) {
        const std::vector<Reference*>& refs = primitive->getReferencesTo();
        for (auto* ref : refs) {
            if (monitor.isCancelled()) return cnt;

            const RefType* rt = ref->getReferenceType();
            if (rt != &RefTypes::INDIRECTION && rt != &RefTypes::READ) continue;

            Address fromAddr = ref->getFromAddress();
            Instruction* instr = listing->getInstructionAt(fromAddr);
            if (instr == nullptr) continue;

            if (rt == &RefTypes::READ && !instr->getFlowType()->isComputed()) continue;

            queueReference(refQueue, destBlock, destRef->getToAddress(), fromAddr,
                           instr->getFlowType()->isCall() ? &RefTypes::COMPUTED_CALL
                                                           : &RefTypes::COMPUTED_JUMP);
            ++cnt;
        }
    }
    return cnt;
}

void SimpleSourceReferenceIterator::queueReference(
    std::vector<CodeBlockReference*>* refQueue,
    CodeBlock* destBlock, Address toAddr, Address fromAddr,
    const FlowType* flowType) {

    if (refQueue == nullptr) return;

    refQueue->push_back(new CodeBlockReferenceImpl(nullptr, destBlock, flowType, toAddr, fromAddr));
}

} // namespace ghidra
