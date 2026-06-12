/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SimpleDestReferenceIterator.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/SimpleBlockModel.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/RefType.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Listing.h>
#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>

namespace ghidra {

SimpleDestReferenceIterator::SimpleDestReferenceIterator(CodeBlock* block,
                                                         bool followIndirectFlows,
                                                         TaskMonitor& monitor) {
    getDestinations(block, &refs_, followIndirectFlows, monitor);
}

int SimpleDestReferenceIterator::getNumDestinations(CodeBlock* block, bool followIndirectFlows,
                                                     TaskMonitor& monitor) {
    return getDestinations(block, nullptr, followIndirectFlows, monitor);
}

int SimpleDestReferenceIterator::getDestinations(CodeBlock* block,
                                                 std::vector<CodeBlockReference*>* refQueue,
                                                 bool followIndirectFlows,
                                                 TaskMonitor& monitor) {
    if (block == nullptr) return 0;

    CodeBlockModel* m = block->getModel()->getBasicBlockModel();
    SimpleBlockModel* model = dynamic_cast<SimpleBlockModel*>(m);
    if (model == nullptr) return 0;

    bool includeExternals = model->externalsIncluded();

    Address start = block->getMinAddress();
    Address end = block->getMaxAddress();
    if (!start.isValid() || start.isExternalAddress()) return 0;

    int count = 0;
    Listing* listing = model->getProgram()->getListing();
    std::vector<Reference*> allRefs = model->getProgram()->getReferenceManager()->getReferenceIterator(start);
    Instruction* instr = nullptr;

    for (auto* ref : allRefs) {
        if (monitor.isCancelled()) return count;

        Address fromAddr = ref->getFromAddress();
        if (fromAddr.compareTo(end) > 0) break;

        const RefType* refType = ref->getReferenceType();
        if (!refType->isFlow()) continue;

        // Handle possible indirection
        if (refType == &RefTypes::INDIRECTION) {
            Instruction* destInstr = listing->getInstructionContaining(ref->getToAddress());
            int cnt = 0;
            if (destInstr == nullptr && followIndirectFlows) {
                if (instr == nullptr || !(instr->getAddress() == fromAddr)) {
                    instr = listing->getInstructionAt(fromAddr);
                }
                const FlowType* flowType = (instr && instr->getFlowType())
                    ? (instr->getFlowType()->isCall() ? &RefTypes::COMPUTED_CALL : &RefTypes::COMPUTED_JUMP)
                    : &RefTypes::INDIRECTION;
                cnt = followIndirection(block, refQueue, ref, flowType, includeExternals, monitor);
            }
            if (cnt == 0) {
                queueReference(refQueue, block, fromAddr, ref->getToAddress(), &RefTypes::INDIRECTION);
                cnt = 1;
            }
            count += cnt;
        }
        // Handle other FlowType reference
        else {
            queueReference(refQueue, block, fromAddr, ref->getToAddress(),
                           static_cast<const FlowType*>(refType));
            ++count;
        }
    }

    // Check for single fall-through destination
    instr = listing->getInstructionContaining(end);
    if (instr != nullptr) {
        instr = instr->getNext();
        if (instr != nullptr) {
            Address addr = instr->getFallFrom();
            if (addr.isValid() && addr.compareTo(end) <= 0) {
                queueReference(refQueue, block, addr, instr->getAddress(), &RefTypes::FALL_THROUGH);
                ++count;
            }
        }
    }

    return count;
}

int SimpleDestReferenceIterator::followIndirection(
    CodeBlock* srcBlock, std::vector<CodeBlockReference*>* refQueue,
    Reference* srcRef, const FlowType* indirectFlowType,
    bool includeExternals, TaskMonitor& monitor) {

    SimpleBlockModel* model = dynamic_cast<SimpleBlockModel*>(srcBlock->getModel());
    if (model == nullptr) return 0;

    Address addr = srcRef->getToAddress();
    Listing* listing = model->getProgram()->getListing();
    Data* data = listing->getDefinedDataContaining(addr);
    if (data == nullptr) return 0;

    int cnt = 0;
    int offset = static_cast<int>(addr.subtract(data->getAddress()));
    Data* primitive = data->getPrimitiveAt(offset);
    if (primitive != nullptr) {
        const std::vector<Reference*>& refs = primitive->getReferencesFrom();
        for (auto* r : refs) {
            if (monitor.isCancelled()) return cnt;

            CodeBlock* destBlock = nullptr;

            Address toAddr = r->getToAddress();
            if (toAddr.isMemoryAddress()) {
                CodeUnit* cu = listing->getCodeUnitAt(toAddr);
                if (cu != nullptr) {
                    if (dynamic_cast<Instruction*>(cu) != nullptr) {
                        if (refQueue != nullptr) {
                            destBlock = model->getFirstCodeBlockContaining(toAddr, monitor);
                        }
                    }
                    else if (dynamic_cast<Data*>(cu) != nullptr &&
                             static_cast<Data*>(cu)->isDefined()) {
                        continue;
                    }
                }
            }
            else if (toAddr.isExternalAddress()) {
                if (!includeExternals) continue;
                if (refQueue != nullptr) {
                    destBlock = model->getFirstCodeBlockContaining(toAddr, monitor);
                }
            }

            if (refQueue != nullptr) {
                if (destBlock == nullptr) {
                    destBlock = createSimpleDataBlock(model, toAddr);
                }
                refQueue->push_back(new CodeBlockReferenceImpl(
                    srcBlock, destBlock, indirectFlowType, toAddr, srcRef->getFromAddress()));
            }
            ++cnt;
        }
    }
    return cnt;
}

void SimpleDestReferenceIterator::queueReference(
    std::vector<CodeBlockReference*>* refQueue,
    CodeBlock* srcBlock, Address fromAddr, Address toAddr,
    const FlowType* flowType) {

    if (refQueue == nullptr) return;
    refQueue->push_back(new CodeBlockReferenceImpl(srcBlock, nullptr, flowType, toAddr, fromAddr));
}

CodeBlockImpl* SimpleDestReferenceIterator::createSimpleDataBlock(SimpleBlockModel* model,
                                                                   Address addr) {
    auto* db = new CodeBlockImpl(model, model->getProgram(), "data",
                                 AddressSet(addr, addr));
    db->addStartAddress(addr);
    return db;
}

} // namespace ghidra
