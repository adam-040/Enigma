/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SubroutineDestReferenceIterator.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>

namespace ghidra {

SubroutineDestReferenceIterator::SubroutineDestReferenceIterator(CodeBlock* block, TaskMonitor& monitor) {
    if (block == nullptr || !block->getMinAddress().isValid()) {
        return;
    }

    CodeBlockModel* model = block->getModel();
    if (model == nullptr) {
        return;
    }

    bool includeExternals = model->externalsIncluded();
    CodeBlockModel* bbModel = model->getBasicBlockModel();
    if (bbModel == nullptr) {
        return;
    }

    CodeBlockIterator bblockIter = bbModel->getCodeBlocksContaining(block, monitor);
    while (bblockIter.hasNext()) {
        CodeBlock* bblock = bblockIter.next();
        if (bblock == nullptr) {
            continue;
        }

        std::unique_ptr<CodeBlockReferenceIterator> bbDestIter(
            bblock->getDestinations(monitor));
        while (bbDestIter->hasNext()) {
            CodeBlockReference* bbDestRef = bbDestIter->next();
            if (bbDestRef == nullptr) {
                continue;
            }

            const FlowType* refFlowType = static_cast<const FlowType*>(bbDestRef->getFlowType());
            if (refFlowType == nullptr) {
                continue;
            }

            Address destAddr = bbDestRef->getReference();
            bool addBlockRef = false;

            if (destAddr.isExternalAddress()) {
                if (includeExternals) {
                    addBlockRef = true;
                }
            }
            else if (refFlowType->isCall()) {
                addBlockRef = true;
            }
            else if (refFlowType->isJump() || refFlowType->isFallthrough()) {
                if (!block->contains(destAddr)) {
                    addBlockRef = true;
                }
            }

            if (addBlockRef) {
                refs_.push_back(new CodeBlockReferenceImpl(
                    block, nullptr, refFlowType, destAddr,
                    bbDestRef->getReferent()));
            }
        }
    }
}

int SubroutineDestReferenceIterator::getNumDestinations(CodeBlock* block, TaskMonitor& monitor) {
    if (block == nullptr || !block->getMinAddress().isValid()) {
        return 0;
    }

    CodeBlockModel* model = block->getModel();
    if (model == nullptr) {
        return 0;
    }

    bool includeExternals = model->externalsIncluded();
    CodeBlockModel* bbModel = model->getBasicBlockModel();
    if (bbModel == nullptr) {
        return 0;
    }

    int count = 0;
    CodeBlockIterator bblockIter = bbModel->getCodeBlocksContaining(block, monitor);
    while (bblockIter.hasNext()) {
        CodeBlock* bblock = bblockIter.next();
        if (bblock == nullptr) {
            continue;
        }

        std::unique_ptr<CodeBlockReferenceIterator> bbDestIter(
            bblock->getDestinations(monitor));
        while (bbDestIter->hasNext()) {
            CodeBlockReference* bbDestRef = bbDestIter->next();
            if (bbDestRef == nullptr) {
                continue;
            }

            const FlowType* refFlowType = static_cast<const FlowType*>(bbDestRef->getFlowType());
            if (refFlowType == nullptr) {
                continue;
            }

            Address destAddr = bbDestRef->getReference();
            if (destAddr.isExternalAddress()) {
                if (includeExternals) {
                    ++count;
                }
            }
            else if (refFlowType->isCall()) {
                ++count;
            }
            else if (refFlowType->isJump() || refFlowType->isFallthrough()) {
                if (!block->contains(destAddr)) {
                    ++count;
                }
            }
        }
    }
    return count;
}

} // namespace ghidra
