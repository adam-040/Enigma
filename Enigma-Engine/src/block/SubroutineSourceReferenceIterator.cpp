/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SubroutineSourceReferenceIterator.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <memory>

namespace ghidra {

static int queueSrcReferences(std::vector<CodeBlockReference*>& blockRefQueue,
                              CodeBlock* destBlock, const Address& destAddr,
                              const Address& srcAddr, const FlowType* flowType,
                              TaskMonitor& monitor);

SubroutineSourceReferenceIterator::SubroutineSourceReferenceIterator(CodeBlock* block, TaskMonitor& monitor) {
    if (block == nullptr || !block->getMinAddress().isValid()) {
        return;
    }

    CodeBlockModel* model = block->getModel();
    if (model == nullptr) {
        return;
    }

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

        std::unique_ptr<CodeBlockReferenceIterator> bbSrcIter(
            bblock->getSources(monitor));
        while (bbSrcIter->hasNext()) {
            CodeBlockReference* bbSrcRef = bbSrcIter->next();
            if (bbSrcRef == nullptr) {
                continue;
            }

            const FlowType* refFlowType = dynamic_cast<const FlowType*>(bbSrcRef->getFlowType());
            if (refFlowType == nullptr) {
                continue;
            }

            if (refFlowType->isCall()) {
                queueSrcReferences(refs_, block,
                    bbSrcRef->getReference(), bbSrcRef->getReferent(),
                    refFlowType, monitor);
            }
            else if (refFlowType->isJump() || refFlowType->isFallthrough()) {
                Address srcAddr = bbSrcRef->getReferent();
                if (!block->contains(srcAddr)) {
                    CodeBlock* srcBlock = model->getFirstCodeBlockContaining(srcAddr, monitor);
                    if (srcBlock != nullptr) {
                        queueSrcReferences(refs_, block,
                            bbSrcRef->getReference(), srcAddr,
                            refFlowType, monitor);
                    }
                }
            }
        }
    }
}

int SubroutineSourceReferenceIterator::getNumSources(CodeBlock* block, TaskMonitor& monitor) {
    if (block == nullptr || !block->getMinAddress().isValid()) {
        return 0;
    }

    CodeBlockModel* model = block->getModel();
    if (model == nullptr) {
        return 0;
    }

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

        std::unique_ptr<CodeBlockReferenceIterator> bbSrcIter(
            bblock->getSources(monitor));
        while (bbSrcIter->hasNext()) {
            CodeBlockReference* bbSrcRef = bbSrcIter->next();
            if (bbSrcRef == nullptr) {
                continue;
            }

            const FlowType* refFlowType = dynamic_cast<const FlowType*>(bbSrcRef->getFlowType());
            if (refFlowType == nullptr) {
                continue;
            }

            if (refFlowType->isCall()) {
                ++count;
            }
            else if (refFlowType->isJump() || refFlowType->isFallthrough()) {
                Address srcAddr = bbSrcRef->getReferent();
                if (!block->contains(srcAddr)) {
                    ++count;
                }
            }
        }
    }
    return count;
}

static int queueSrcReferences(std::vector<CodeBlockReference*>& blockRefQueue,
                              CodeBlock* destBlock, const Address& destAddr,
                              const Address& srcAddr, const FlowType* flowType,
                              TaskMonitor& monitor) {
    CodeBlockModel* model = destBlock->getModel();
    if (model == nullptr) {
        return 0;
    }

    if (model->allowsBlockOverlap()) {
        int blockCount = 0;
        CodeBlock** srcBlocks = model->getCodeBlocksContaining(srcAddr, monitor, blockCount);
        if (blockCount > 0) {
            for (int i = 0; i < blockCount; ++i) {
                blockRefQueue.push_back(new CodeBlockReferenceImpl(
                    srcBlocks[i], destBlock, flowType, destAddr, srcAddr));
            }
            delete[] srcBlocks;
            return blockCount;
        }
        delete[] srcBlocks;
    }

    blockRefQueue.push_back(new CodeBlockReferenceImpl(
        nullptr, destBlock, flowType, destAddr, srcAddr));
    return 1;
}

} // namespace ghidra
