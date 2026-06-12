/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/Address.h>
#include <vector>

namespace ghidra {

class CodeBlock;
class CodeBlockReference;
class CodeBlockReferenceImpl;
class CodeBlockImpl;
class SimpleBlockModel;
class TaskMonitor;
class CancelledException;
class Reference;
class FlowType;

/**
 * SimpleDestReferenceIterator iterates over destination block references for a CodeBlock.
 * Translated from: ghidra.program.model.block.SimpleDestReferenceIterator
 */
class SimpleDestReferenceIterator : public CodeBlockReferenceIterator {
public:
    SimpleDestReferenceIterator(CodeBlock* block, bool followIndirectFlows, TaskMonitor& monitor);
    ~SimpleDestReferenceIterator() override = default;

    static int getNumDestinations(CodeBlock* block, bool followIndirectFlows, TaskMonitor& monitor);

private:
    static int getDestinations(CodeBlock* block, std::vector<CodeBlockReference*>* refQueue,
                               bool followIndirectFlows, TaskMonitor& monitor);

    static int followIndirection(CodeBlock* srcBlock, std::vector<CodeBlockReference*>* refQueue,
                                 Reference* srcRef, const FlowType* indirectFlowType,
                                 bool includeExternals, TaskMonitor& monitor);

    static void queueReference(std::vector<CodeBlockReference*>* refQueue,
                               CodeBlock* srcBlock, Address fromAddr, Address toAddr,
                               const FlowType* flowType);

    static CodeBlockImpl* createSimpleDataBlock(SimpleBlockModel* model, Address addr);
};

} // namespace ghidra
