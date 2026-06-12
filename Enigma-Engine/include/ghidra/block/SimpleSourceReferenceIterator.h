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
class Reference;
class FlowType;
class TaskMonitor;
class CancelledException;

/**
 * SimpleSourceReferenceIterator iterates over source block references for a CodeBlock.
 * Translated from: ghidra.program.model.block.SimpleSourceReferenceIterator
 */
class SimpleSourceReferenceIterator : public CodeBlockReferenceIterator {
public:
    SimpleSourceReferenceIterator(CodeBlock* block, bool followIndirectFlows, TaskMonitor& monitor);
    ~SimpleSourceReferenceIterator() override = default;

    static int getNumSources(CodeBlock* block, bool followIndirectFlows, TaskMonitor& monitor);

private:
    static int getSources(CodeBlock* block, std::vector<CodeBlockReference*>* refQueue,
                          bool followIndirectFlows, TaskMonitor& monitor);

    static int followIndirection(CodeBlock* destBlock, std::vector<CodeBlockReference*>* refQueue,
                                 Reference* destRef, TaskMonitor& monitor);

    static void queueReference(std::vector<CodeBlockReference*>* refQueue,
                               CodeBlock* destBlock, Address toAddr, Address fromAddr,
                               const FlowType* flowType);
};

} // namespace ghidra
