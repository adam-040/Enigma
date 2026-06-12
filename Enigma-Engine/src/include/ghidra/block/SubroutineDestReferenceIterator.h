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
#include <list>

namespace ghidra {

class CodeBlock;
class CodeBlockReference;
class TaskMonitor;
class CancelledException;

/**
 * SubroutineDestReferenceIterator is a unidirectional iterator over
 * the destination CodeBlockReferences for a subroutine CodeBlock.
 * Translated from: ghidra.program.model.block.SubroutineDestReferenceIterator
 */
class SubroutineDestReferenceIterator : public CodeBlockReferenceIterator {
public:
    SubroutineDestReferenceIterator(CodeBlock* block, TaskMonitor& monitor);
    ~SubroutineDestReferenceIterator() override = default;

    static int getNumDestinations(CodeBlock* block, TaskMonitor& monitor);
};

} // namespace ghidra
