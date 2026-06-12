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
#include <list>

namespace ghidra {

class CodeBlock;
class CodeBlockReference;
class TaskMonitor;
class CancelledException;

/**
 * SubroutineSourceReferenceIterator is a unidirectional iterator over
 * the source CodeBlockReferences for a subroutine CodeBlock.
 * Translated from: ghidra.program.model.block.SubroutineSourceReferenceIterator
 */
class SubroutineSourceReferenceIterator : public CodeBlockReferenceIterator {
public:
    SubroutineSourceReferenceIterator(CodeBlock* block, TaskMonitor& monitor);
    ~SubroutineSourceReferenceIterator() override = default;

    static int getNumSources(CodeBlock* block, TaskMonitor& monitor);
};

} // namespace ghidra
