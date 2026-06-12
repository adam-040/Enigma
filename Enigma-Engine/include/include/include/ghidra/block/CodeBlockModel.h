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

#include <ghidra/Address.h>
#include <string>
#include <memory>

namespace ghidra {

class Program;
class AddressSetView;
class AddressSet;
class CodeBlock;
class CodeBlockIterator;
class CodeBlockReferenceIterator;
class TaskMonitor;
class CancelledException;

/**
 * CodeBlockModel defines the interface for code block models.
 * Translated from: ghidra.program.model.block.CodeBlockModel
 */
class CodeBlockModel {
public:
    virtual ~CodeBlockModel() = default;

    virtual std::string getName() const = 0;

    virtual Program* getProgram() const = 0;

    virtual int getCodeBlockCount() const = 0;

    virtual CodeBlock* getCodeBlockAt(Address addr, TaskMonitor& monitor) = 0;
    virtual CodeBlock* getFirstCodeBlockContaining(Address addr, TaskMonitor& monitor) = 0;
    virtual CodeBlock* getCodeBlockContaining(Address addr, TaskMonitor& monitor) = 0;

    virtual CodeBlockIterator getCodeBlocksContaining(Address addr, TaskMonitor& monitor) = 0;
    virtual CodeBlockIterator getCodeBlocksContaining(CodeBlock* block, TaskMonitor& monitor) = 0;
    virtual CodeBlockIterator getCodeBlocksContaining(const AddressSetView& addrSet, TaskMonitor& monitor) = 0;

    virtual CodeBlock** getCodeBlocksContaining(Address addr, TaskMonitor& monitor, int& count) = 0;

    virtual CodeBlockIterator getCodeBlocks(TaskMonitor& monitor) = 0;

    virtual CodeBlockIterator getDestinations(CodeBlock* block, TaskMonitor& monitor) = 0;
    virtual CodeBlockIterator getSources(CodeBlock* block, TaskMonitor& monitor) = 0;

    virtual int getNumDestinations(CodeBlock* block, TaskMonitor& monitor) = 0;
    virtual int getNumSources(CodeBlock* block, TaskMonitor& monitor) = 0;

    virtual bool allowsBlockOverlap() const = 0;

    virtual CodeBlockModel* getBasicBlockModel() const = 0;

    virtual bool externalsIncluded() const = 0;

    virtual AddressSet* getAddressSet() const = 0;

    virtual bool isSubroutineModel() const = 0;

    virtual CodeBlock* createBlock(CodeBlock* parent, Address start) = 0;
};

} // namespace ghidra
