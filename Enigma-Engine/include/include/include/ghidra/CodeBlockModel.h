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
#include <ghidra/AddressSetView.h>
#include <ghidra/RefType.h>
#include <string>
#include <vector>

namespace ghidra {

class CodeBlock;
class CodeBlockIterator;
class CodeBlockReferenceIterator;
class Program;
class TaskMonitor;

class CodeBlockModel {
public:
    virtual ~CodeBlockModel() = default;
    virtual std::string getName() const = 0;
    virtual CodeBlock* getCodeBlockAt(Address addr, TaskMonitor* monitor) = 0;
    virtual CodeBlock* getFirstCodeBlockContaining(Address addr, TaskMonitor* monitor) = 0;
    virtual std::vector<CodeBlock*> getCodeBlocksContaining(Address addr, TaskMonitor* monitor) = 0;
    virtual CodeBlockIterator* getCodeBlocks(TaskMonitor* monitor) = 0;
    virtual CodeBlockIterator* getCodeBlocksContaining(AddressSetView* addrSet, TaskMonitor* monitor) = 0;
    virtual CodeBlockReferenceIterator* getSources(CodeBlock* block, TaskMonitor* monitor) = 0;
    virtual int getNumSources(CodeBlock* block, TaskMonitor* monitor) = 0;
    virtual CodeBlockReferenceIterator* getDestinations(CodeBlock* block, TaskMonitor* monitor) = 0;
    virtual int getNumDestinations(CodeBlock* block, TaskMonitor* monitor) = 0;
    virtual CodeBlockModel* getBasicBlockModel() = 0;
    virtual bool externalsIncluded() const = 0;
    virtual FlowType getFlowType(CodeBlock* block) = 0;
    virtual std::string getName(CodeBlock* block) = 0;
    virtual Program* getProgram() const = 0;
    virtual bool allowsBlockOverlap() const = 0;
};

} // namespace ghidra
