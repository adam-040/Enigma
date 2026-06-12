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

#include <ghidra/block/SubroutineBlockModel.h>
#include <ghidra/block/CodeBlockCache.h>
#include <ghidra/Address.h>
#include <vector>
#include <memory>

namespace ghidra {

class Program;
class CodeBlock;
class CodeBlockIterator;
class TaskMonitor;
class CancelledException;
class AddressSetView;

/**
 * MultEntSubModel (M-Model) defines subroutines with multiple entry points.
 * Translated from: ghidra.program.model.block.MultEntSubModel
 */
class MultEntSubModel : public SubroutineBlockModel {
public:
    static constexpr const char* MULTI_ENTRY_MODEL_NAME = "Multiple Entry";

    explicit MultEntSubModel(Program* program);
    MultEntSubModel(Program* program, bool includeExternals);
    ~MultEntSubModel() override = default;

    std::string getName() const override { return MULTI_ENTRY_MODEL_NAME; }

    Program* getProgram() const override { return program_; }

    int getCodeBlockCount() const override;

    CodeBlock* getCodeBlockAt(Address addr, TaskMonitor& monitor) override;
    CodeBlock* getFirstCodeBlockContaining(Address addr, TaskMonitor& monitor) override;
    CodeBlock* getCodeBlockContaining(Address addr, TaskMonitor& monitor) override;

    CodeBlockIterator getCodeBlocksContaining(Address addr, TaskMonitor& monitor) override;
    CodeBlockIterator getCodeBlocksContaining(CodeBlock* block, TaskMonitor& monitor) override;
    CodeBlockIterator getCodeBlocksContaining(const AddressSetView& addrSet, TaskMonitor& monitor) override;

    CodeBlock** getCodeBlocksContaining(Address addr, TaskMonitor& monitor, int& count) override;

    CodeBlockIterator getCodeBlocks(TaskMonitor& monitor) override;

    CodeBlockIterator getDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    CodeBlockIterator getSources(CodeBlock* block, TaskMonitor& monitor) override;

    int getNumDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    int getNumSources(CodeBlock* block, TaskMonitor& monitor) override;

    bool allowsBlockOverlap() const override { return true; }

    CodeBlockModel* getBasicBlockModel() const override;

    bool externalsIncluded() const override { return includeExternals_; }

    AddressSet* getAddressSet() const override;

    CodeBlock* createBlock(CodeBlock* parent, Address start) override;

    CodeBlock* getSubroutine(Address addr, TaskMonitor& monitor) override;
    CodeBlockIterator getSubroutines(TaskMonitor& monitor) override;
    CodeBlockIterator getSubroutines(const AddressSetView& addrSet, TaskMonitor& monitor) override;

protected:
    Program* program_ = nullptr;
    bool includeExternals_ = false;
    CodeBlockModel* basicBlockModel_ = nullptr;
    CodeBlockCache foundSubs_;

    virtual CodeBlock* findSubroutine(Address addr, TaskMonitor& monitor);
    CodeBlock* createSub(AddressSet* addrSet, Address entryAddr);
    CodeBlock* getSubFromCache(const Address& addr);
};

} // namespace ghidra
