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

#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockCache.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <map>
#include <memory>

namespace ghidra {

class Program;
class CodeBlock;
class CodeBlockIterator;
class CodeBlockReferenceIterator;
class Instruction;
class TaskMonitor;
class CancelledException;

/**
 * SimpleBlockModel is an abstract base for code block models.
 * Translated from: ghidra.program.model.block.SimpleBlockModel
 */
class SimpleBlockModel : public CodeBlockModel {
protected:
    Program* program_;
    std::string name_;
    CodeBlockCache cache_;
    bool overlapAllowed_ = false;
    CodeBlockModel* basicBlockModel_ = nullptr;

    virtual CodeBlock* createNewBlock(CodeBlockModel* model, Program* program,
                                        const std::string& name,
                                        const AddressSetView& addrSet) const;

    virtual CodeBlock* createSimpleDataBlock(Address start, Address end);

    virtual bool hasEndOfBlockFlow(Instruction* instr);

public:
    SimpleBlockModel(Program* program, const std::string& name);
    SimpleBlockModel(Program* program, const std::string& name, bool overlapAllowed);

    ~SimpleBlockModel() override = default;

    std::string getName() const override { return name_; }

    Program* getProgram() const override { return program_; }

    int getCodeBlockCount() const override { return cache_.size(); }

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

    bool allowsBlockOverlap() const override { return overlapAllowed_; }

    CodeBlockModel* getBasicBlockModel() const override { return basicBlockModel_; }
    void setBasicBlockModel(CodeBlockModel* model) { basicBlockModel_ = model; }

    bool externalsIncluded() const override { return false; }

    AddressSet* getAddressSet() const override;

    bool isSubroutineModel() const override { return false; }

    CodeBlock* createBlock(CodeBlock* parent, Address start) override;

    void addBlock(CodeBlock* block, const AddressSetView& addrSet);
    void removeBlock(CodeBlock* block);
    void clearCache();
};

} // namespace ghidra
