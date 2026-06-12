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

#include <ghidra/block/MultEntSubModel.h>
#include <ghidra/block/CodeBlockCache.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <map>
#include <vector>
#include <mutex>

namespace ghidra {

class Program;
class CodeBlock;
class Listing;
class TaskMonitor;
class CancelledException;

/**
 * OverlapCodeSubModel (O-Model) defines subroutines that may share code with other subroutines.
 * Translated from: ghidra.program.model.block.OverlapCodeSubModel
 */
class OverlapCodeSubModel : public MultEntSubModel {
public:
    static constexpr const char* OVERLAP_MODEL_NAME = "Overlap Code";

    explicit OverlapCodeSubModel(Program* program);
    OverlapCodeSubModel(Program* program, bool includeExternals);
    ~OverlapCodeSubModel() override = default;

    std::string getName() const override { return OVERLAP_MODEL_NAME; }

    CodeBlock* getSubroutine(Address addr, TaskMonitor& monitor) override;
    CodeBlockIterator getSubroutines(TaskMonitor& monitor) override;

    CodeBlockIterator getDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    CodeBlockIterator getSources(CodeBlock* block, TaskMonitor& monitor) override;

    int getNumDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    int getNumSources(CodeBlock* block, TaskMonitor& monitor) override;

    bool allowsBlockOverlap() const override { return true; }

    CodeBlockModel* getBasicBlockModel() const override { return modelM_; }

protected:
    CodeBlockModel* modelM_ = nullptr;
    Listing* listing_ = nullptr;
    CodeBlockCache subCache_;
    std::mutex cacheMutex_;

    CodeBlock* findSubroutine(Address addr, TaskMonitor& monitor) override;

    virtual CodeBlock* doGetSubroutine(Address mStartAddr, TaskMonitor& monitor);
    CodeBlock* createSub(AddressSet* addrSet, Address entryAddr);
};

} // namespace ghidra
