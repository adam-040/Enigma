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

#include <ghidra/block/OverlapCodeSubModel.h>
#include <ghidra/block/CodeBlockCache.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <map>

namespace ghidra {

class Program;
class CodeBlock;
class CodeBlockIterator;
class TaskMonitor;
class CancelledException;

/**
 * PartitionCodeSubModel (P-Model) partitions code into mutually exclusive subroutines.
 * Translated from: ghidra.program.model.block.PartitionCodeSubModel
 */
class PartitionCodeSubModel : public OverlapCodeSubModel {
public:
    static constexpr const char* PARTITION_MODEL_NAME = "Partition Code";

    explicit PartitionCodeSubModel(Program* program);
    PartitionCodeSubModel(Program* program, bool includeExternals);
    ~PartitionCodeSubModel() override = default;

    std::string getName() const override { return PARTITION_MODEL_NAME; }

    CodeBlock* getSubroutine(Address addr, TaskMonitor& monitor) override;
    CodeBlockIterator getSubroutines(TaskMonitor& monitor) override;

    CodeBlockIterator getDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    CodeBlockIterator getSources(CodeBlock* block, TaskMonitor& monitor) override;

    int getNumDestinations(CodeBlock* block, TaskMonitor& monitor) override;
    int getNumSources(CodeBlock* block, TaskMonitor& monitor) override;

protected:
    CodeBlock* doGetSubroutine(Address mStartAddr, TaskMonitor& monitor) override;
    CodeBlock* findSubroutine(Address addr, TaskMonitor& monitor) override;
};

} // namespace ghidra
