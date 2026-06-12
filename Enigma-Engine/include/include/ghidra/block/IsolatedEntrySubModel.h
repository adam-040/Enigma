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

namespace ghidra {

class Program;
class CodeBlock;
class TaskMonitor;
class CancelledException;

/**
 * IsolatedEntrySubModel (S-Model) defines subroutines with a unique entry point,
 * which may share code with other subroutines.
 * Translated from: ghidra.program.model.block.IsolatedEntrySubModel
 */
class IsolatedEntrySubModel : public OverlapCodeSubModel {
public:
    static constexpr const char* ISOLATED_MODEL_NAME = "Isolated Entry";

    explicit IsolatedEntrySubModel(Program* program);
    IsolatedEntrySubModel(Program* program, bool includeExternals);
    ~IsolatedEntrySubModel() override = default;

    std::string getName() const override { return ISOLATED_MODEL_NAME; }

protected:
    CodeBlock* doGetSubroutine(Address mStartAddr, TaskMonitor& monitor) override;
};

} // namespace ghidra
