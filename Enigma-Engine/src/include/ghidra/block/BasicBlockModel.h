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

#include <ghidra/block/SimpleBlockModel.h>

namespace ghidra {

class Program;
class Instruction;
class TaskMonitor;
class CancelledException;

/**
 * BasicBlockModel builds basic blocks from code flows.
 * Translated from: ghidra.program.model.block.BasicBlockModel
 */
class BasicBlockModel : public SimpleBlockModel {
public:
    static constexpr const char* MODEL_NAME = "Basic Block Model";

    explicit BasicBlockModel(Program* program);
    BasicBlockModel(Program* program, const std::string& name);

    ~BasicBlockModel() override = default;

    bool hasEndOfBlockFlow(Instruction* instr) override;

    bool externalsIncluded() const override { return false; }
};

} // namespace ghidra
