/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/BasicBlockModel.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/Program.h>

namespace ghidra {

BasicBlockModel::BasicBlockModel(Program* program)
    : SimpleBlockModel(program, MODEL_NAME) {
}

BasicBlockModel::BasicBlockModel(Program* program, const std::string& name)
    : SimpleBlockModel(program, name) {
}

bool BasicBlockModel::hasEndOfBlockFlow(Instruction* instr) {
    FlowType* flowType = instr->getFlowType();
    if (flowType != nullptr && (flowType->isJump() || flowType->isTerminal())) {
        return true;
    }
    const auto& refs = instr->getReferencesFrom();
    for (Reference* ref : refs) {
        const RefType* refType = ref->getReferenceType();
        if (refType != nullptr && (refType->isJump() || refType->isTerminal())) {
            return true;
        }
    }
    return false;
}

} // namespace ghidra
