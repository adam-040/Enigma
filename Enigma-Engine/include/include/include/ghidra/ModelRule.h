/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ModelRule.h
/// \brief A rule controlling how parameters are assigned addresses
/// Translated from: ghidra.program.model.lang.protorules.ModelRule
#pragma once

#include <ghidra/DatatypeFilter.h>
#include <ghidra/QualifierFilter.h>
#include <ghidra/AssignAction.h>
#include <ghidra/PrototypePieces.h>
#include <ghidra/ParameterPieces.h>
#include <vector>

namespace ghidra {

class DataTypeManager;

class ModelRule {
private:
    DatatypeFilter* filter;
    QualifierFilter* qualifier;
    AssignAction* assign;
    std::vector<AssignAction*> preconditions;
    std::vector<AssignAction*> sideeffects;

    void destroy();

public:
    ModelRule();
    ModelRule(const ModelRule& op2, ParamListStandard* res);
    ModelRule(DatatypeFilter* typeFilter, AssignAction* action, ParamListStandard* res);
    ~ModelRule();

    ModelRule(const ModelRule&) = delete;
    ModelRule& operator=(const ModelRule&) = delete;

    bool isEquivalent(const ModelRule& op) const;

    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res);
    void encode(Encoder& encoder);
};

} // namespace ghidra
