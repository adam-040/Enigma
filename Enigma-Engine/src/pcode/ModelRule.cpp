/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ModelRule.h>
#include <ghidra/DataTypeManager.h>
#include <algorithm>

namespace ghidra {

void ModelRule::destroy() {
    delete filter;
    delete qualifier;
    delete assign;
    for (auto* p : preconditions) delete p;
    for (auto* s : sideeffects) delete s;
}

ModelRule::ModelRule()
    : filter(nullptr), qualifier(nullptr), assign(nullptr) {
}

ModelRule::ModelRule(const ModelRule& op2, ParamListStandard* res) {
    filter = op2.filter ? op2.filter->clone() : nullptr;
    qualifier = op2.qualifier ? op2.qualifier->clone() : nullptr;
    assign = op2.assign ? op2.assign->clone(res) : nullptr;

    preconditions.resize(op2.preconditions.size());
    for (size_t i = 0; i < op2.preconditions.size(); ++i) {
        preconditions[i] = op2.preconditions[i]->clone(res);
    }
    sideeffects.resize(op2.sideeffects.size());
    for (size_t i = 0; i < op2.sideeffects.size(); ++i) {
        sideeffects[i] = op2.sideeffects[i]->clone(res);
    }
}

ModelRule::ModelRule(DatatypeFilter* typeFilter, AssignAction* action, ParamListStandard* res) {
    filter = typeFilter ? typeFilter->clone() : nullptr;
    qualifier = nullptr;
    assign = action ? action->clone(res) : nullptr;
}

ModelRule::~ModelRule() {
    destroy();
}

bool ModelRule::isEquivalent(const ModelRule& op) const {
    auto eqOrNull = [](auto* a, auto* b) -> bool {
        if (a == nullptr && b == nullptr) return true;
        if (a == nullptr || b == nullptr) return false;
        return a->isEquivalent(*b);
    };
    if (!eqOrNull(assign, op.assign)) return false;
    if (!eqOrNull(filter, op.filter)) return false;
    if (!eqOrNull(qualifier, op.qualifier)) return false;
    if (preconditions.size() != op.preconditions.size()) return false;
    for (size_t i = 0; i < preconditions.size(); ++i) {
        if (!preconditions[i]->isEquivalent(*op.preconditions[i]))
            return false;
    }
    if (sideeffects.size() != op.sideeffects.size()) return false;
    for (size_t i = 0; i < sideeffects.size(); ++i) {
        if (!sideeffects[i]->isEquivalent(*op.sideeffects[i]))
            return false;
    }
    return true;
}

int ModelRule::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                              DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    if (filter && !filter->filter(dt))
        return AssignAction::FAIL;
    if (qualifier && !qualifier->filter(proto, pos))
        return AssignAction::FAIL;

    for (auto* pc : preconditions) {
        pc->assignAddress(dt, proto, pos, dtManager, status, res);
    }

    int response = assign->assignAddress(dt, proto, pos, dtManager, status, res);
    if (response != AssignAction::FAIL) {
        for (auto* se : sideeffects) {
            se->assignAddress(dt, proto, pos, dtManager, status, res);
        }
    }
    return response;
}

void ModelRule::encode(Encoder& encoder) {
    // Stub
}

} // namespace ghidra
