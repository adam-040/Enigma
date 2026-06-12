/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ConstructState.cpp
/// \brief Implementation of ConstructState methods
#include "ghidra/ConstructState.h"
#include "ghidra/Constructor.h"
#include <sstream>

namespace ghidra {

ConstructState::ConstructState(ConstructState* parent) : parent(parent) {
    if (parent) {
        parent->addSubState(this);
    }
}

int ConstructState::computeHashCode(int hashcode) const {
    if (!ct) return hashcode;
    int idx = ct->getIndex();
    hashcode = (hashcode ^ (idx >> 8)) & 0xff;
    hashcode = (hashcode ^ idx) & 0xff;
    for (auto subState : resolvedStates) {
        hashcode = subState->computeHashCode(hashcode);
    }
    return hashcode;
}

std::string ConstructState::dumpConstructorTree() const {
    if (!ct) return "";
    std::stringstream ss;
    ss << ct->getIndex();
    if (resolvedStates.empty()) return ss.str();

    ss << "[";
    for (size_t i = 0; i < resolvedStates.size(); ++i) {
        std::string s = resolvedStates[i]->dumpConstructorTree();
        if (!s.empty()) {
            if (i > 0) ss << ",";
            ss << s;
        }
    }
    ss << "]";
    return ss.str();
}

} // namespace ghidra
