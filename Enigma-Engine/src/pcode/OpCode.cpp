/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OpCode.cpp
/// \brief OpCode implementation - enumeration of all pcode operations
#include "ghidra/OpCode.h"

namespace ghidra {

OpCode getOpCode(int ordinal) {
    return static_cast<OpCode>(ordinal);
}

OpCode getOpCode(const std::string& name) {
    static const std::unordered_map<std::string, OpCode> nameMap = []() {
        std::unordered_map<std::string, OpCode> m;
        for (int i = 1; i < static_cast<int>(OpCode::CPUI_MAX); i++) {
            OpCode op = static_cast<OpCode>(i);
            const char* n = opCodeName(op);
            if (n) m[n] = op;
        }
        return m;
    }();
    auto it = nameMap.find(name);
    return (it != nameMap.end()) ? it->second : OpCode::CPUI_MAX;
}

OpCode opCodeFlip(OpCode op) {
    switch (op) {
        case OpCode::CPUI_INT_EQUAL: return OpCode::CPUI_INT_NOTEQUAL;
        case OpCode::CPUI_INT_NOTEQUAL: return OpCode::CPUI_INT_EQUAL;
        case OpCode::CPUI_INT_SLESS: return OpCode::CPUI_INT_SLESSEQUAL;
        case OpCode::CPUI_INT_SLESSEQUAL: return OpCode::CPUI_INT_SLESS;
        case OpCode::CPUI_INT_LESS: return OpCode::CPUI_INT_LESSEQUAL;
        case OpCode::CPUI_INT_LESSEQUAL: return OpCode::CPUI_INT_LESS;
        case OpCode::CPUI_BOOL_NEGATE: return OpCode::CPUI_COPY;
        case OpCode::CPUI_FLOAT_EQUAL: return OpCode::CPUI_FLOAT_NOTEQUAL;
        case OpCode::CPUI_FLOAT_NOTEQUAL: return OpCode::CPUI_FLOAT_EQUAL;
        case OpCode::CPUI_FLOAT_LESS: return OpCode::CPUI_FLOAT_LESSEQUAL;
        case OpCode::CPUI_FLOAT_LESSEQUAL: return OpCode::CPUI_FLOAT_LESS;
        default: return OpCode::CPUI_MAX;
    }
}

bool opCodeBooleanFlip(OpCode op) {
    switch (op) {
        case OpCode::CPUI_INT_EQUAL: return false;
        case OpCode::CPUI_INT_NOTEQUAL: return false;
        case OpCode::CPUI_INT_SLESS: return true;
        case OpCode::CPUI_INT_SLESSEQUAL: return true;
        case OpCode::CPUI_INT_LESS: return true;
        case OpCode::CPUI_INT_LESSEQUAL: return true;
        case OpCode::CPUI_BOOL_NEGATE: return false;
        case OpCode::CPUI_FLOAT_EQUAL: return false;
        case OpCode::CPUI_FLOAT_NOTEQUAL: return false;
        case OpCode::CPUI_FLOAT_LESS: return true;
        case OpCode::CPUI_FLOAT_LESSEQUAL: return true;
        default: return false;
    }
}

} // namespace ghidra
