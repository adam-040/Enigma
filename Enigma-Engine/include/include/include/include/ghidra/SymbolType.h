/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolType.h
/// \brief Symbol type enumeration
/// Translated from: ghidra.program.model.symbol.SymbolType
#pragma once

#include <string>
#include <stdexcept>

namespace ghidra {

enum class SymbolType {
    LABEL = 0,
    FUNCTION = 1,
    PARAMETER = 2,
    LOCAL_VARIABLE = 3,
    GLOBAL_VARIABLE = 4,
    CLASS = 5,
    NAMESPACE = 6,
    FIELD = 7,
    LIBRARY = 8,
    DYNAMIC_VARIABLE = 9,
    STACK_FRAME = 10,
    THIS = 11,
    AUTOMATIC = 12,
    POINTER = 13,
    ARRAY = 14,
    TYPEDEF = 15,
    ENUM = 16,
    STRUCTURE = 17,
    UNION = 18,
    FUNCTION_PTR = 19,
    DATA_PTR = 20,
    ARRAY_PTR = 21,
    OTHER = 22,
    THUNK = 23,
    EXTERNAL = 24,
    SECTION = 25,
    MODULE = 26,
    OBJECT = 27,
    COMMON = 28,
    WEAK = 29,
    UNDEFINED = 30
};

inline std::string symbolTypeToString(SymbolType type) {
    switch (type) {
        case SymbolType::LABEL: return "LABEL";
        case SymbolType::FUNCTION: return "FUNCTION";
        case SymbolType::PARAMETER: return "PARAMETER";
        case SymbolType::LOCAL_VARIABLE: return "LOCAL_VARIABLE";
        case SymbolType::GLOBAL_VARIABLE: return "GLOBAL_VARIABLE";
        case SymbolType::CLASS: return "CLASS";
        case SymbolType::NAMESPACE: return "NAMESPACE";
        case SymbolType::FIELD: return "FIELD";
        case SymbolType::LIBRARY: return "LIBRARY";
        case SymbolType::DYNAMIC_VARIABLE: return "DYNAMIC_VARIABLE";
        case SymbolType::STACK_FRAME: return "STACK_FRAME";
        case SymbolType::THIS: return "THIS";
        case SymbolType::AUTOMATIC: return "AUTOMATIC";
        case SymbolType::POINTER: return "POINTER";
        case SymbolType::ARRAY: return "ARRAY";
        case SymbolType::TYPEDEF: return "TYPEDEF";
        case SymbolType::ENUM: return "ENUM";
        case SymbolType::STRUCTURE: return "STRUCTURE";
        case SymbolType::UNION: return "UNION";
        case SymbolType::FUNCTION_PTR: return "FUNCTION_PTR";
        case SymbolType::DATA_PTR: return "DATA_PTR";
        case SymbolType::ARRAY_PTR: return "ARRAY_PTR";
        case SymbolType::OTHER: return "OTHER";
        case SymbolType::THUNK: return "THUNK";
        case SymbolType::EXTERNAL: return "EXTERNAL";
        case SymbolType::SECTION: return "SECTION";
        case SymbolType::MODULE: return "MODULE";
        case SymbolType::OBJECT: return "OBJECT";
        case SymbolType::COMMON: return "COMMON";
        case SymbolType::WEAK: return "WEAK";
        case SymbolType::UNDEFINED: return "UNDEFINED";
    }
    return "UNKNOWN";
}

inline bool isFunctionType(SymbolType type) {
    return type == SymbolType::FUNCTION || type == SymbolType::THUNK;
}

inline bool isLabelType(SymbolType type) {
    return type == SymbolType::LABEL || type == SymbolType::FUNCTION || type == SymbolType::THUNK;
}

inline bool isNamespaceType(SymbolType type) {
    return type == SymbolType::NAMESPACE || type == SymbolType::CLASS || type == SymbolType::LIBRARY;
}

} // namespace ghidra
