/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProcessorSymbolType.h
/// \brief Type of symbol stored in a processor context register.
/// Translated from: ghidra.program.model.util.ProcessorSymbolType
#pragma once

#include <string>
#include <stdexcept>

namespace ghidra {

enum class ProcessorSymbolType {
    CODE,
    CODE_PTR
};

class ProcessorSymbolTypes {
public:
    static ProcessorSymbolType getType(const std::string& s) {
        std::string lower;
        for (char c : s) lower += (char)tolower((unsigned char)c);
        if (lower == "code") return ProcessorSymbolType::CODE;
        if (lower == "code_ptr") return ProcessorSymbolType::CODE_PTR;
        throw std::invalid_argument("unsupported symbol type: " + s);
    }

    static const char* toString(ProcessorSymbolType t) {
        switch (t) {
            case ProcessorSymbolType::CODE: return "code";
            case ProcessorSymbolType::CODE_PTR: return "code_ptr";
        }
        return "code";
    }
};

} // namespace ghidra
