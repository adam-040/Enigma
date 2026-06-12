/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DecompilerLanguage.h
/// \brief Source languages that can be output by the decompiler
/// Translated from: ghidra.program.model.lang.DecompilerLanguage
#pragma once

#include <string>

namespace ghidra {

enum class DecompilerLanguage {
    C_LANGUAGE,
    JAVA_LANGUAGE
};

inline std::string toString(DecompilerLanguage lang) {
    switch (lang) {
        case DecompilerLanguage::C_LANGUAGE: return "c-language";
        case DecompilerLanguage::JAVA_LANGUAGE: return "java-language";
    }
    return "unknown";
}

} // namespace ghidra
