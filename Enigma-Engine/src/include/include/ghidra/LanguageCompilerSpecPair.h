/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LanguageCompilerSpecPair.h
/// \brief Represents a processor language and compiler pair
/// Translated from: ghidra.program.model.lang.LanguageCompilerSpecPair
#pragma once

#include <string>
#include <stdexcept>
#include "ghidra/LanguageID.h"
#include "ghidra/CompilerSpecID.h"

namespace ghidra {

class LanguageCompilerSpecPair {
public:
    LanguageID languageID;
    CompilerSpecID compilerSpecID;

    LanguageCompilerSpecPair() = default;

    LanguageCompilerSpecPair(const std::string& langID, const std::string& csID)
        : languageID(langID), compilerSpecID(csID) {
        if (langID.empty()) throw std::invalid_argument("empty languageID not allowed");
        if (csID.empty()) throw std::invalid_argument("empty compilerSpecID not allowed");
    }

    LanguageCompilerSpecPair(const LanguageID& langID, const CompilerSpecID& csID)
        : languageID(langID), compilerSpecID(csID) {}

    const LanguageID& getLanguageID() const { return languageID; }
    const CompilerSpecID& getCompilerSpecID() const { return compilerSpecID; }

    bool operator==(const LanguageCompilerSpecPair& other) const {
        return languageID == other.languageID && compilerSpecID == other.compilerSpecID;
    }
    bool operator!=(const LanguageCompilerSpecPair& other) const {
        return !(*this == other);
    }
    bool operator<(const LanguageCompilerSpecPair& other) const {
        if (languageID != other.languageID) return languageID < other.languageID;
        return compilerSpecID < other.compilerSpecID;
    }

    bool isValid() const {
        return !languageID.getIdAsString().empty() && !compilerSpecID.getIdAsString().empty();
    }

    std::string toString() const {
        return languageID.getIdAsString() + ":" + compilerSpecID.getIdAsString();
    }
};

} // namespace ghidra
