/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalLanguageCompilerSpecQuery.h
/// \brief Query parameters for external (non-Ghidra) languages
/// Translated from: ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery
#pragma once

#include <string>
#include <optional>
#include "ghidra/Endian.h"
#include "ghidra/CompilerSpecID.h"

namespace ghidra {

struct ExternalLanguageCompilerSpecQuery {
    std::string externalProcessorName;
    std::string externalTool;
    Endian endian;
    std::optional<int> size;
    CompilerSpecID compilerSpecID;

    ExternalLanguageCompilerSpecQuery() = default;

    ExternalLanguageCompilerSpecQuery(const std::string& procName, const std::string& tool,
                                       Endian e, std::optional<int> s, const CompilerSpecID& csid)
        : externalProcessorName(procName), externalTool(tool), endian(e), size(s),
          compilerSpecID(csid) {}

    std::string toString() const {
        return "externalProcessorName=" + externalProcessorName +
               "; externalTool=" + externalTool +
               "; endian=" + (endian == Endian::BIG ? "big" : "little") +
               "; size=" + (size.has_value() ? std::to_string(*size) : "null") +
               "; compiler=" + compilerSpecID.getIdAsString();
    }
};

} // namespace ghidra
