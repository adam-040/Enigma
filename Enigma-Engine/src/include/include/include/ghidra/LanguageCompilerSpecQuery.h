/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LanguageCompilerSpecQuery.h
/// \brief Query parameters for finding language/compiler-spec pairs
/// Translated from: ghidra.program.model.lang.LanguageCompilerSpecQuery
#pragma once

#include <string>
#include <optional>
#include "ghidra/Processor.h"
#include "ghidra/Endian.h"
#include "ghidra/CompilerSpecID.h"

namespace ghidra {

struct LanguageCompilerSpecQuery {
    Processor processor;
    Endian endian;
    std::optional<int> size;
    std::string variant;
    CompilerSpecID compilerSpecID;

    LanguageCompilerSpecQuery() = default;

    LanguageCompilerSpecQuery(const Processor& proc, Endian e, std::optional<int> s,
                               const std::string& v, const CompilerSpecID& csid)
        : processor(proc), endian(e), size(s), variant(v), compilerSpecID(csid) {}

    std::string toString() const {
        return "processor=" + processor.getName() + "; endian=" + (endian == Endian::BIG ? "big" : "little") +
               "; size=" + (size.has_value() ? std::to_string(*size) : "null") +
               "; variant=" + variant + "; compiler=" + compilerSpecID.getIdAsString();
    }
};

} // namespace ghidra
