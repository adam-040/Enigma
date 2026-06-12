/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IllegalCharCppTransformer.h
/// \brief Replace illegal C++ characters in symbol names with '_'.
/// Translated from: ghidra.program.model.symbol.IllegalCharCppTransformer
#pragma once

#include <ghidra/NameTransformer.h>

namespace ghidra {

class IllegalCharCppTransformer : public NameTransformer {
public:
    IllegalCharCppTransformer();

    std::string simplify(const std::string& input) override;

public:
    static constexpr int AFTER_FIRST_CHAR = 1;
    static constexpr int TEMPLATE = 2;
    static constexpr int OPERATOR = 4;
    static constexpr int FIRST_CHAR = 8;

private:
};

} // namespace ghidra
