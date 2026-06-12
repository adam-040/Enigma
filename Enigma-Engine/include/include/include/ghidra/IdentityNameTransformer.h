/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IdentityNameTransformer.h
/// \brief Name transformer that returns input unchanged
/// Translated from: ghidra.program.model.symbol.IdentityNameTransformer
#pragma once

#include <ghidra/NameTransformer.h>

namespace ghidra {

class IdentityNameTransformer : public NameTransformer {
public:
    std::string simplify(const std::string& input) override {
        return input;
    }
};

} // namespace ghidra
