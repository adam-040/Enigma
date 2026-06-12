/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionShellSymbol.h
/// \brief A function symbol that represents only a shell of the function.
/// Translated from: ghidra.program.model.pcode.HighFunctionShellSymbol
#pragma once

#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

class HighFunctionShellSymbol : public HighSymbol {
public:
    HighFunctionShellSymbol(int64_t id, const std::string& nm, const Address& addr, void* manage);

    bool isGlobal() const override { return true; }

    void encode(Encoder& encoder) const override;
};

}  // namespace pcode
}  // namespace ghidra
