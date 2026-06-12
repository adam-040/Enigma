/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionSymbol.h
/// \brief A function symbol that encapsulates detailed information about a particular function.
/// Translated from: ghidra.program.model.pcode.HighFunctionSymbol
#pragma once

#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

class HighFunction;

class HighFunctionSymbol : public HighSymbol {
public:
    HighFunctionSymbol(const Address& addr, int size, HighFunction* function);

    bool isGlobal() const override { return true; }

    int getSize() const override { return size; }
    int size = 0;

    void encode(Encoder& encoder) const override;
};

}  // namespace pcode
}  // namespace ghidra
