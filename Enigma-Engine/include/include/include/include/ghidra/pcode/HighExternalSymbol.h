/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighExternalSymbol.h
/// \brief A symbol for a function without a body in the current Program.
/// Translated from: ghidra.program.model.pcode.HighExternalSymbol
#pragma once

#include "ghidra/HighSymbol.h"
#include "ghidra/Address.h"

namespace ghidra {
namespace pcode {

class HighExternalSymbol : public HighSymbol {
public:
    HighExternalSymbol(const std::string& nm, const Address& addr,
                       const Address& resolveAddr, void* dtmanage);

    const Address& getResolveAddress() const { return resolveAddress; }

    void encode(Encoder& encoder) const override;

private:
    Address resolveAddress;
};

}  // namespace pcode
}  // namespace ghidra
