/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighLabelSymbol.h
/// \brief A symbol with no underlying data-type. A label within code.
/// Translated from: ghidra.program.model.pcode.HighLabelSymbol
#pragma once

#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

class HighLabelSymbol : public HighSymbol {
public:
    HighLabelSymbol(const std::string& nm, const Address& addr, void* dtmanage);

    int getSize() const override { return 1; }

    void encode(Encoder& encoder) const override;
};

}  // namespace pcode
}  // namespace ghidra
