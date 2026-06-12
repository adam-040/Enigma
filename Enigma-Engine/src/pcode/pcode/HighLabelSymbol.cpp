/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighLabelSymbol.cpp
/// \brief A symbol with no underlying data-type. A label within code.
#include "ghidra/pcode/HighLabelSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Encoder.h"
#include "ghidra/ElementId.h"

namespace ghidra {
namespace pcode {

HighLabelSymbol::HighLabelSymbol(const std::string& nm, const Address& addr, void* dtmanage)
    : HighSymbol(0, nm, nullptr, true, true, dtmanage) {
    (void)addr;
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

void HighLabelSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

}  // namespace pcode
}  // namespace ghidra
