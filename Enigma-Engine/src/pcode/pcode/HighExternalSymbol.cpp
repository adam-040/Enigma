/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighExternalSymbol.cpp
/// \brief A symbol for a function without a body in the current Program.
#include "ghidra/pcode/HighExternalSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Encoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {
namespace pcode {

HighExternalSymbol::HighExternalSymbol(const std::string& nm, const Address& addr,
                                       const Address& resolveAddr, void* dtmanage)
    : HighSymbol(0, nm, nullptr, true, true, dtmanage), resolveAddress(resolveAddr) {
    (void)addr;
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

void HighExternalSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    if (!name.empty()) {
        encoder.writeString(ATTRIB_NAME, name + "_exref");
    }
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

}  // namespace pcode
}  // namespace ghidra
