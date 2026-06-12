/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionShellSymbol.cpp
/// \brief A function symbol that represents only a shell of the function.
#include "ghidra/pcode/HighFunctionShellSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Encoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {
namespace pcode {

HighFunctionShellSymbol::HighFunctionShellSymbol(int64_t id, const std::string& nm,
                                                 const Address& addr, void* manage)
    : HighSymbol(id, nm, nullptr, true, true, manage) {
    (void)addr;
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

void HighFunctionShellSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encoder.writeUnsignedInteger(ATTRIB_ID, static_cast<uint64_t>(getId()));
    encoder.writeString(ATTRIB_NAME, name);
    encoder.writeSignedInteger(ATTRIB_SIZE, 1);
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

}  // namespace pcode
}  // namespace ghidra
