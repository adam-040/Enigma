/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionSymbol.cpp
/// \brief A function symbol.
#include "ghidra/pcode/HighFunctionSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Encoder.h"
#include "ghidra/ElementId.h"

namespace ghidra {
namespace pcode {

HighFunctionSymbol::HighFunctionSymbol(const Address& addr, int sz, HighFunction* function)
    : HighSymbol(0, std::string(), nullptr, function), size(sz) {
    (void)addr;
    setNameLock(true);
    setTypeLock(true);
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

void HighFunctionSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

}  // namespace pcode
}  // namespace ghidra
