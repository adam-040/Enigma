/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MappedEntry.cpp
/// \brief A normal mapping of a HighSymbol to a particular Address.
#include "ghidra/MappedEntry.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/MutabilitySettingsDefinition.h"

namespace ghidra {

MappedEntry::MappedEntry(HighSymbol* sym) : SymbolEntry(sym) {}

MappedEntry::MappedEntry(HighSymbol* sym, const VariableStorage& store, const Address& addr)
    : SymbolEntry(sym), storage(store) {
    pcaddr = addr;
}

void MappedEntry::decode(Decoder& decoder) {
    int addrel = decoder.openElement(ELEM_ADDR);
    (void)addrel;
    storage = VariableStorage();
    decoder.closeElement(addrel);
    decodeRangeList(decoder);
}

void MappedEntry::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_ADDR);
    encoder.closeElement(ELEM_ADDR);
    encodeRangelist(encoder);
}

VariableStorage MappedEntry::getStorage() const {
    return storage;
}

int MappedEntry::getSize() const {
    return storage.size();
}

int MappedEntry::getMutability() const {
    return getMutabilityOfAddress(storage.getMinAddress(), nullptr);
}

int MappedEntry::getMutabilityOfAddress(const Address& /*addr*/, void* /*program*/) {
    return MutabilitySettingsDefinition::NORMAL;
}

} // namespace ghidra
