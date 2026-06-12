/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DynamicEntry.cpp
/// \brief HighSymbol mapping based on local hashing of a Varnode.
#include "ghidra/DynamicEntry.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/MutabilitySettingsDefinition.h"
#include "ghidra/AddressSpace.h"
#include <stdexcept>

namespace ghidra {

DynamicEntry::DynamicEntry(HighSymbol* sym) : SymbolEntry(sym), hash(0) {}

DynamicEntry::DynamicEntry(HighSymbol* sym, const Address& addr, int64_t h)
    : SymbolEntry(sym), hash(h) {
    pcaddr = addr;
}

void DynamicEntry::decode(Decoder& decoder) {
    int addrel = decoder.openElement(ELEM_HASH);
    hash = static_cast<int64_t>(decoder.readUnsignedInteger(ATTRIB_VAL));
    decoder.closeElement(addrel);
    decodeRangeList(decoder);
}

void DynamicEntry::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_HASH);
    encoder.writeUnsignedInteger(ATTRIB_VAL, static_cast<uint64_t>(hash));
    encoder.closeElement(ELEM_HASH);
    encodeRangelist(encoder);
}

VariableStorage DynamicEntry::getStorage() const {
    if (symbol == nullptr) {
        return VariableStorage();
    }
    AddressSpace* hashSpace = nullptr;
    if (hashSpace == nullptr) {
        return VariableStorage();
    }
    return VariableStorage(nullptr, hashSpace->getAddress(hash), getSize());
}

int DynamicEntry::getSize() const {
    return symbol ? symbol->getSize() : 0;
}

int DynamicEntry::getMutability() const {
    return MutabilitySettingsDefinition::NORMAL;
}

DynamicEntry DynamicEntry::build(Varnode* /*vn*/) {
    throw std::runtime_error("DynamicEntry::build requires HighFunction/DynamicHash");
}

} // namespace ghidra
