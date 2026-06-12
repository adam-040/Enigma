/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MappedDataEntry.cpp
/// \brief A normal address based HighSymbol mapping with an associated Data object.
#include "ghidra/MappedDataEntry.h"
#include "ghidra/MutabilitySettingsDefinition.h"

namespace ghidra {

MappedDataEntry::MappedDataEntry(HighSymbol* sym) : MappedEntry(sym), data(nullptr) {}

MappedDataEntry::MappedDataEntry(HighSymbol* sym, const VariableStorage& store, void* d)
    : MappedEntry(sym, store, Address()), data(d) {}

void MappedDataEntry::decode(Decoder& decoder) {
    MappedEntry::decode(decoder);
    data = nullptr;
}

int MappedDataEntry::getMutability() const {
    return MutabilitySettingsDefinition::NORMAL;
}

} // namespace ghidra
