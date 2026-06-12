/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MappedEntry.h
/// \brief A normal mapping of a HighSymbol to a particular Address, consuming a set number of bytes.
/// Translated from: ghidra.program.model.pcode.MappedEntry
#pragma once

#include <ghidra/SymbolEntry.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Address.h>

namespace ghidra {

/**
 * A normal mapping of a HighSymbol to a particular Address, consuming a set number of bytes.
 */
class MappedEntry : public SymbolEntry {
public:
    MappedEntry(HighSymbol* sym);

    MappedEntry(HighSymbol* sym, const VariableStorage& store, const Address& addr);

    void decode(Decoder& decoder) override;
    void encode(Encoder& encoder) const override;
    VariableStorage getStorage() const override;
    int getSize() const override;
    int getMutability() const override;

    void setStorage(const VariableStorage& store) { storage = store; }

    static int getMutabilityOfAddress(const Address& addr, void* program);

protected:
    VariableStorage storage;
};

} // namespace ghidra
