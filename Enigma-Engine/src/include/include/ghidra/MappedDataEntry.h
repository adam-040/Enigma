/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MappedDataEntry.h
/// \brief A normal address based HighSymbol mapping with an associated Data object.
/// Translated from: ghidra.program.model.pcode.MappedDataEntry
#pragma once

#include <ghidra/MappedEntry.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Address.h>

namespace ghidra {

/**
 * A normal address based HighSymbol mapping with an associated Data object.
 * The Data interface is not yet ported; it is represented as an opaque void*.
 */
class MappedDataEntry : public MappedEntry {
public:
    MappedDataEntry(HighSymbol* sym);
    MappedDataEntry(HighSymbol* sym, const VariableStorage& store, void* d);

    void* getData() const { return data; }

    void decode(Decoder& decoder) override;
    int getMutability() const override;

private:
    void* data;
};

} // namespace ghidra
