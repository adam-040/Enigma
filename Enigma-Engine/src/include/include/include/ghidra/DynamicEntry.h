/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DynamicEntry.h
/// \brief A HighSymbol mapping based on local hashing of the symbol's Varnode within a function's syntax tree.
/// Translated from: ghidra.program.model.pcode.DynamicEntry
#pragma once

#include <ghidra/SymbolEntry.h>
#include <ghidra/Address.h>
#include <cstdint>

namespace ghidra {

class Varnode;

/**
 * A HighSymbol mapping based on local hashing of the symbol's Varnode within
 * a function's syntax tree. The storage address of a temporary Varnode is too
 * ephemeral to use as a permanent identifier; this symbol stores a hash (from
 * DynamicHash) that is better suited to identifying the Varnode.
 */
class DynamicEntry : public SymbolEntry {
public:
    DynamicEntry(HighSymbol* sym);
    DynamicEntry(HighSymbol* sym, const Address& addr, int64_t h);

    int64_t getHash() const { return hash; }

    void decode(Decoder& decoder) override;
    void encode(Encoder& encoder) const override;
    VariableStorage getStorage() const override;
    int getSize() const override;
    int getMutability() const override;

    static DynamicEntry build(Varnode* vn);

private:
    int64_t hash;
};

} // namespace ghidra
