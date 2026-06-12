/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LocalSymbolMap.h
/// \brief Container for local symbols in the decompiler's model of a function.
/// Translated from: ghidra.program.model.pcode.LocalSymbolMap
#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>

namespace ghidra {

class HighSymbol;
class HighVariable;
class Varnode;
class Address;

/**
 * Container for local symbols in the decompiler's model of a function.
 * Currently a stub. The full Java implementation depends on HighFunction,
 * EquateTable, HighCodeSymbol, etc. which are not yet ported.
 */
class LocalSymbolMap {
public:
    LocalSymbolMap();

    void decodeSymbolMap(void* decoder);
    void encodeSymbolMap(void* encoder) const;

    std::size_t size() const { return idToSymbol.size(); }
    HighSymbol* getSymbol(int64_t id) const;

private:
    std::unordered_map<int64_t, HighSymbol*> idToSymbol;
};

} // namespace ghidra
