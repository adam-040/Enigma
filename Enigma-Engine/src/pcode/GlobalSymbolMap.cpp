/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GlobalSymbolMap.cpp
/// \brief Container for global symbols in the decompiler's model of a function.
#include "ghidra/GlobalSymbolMap.h"
#include "ghidra/HighSymbol.h"

namespace ghidra {

GlobalSymbolMap::GlobalSymbolMap() : uniqueSymbolId(0) {}

HighSymbol* GlobalSymbolMap::getSymbol(int64_t id) const {
    auto it = symbolMap.find(id);
    return (it != symbolMap.end()) ? it->second : nullptr;
}

HighSymbol* GlobalSymbolMap::getSymbol(const Address& addr) const {
    auto it = addrMappedSymbols.find(addr);
    return (it != addrMappedSymbols.end()) ? it->second : nullptr;
}

std::vector<HighSymbol*> GlobalSymbolMap::getSymbols() const {
    std::vector<HighSymbol*> result;
    result.reserve(symbolMap.size());
    for (const auto& kv : symbolMap) {
        result.push_back(kv.second);
    }
    return result;
}

void GlobalSymbolMap::insertSymbol(HighSymbol* sym, const Address& addr) {
    if (sym == nullptr) return;
    int64_t uniqueId = sym->getId();
    if ((uniqueId >> 56) == (static_cast<int64_t>(0) >> 56)) {
        int64_t val = uniqueId & 0x7fffffffLL;
        if (val > uniqueSymbolId) {
            uniqueSymbolId = val;
        }
    }
    symbolMap[uniqueId] = sym;
    addrMappedSymbols[addr] = sym;
}

HighSymbol* GlobalSymbolMap::populateSymbol(int64_t /*id*/, DataType* /*dataType*/, int /*sz*/) {
    return nullptr;
}

void GlobalSymbolMap::populateAnnotation(void* /*vn*/) {}

HighSymbol* GlobalSymbolMap::newSymbol(int64_t /*id*/, const Address& /*addr*/,
                                       DataType* /*dataType*/, int /*sz*/) {
    return nullptr;
}

} // namespace ghidra
