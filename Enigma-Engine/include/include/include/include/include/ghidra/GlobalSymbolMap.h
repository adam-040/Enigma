/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GlobalSymbolMap.h
/// \brief Container for global symbols in the decompiler's model of a function.
/// Translated from: ghidra.program.model.pcode.GlobalSymbolMap
#pragma once

#include <ghidra/Address.h>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace ghidra {

class HighSymbol;
class DataType;

/**
 * A container for global symbols in the decompiler's model of a function.
 * Currently, only the storage and lookup methods are implemented. Methods that
 * require HighFunction, CodeSymbol, FunctionSymbol, etc. are stubbed out and
 * return nullptr.
 */
class GlobalSymbolMap {
public:
    GlobalSymbolMap();

    HighSymbol* getSymbol(int64_t id) const;
    HighSymbol* getSymbol(const Address& addr) const;

    std::vector<HighSymbol*> getSymbols() const;

    int64_t getNextUniqueSymbolId() const { return uniqueSymbolId; }
    std::size_t size() const { return symbolMap.size(); }

    void insertSymbol(HighSymbol* sym, const Address& addr);

    HighSymbol* populateSymbol(int64_t id, DataType* dataType, int sz);

    void populateAnnotation(void* vn);

    HighSymbol* newSymbol(int64_t id, const Address& addr, DataType* dataType, int sz);

private:
    std::unordered_map<int64_t, HighSymbol*> symbolMap;
    std::unordered_map<Address, HighSymbol*> addrMappedSymbols;
    int64_t uniqueSymbolId;
};

} // namespace ghidra
