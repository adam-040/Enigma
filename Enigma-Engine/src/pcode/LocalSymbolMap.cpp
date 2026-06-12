/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LocalSymbolMap.cpp
/// \brief Container for local symbols in the decompiler's model of a function.
#include "ghidra/LocalSymbolMap.h"

namespace ghidra {

LocalSymbolMap::LocalSymbolMap() {}

void LocalSymbolMap::decodeSymbolMap(void* /*decoder*/) {}

void LocalSymbolMap::encodeSymbolMap(void* /*encoder*/) const {}

HighSymbol* LocalSymbolMap::getSymbol(int64_t id) const {
    auto it = idToSymbol.find(id);
    return (it != idToSymbol.end()) ? it->second : nullptr;
}

} // namespace ghidra
