/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolManager.cpp
/// \brief Manages symbols in the program
/// Translated from: ghidra.program.database.symbol.SymbolManager

#include <ghidra/SymbolManager.h>

namespace ghidra {

int SymbolManager::getNumEntries() {
    return symbolTable_ ? symbolTable_->getNumSymbols() : 0;
}

} // namespace ghidra
