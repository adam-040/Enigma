/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolTableListener.h
/// \brief Listener for symbol table changes.
/// Translated from: ghidra.program.model.symbol.SymbolTableListener
#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class Symbol;
class Reference;

class SymbolTableListener {
public:
    virtual ~SymbolTableListener() = default;

    virtual void symbolAdded(Symbol* symbol) = 0;
    virtual void symbolRemoved(const Address& addr, const std::string& name, bool isLocal) = 0;
    virtual void symbolRenamed(Symbol* symbol, const std::string& oldName) = 0;
    virtual void primarySymbolSet(Symbol* symbol) = 0;
    virtual void symbolScopeChanged(Symbol* symbol) = 0;
    virtual void externalEntryPointAdded(const Address& addr) = 0;
    virtual void externalEntryPointRemoved(const Address& addr) = 0;
    virtual void associationAdded(Symbol* symbol, Reference* ref) = 0;
    virtual void associationRemoved(Reference* ref) = 0;
};

} // namespace ghidra
