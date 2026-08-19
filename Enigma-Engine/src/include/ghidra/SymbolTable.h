/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolTable.h
/// \brief Symbol table interface for program symbols
/// Translated from: ghidra.program.model.symbol.SymbolTable
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/ContextSymbol.h>
#include <ghidra/Namespace.h>
#include <ghidra/Reference.h>
#include <ghidra/SourceType.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/SymbolType.h>
#include <vector>
#include <unordered_map>
#include <string>
#include <memory>

namespace ghidra {

class Function;
class Program;

class SymbolTable {
public:
    SymbolTable() = default;
    explicit SymbolTable(Program* program);

    Program* getProgram() const { return program_; }

    void addSymbol(ContextSymbol* sym);
    ContextSymbol* getSymbol(const std::string& name) const;
    size_t size() const;
    std::vector<ContextSymbol*> getAllSymbols() const;

    Symbol* createLabel(Address addr, const std::string& name, SourceType source);
    Symbol* createLabel(Address addr, const std::string& name, Namespace* ns, SourceType source);
    /// Creates an external symbol (address in the external address space,
    /// parent namespace is a library).  Uses the given symbol id so original
    /// database ids are preserved.
    Symbol* createExternalSymbol(long id, const std::string& name, Address addr, Namespace* ns,
                                 SourceType source, bool isFunction);
    bool removeSymbolSpecial(Symbol* sym);

    Symbol* getSymbol(long symbolID) const;
    Symbol* getSymbol(const std::string& name, Address addr, Namespace* ns) const;
    Symbol* getGlobalSymbol(const std::string& name, Address addr) const;
    std::vector<Symbol*> getGlobalSymbols(const std::string& name) const;
    SymbolIterator getSymbols(const std::string& name) const;
    SymbolIterator getAllProgramSymbols(bool includeDynamic = true) const;
    Symbol* getPrimarySymbol(Address addr) const;
    std::vector<Symbol*> getSymbols(Address addr) const;
    SymbolIterator getSymbolsAsIterator(Address addr) const;
    bool hasSymbol(Address addr) const;
    int getNumSymbols() const;

    Namespace* getGlobalNamespace() const;
    Namespace* getNamespace(const std::string& name, Namespace* parent) const;
    Namespace* createNameSpace(Namespace* parent, const std::string& name, SourceType source);
    Namespace* addNamespaceWithId(long id, const std::string& name, Namespace* parent);
    const std::unordered_map<long, std::unique_ptr<Namespace>>& getNamespaces() const { return namespaces_; }

    std::vector<Symbol*> getSymbols(Namespace* ns) const;
    std::vector<Symbol*> getLabelOrFunctionSymbols(const std::string& name, Namespace* ns) const;

    Symbol* getExternalSymbol(const std::string& name) const;
    void addExternalEntryPoint(Address addr);
    void removeExternalEntryPoint(Address addr);
    bool isExternalEntryPoint(Address addr) const;
    std::vector<Address> getExternalEntryPoints() const;

private:
    Program* program_ = nullptr;
    std::unordered_map<long, std::unique_ptr<Symbol>> symbols_;
    std::unordered_map<std::string, std::vector<Symbol*>> symbolsAtAddr_;
    std::unordered_map<std::string, std::vector<Symbol*>> symbolsByName_;
    std::unordered_map<long, std::unique_ptr<Namespace>> namespaces_;
    std::unique_ptr<Namespace> globalNamespace_;
    std::vector<Address> externalEntryPoints_;
    std::unordered_map<std::string, ContextSymbol*> contextSymbols_;
    long nextID_ = 1;
};

} // namespace ghidra
