/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolTable.cpp
/// \brief Symbol table implementation for program symbols
#include <ghidra/SymbolTable.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>

namespace ghidra {

SymbolTable::SymbolTable(Program* program) : program_(program) {
    globalNamespace_ = std::make_unique<Namespace>("global", nullptr, Namespace::GLOBAL_NAMESPACE_ID);
}

void SymbolTable::addSymbol(ContextSymbol* sym) {
    if (sym) contextSymbols_[sym->getName()] = sym;
}

ContextSymbol* SymbolTable::getSymbol(const std::string& name) const {
    auto it = contextSymbols_.find(name);
    return (it != contextSymbols_.end()) ? it->second : nullptr;
}

size_t SymbolTable::size() const {
    return contextSymbols_.size() + symbols_.size();
}

std::vector<ContextSymbol*> SymbolTable::getAllSymbols() const {
    std::vector<ContextSymbol*> result;
    for (const auto& pair : contextSymbols_) {
        result.push_back(pair.second);
    }
    return result;
}

Symbol* SymbolTable::createLabel(Address addr, const std::string& name, SourceType source) {
    return createLabel(addr, name, globalNamespace_.get(), source);
}

Symbol* SymbolTable::createLabel(Address addr, const std::string& name, Namespace* ns, SourceType source) {
    if (name.empty()) {
        throw std::invalid_argument("Symbol name cannot be empty");
    }
    for (char c : name) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Symbol name cannot contain whitespace: " + name);
        }
    }
    long id = nextID_++;
    auto sym = std::make_unique<Symbol>(name, addr, ns ? ns : globalNamespace_.get(),
                                        source, SymbolType::LABEL, id);
    sym->setPrimary(symbolsAtAddr_[addr.toString()].empty());
    Symbol* raw = sym.get();
    symbols_[id] = std::move(sym);
    symbolsAtAddr_[addr.toString()].push_back(raw);
    symbolsByName_[name].push_back(raw);
    return raw;
}

bool SymbolTable::removeSymbolSpecial(Symbol* sym) {
    if (!sym) return false;
    long id = sym->getID();
    std::string name = sym->getName();
    std::string addrStr = sym->getAddress().toString();
    if (symbols_.erase(id) > 0) {
        symbolsByName_.erase(name);
        symbolsAtAddr_.erase(addrStr);
        return true;
    }
    return false;
}

Symbol* SymbolTable::getSymbol(long symbolID) const {
    auto it = symbols_.find(symbolID);
    return (it != symbols_.end()) ? it->second.get() : nullptr;
}

Symbol* SymbolTable::getSymbol(const std::string& name, Address addr, Namespace* ns) const {
    auto it = symbolsAtAddr_.find(addr.toString());
    if (it == symbolsAtAddr_.end()) return nullptr;
    for (auto* sym : it->second) {
        if (sym->getName() == name) return sym;
    }
    return nullptr;
}

Symbol* SymbolTable::getGlobalSymbol(const std::string& name, Address addr) const {
    return getSymbol(name, addr, globalNamespace_.get());
}

std::vector<Symbol*> SymbolTable::getGlobalSymbols(const std::string& name) const {
    auto it = symbolsByName_.find(name);
    if (it == symbolsByName_.end()) return {};
    std::vector<Symbol*> result;
    for (auto* sym : it->second) {
        if (sym->isGlobal()) result.push_back(sym);
    }
    return result;
}

SymbolIterator SymbolTable::getSymbols(const std::string& name) const {
    auto it = symbolsByName_.find(name);
    if (it == symbolsByName_.end()) return SymbolIterator();
    return SymbolIterator(it->second);
}

SymbolIterator SymbolTable::getAllProgramSymbols(bool includeDynamic) const {
    std::vector<Symbol*> all;
    for (const auto& pair : symbols_) {
        if (includeDynamic || !pair.second->isDynamic()) {
            all.push_back(pair.second.get());
        }
    }
    return SymbolIterator(all);
}

Symbol* SymbolTable::getPrimarySymbol(Address addr) const {
    auto it = symbolsAtAddr_.find(addr.toString());
    if (it == symbolsAtAddr_.end()) return nullptr;
    for (auto* sym : it->second) {
        if (sym->isPrimary()) return sym;
    }
    return it->second.empty() ? nullptr : it->second[0];
}

std::vector<Symbol*> SymbolTable::getSymbols(Address addr) const {
    auto it = symbolsAtAddr_.find(addr.toString());
    if (it == symbolsAtAddr_.end()) return {};
    auto result = it->second;
    // Primary symbol should be first (matching Java behavior)
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i]->isPrimary()) {
            if (i > 0) {
                std::swap(result[0], result[i]);
            }
            break;
        }
    }
    return result;
}

SymbolIterator SymbolTable::getSymbolsAsIterator(Address addr) const {
    auto it = symbolsAtAddr_.find(addr.toString());
    if (it == symbolsAtAddr_.end()) return SymbolIterator();
    return SymbolIterator(it->second);
}

bool SymbolTable::hasSymbol(Address addr) const {
    return symbolsAtAddr_.count(addr.toString()) > 0;
}

int SymbolTable::getNumSymbols() const {
    return static_cast<int>(symbols_.size());
}

Namespace* SymbolTable::getGlobalNamespace() const {
    return globalNamespace_.get();
}

Namespace* SymbolTable::getNamespace(const std::string& name, Namespace* parent) const {
    Namespace* actualParent = parent ? parent : globalNamespace_.get();
    for (const auto& pair : namespaces_) {
        if (pair.second->getName() == name && pair.second->getParent() == actualParent) {
            return pair.second.get();
        }
    }
    return nullptr;
}

Namespace* SymbolTable::createNameSpace(Namespace* parent, const std::string& name, SourceType source) {
    if (name.empty()) {
        throw std::invalid_argument("Namespace name cannot be empty");
    }
    for (char c : name) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Namespace name cannot contain whitespace: " + name);
        }
    }
    // Check for duplicate namespace with same name and parent
    Namespace* actualParent = parent ? parent : globalNamespace_.get();
    for (const auto& pair : namespaces_) {
        if (pair.second->getName() == name && pair.second->getParent() == actualParent) {
            throw std::invalid_argument("Duplicate namespace name: " + name);
        }
    }
    long id = nextID_++;
    auto ns = std::make_unique<Namespace>(name, actualParent, id);
    Namespace* raw = ns.get();
    namespaces_[id] = std::move(ns);
    return raw;
}

Namespace* SymbolTable::addNamespaceWithId(long id, const std::string& name, Namespace* parent) {
    Namespace* actualParent = parent ? parent : globalNamespace_.get();
    auto ns = std::make_unique<Namespace>(name, actualParent, id);
    Namespace* raw = ns.get();
    namespaces_[id] = std::move(ns);
    if (id >= nextID_) {
        nextID_ = id + 1;
    }
    return raw;
}

std::vector<Symbol*> SymbolTable::getSymbols(Namespace* ns) const {
    std::vector<Symbol*> result;
    for (const auto& pair : symbols_) {
        if (pair.second->getParentNamespace() == ns) {
            result.push_back(pair.second.get());
        }
    }
    return result;
}

std::vector<Symbol*> SymbolTable::getLabelOrFunctionSymbols(const std::string& name, Namespace* ns) const {
    auto it = symbolsByName_.find(name);
    if (it == symbolsByName_.end()) return {};
    std::vector<Symbol*> result;
    for (auto* sym : it->second) {
        if (ns && sym->getParentNamespace() != ns) continue;
        if (isLabelType(sym->getSymbolType()) || isFunctionType(sym->getSymbolType())) {
            result.push_back(sym);
        }
    }
    return result;
}

Symbol* SymbolTable::getExternalSymbol(const std::string& name) const {
    auto it = symbolsByName_.find(name);
    if (it == symbolsByName_.end()) return nullptr;
    for (auto* sym : it->second) {
        if (sym->isExternal()) return sym;
    }
    return nullptr;
}

void SymbolTable::addExternalEntryPoint(Address addr) {
    externalEntryPoints_.push_back(addr);
}

void SymbolTable::removeExternalEntryPoint(Address addr) {
    externalEntryPoints_.erase(
        std::remove(externalEntryPoints_.begin(), externalEntryPoints_.end(), addr),
        externalEntryPoints_.end());
}

bool SymbolTable::isExternalEntryPoint(Address addr) const {
    for (const auto& a : externalEntryPoints_) {
        if (a == addr) return true;
    }
    return false;
}

std::vector<Address> SymbolTable::getExternalEntryPoints() const {
    return externalEntryPoints_;
}

} // namespace ghidra
