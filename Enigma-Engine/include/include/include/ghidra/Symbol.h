/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Symbol.h
/// \brief Symbol representation for program symbols
/// Translated from: ghidra.program.model.symbol.Symbol
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Namespace.h>
#include <ghidra/SourceType.h>
#include <ghidra/SymbolType.h>
#include <ghidra/UniversalID.h>
#include <string>
#include <vector>

namespace ghidra {

class Reference;
class Program;

class Symbol {
public:
    Symbol() = default;
    Symbol(const std::string& name, Address address, Namespace* parent,
           SourceType source, SymbolType type, long id = -1);

    const std::string& getName() const { return name_; }
    void setName(const std::string& name) { name_ = name; }

    Address getAddress() const { return address_; }
    void setAddress(Address addr) { address_ = addr; }

    Namespace* getParentNamespace() const { return parent_; }
    void setParentNamespace(Namespace* ns) { parent_ = ns; }

    SourceType getSource() const { return source_; }
    void setSource(SourceType source) { source_ = source; }

    SymbolType getSymbolType() const { return type_; }
    void setSymbolType(SymbolType type) { type_ = type; }

    long getID() const { return id_; }
    void setID(long id) { id_ = id; }

    UniversalID getUniqueID() const { return uniqueID_; }
    void setUniqueID(UniversalID uid) { uniqueID_ = uid; }

    bool isPrimary() const { return isPrimary_; }
    void setPrimary(bool primary) { isPrimary_ = primary; }

    bool isDynamic() const { return isDynamic_; }
    void setDynamic(bool dynamic) { isDynamic_ = dynamic; }

    bool isExternal() const { return isExternal_; }
    void setExternal(bool external) { isExternal_ = external; }

    bool isPinned() const { return isPinned_; }
    void setPinned(bool pinned) { isPinned_ = pinned; }

    bool isGlobal() const;

    const std::vector<Reference*>& getReferences() const { return references_; }
    void addReference(Reference* ref) { references_.push_back(ref); }

    std::string getPathName() const;
    std::string toString() const;

    bool operator==(const Symbol& other) const;
    bool operator!=(const Symbol& other) const;

private:
    std::string name_;
    Address address_;
    Namespace* parent_ = nullptr;
    SourceType source_ = SourceType::DEFAULT;
    SymbolType type_ = SymbolType::LABEL;
    long id_ = -1;
    UniversalID uniqueID_;
    bool isPrimary_ = false;
    bool isDynamic_ = false;
    bool isExternal_ = false;
    bool isPinned_ = false;
    std::vector<Reference*> references_;
};

} // namespace ghidra
