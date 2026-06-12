/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Namespace.h
/// \brief Namespace representation for symbol organization
/// Translated from: ghidra.program.model.symbol.Namespace
#pragma once

#include <ghidra/UniversalID.h>
#include <string>
#include <memory>

namespace ghidra {

class Symbol;
class Program;

class Namespace {
public:
    static constexpr long GLOBAL_NAMESPACE_ID = 0;

    Namespace() = default;
    virtual ~Namespace() = default;
    Namespace(const std::string& name, Namespace* parent = nullptr, long id = -1);

    const std::string& getName() const { return name_; }
    void setName(const std::string& name) { name_ = name; }

    Namespace* getParent() const { return parent_; }
    void setParent(Namespace* parent) { parent_ = parent; }

    long getID() const { return id_; }
    void setID(long id) { id_ = id; }

    UniversalID getUniqueID() const { return uniqueID_; }
    void setUniqueID(UniversalID uid) { uniqueID_ = uid; }

    bool isGlobal() const;
    std::string getPathName() const;

    bool operator==(const Namespace& other) const;
    bool operator!=(const Namespace& other) const;

private:
    std::string name_;
    Namespace* parent_ = nullptr;
    long id_ = -1;
    UniversalID uniqueID_;
};

} // namespace ghidra
