/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalLocation.h
/// \brief Location within an external program (library).
#pragma once

#include "ghidra/Address.h"
#include <cstdint>
#include <string>

namespace ghidra {

class Symbol;
class Namespace;
class Library;
class Function;
class RefType;
class DataType;

/**
 * Defines a location within an external program (i.e., library).
 * Translated from: ghidra.program.model.symbol.ExternalLocation
 */
class ExternalLocation {
public:
    virtual ~ExternalLocation() = default;

    virtual Symbol* getSymbol() const = 0;
    virtual std::string getLibraryName() const = 0;
    virtual std::string getExternalLibraryPath() const = 0;
    virtual Namespace* getParentNameSpace() const = 0;
    virtual std::string getParentName() const = 0;
    virtual std::string getLabel() const = 0;
    virtual std::string getOriginalImportedName() const = 0;
    virtual Address getAddress() const = 0;
    virtual int64_t getAddressOffset() const = 0;
    virtual Function* getFunction() const = 0;
    virtual Library* getLibrary() const = 0;
    virtual int getOrdinal() const = 0;
    virtual std::string getName() const = 0;
    virtual RefType* getReferenceType() const = 0;
    virtual DataType* getDataType() const = 0;
    virtual bool isEquivalent(ExternalLocation* other) const = 0;
};

} // namespace ghidra
