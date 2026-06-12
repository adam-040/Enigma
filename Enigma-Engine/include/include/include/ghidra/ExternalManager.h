/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalManager.h
/// \brief External manager interface
/// Translated from: ghidra.program.model.symbol.ExternalManager
#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>

namespace ghidra {

class Symbol;
class Library;

class ExternalLocation {
public:
    ExternalLocation() = default;
    ExternalLocation(const std::string& libraryName, const std::string& label, Address addr)
        : libraryName_(libraryName), label_(label), address_(addr) {}

    const std::string& getLibraryName() const { return libraryName_; }
    const std::string& getLabel() const { return label_; }
    Address getAddress() const { return address_; }

private:
    std::string libraryName_;
    std::string label_;
    Address address_;
};

class ExternalManager {
public:
    virtual ~ExternalManager() = default;

    virtual ExternalLocation* addExternalLocation(const std::string& libraryName,
                                                   const std::string& label,
                                                   Address addr) = 0;
    virtual ExternalLocation* getExternalLocation(const std::string& libraryName,
                                                   const std::string& label) = 0;
    virtual ExternalLocation* getExternalLocation(Symbol* s) = 0;
    virtual std::vector<ExternalLocation*> getExternalLocations() = 0;
    virtual std::vector<std::string> getExternalLibraryNames() = 0;
    virtual int getExternalLocationCount() = 0;

    virtual Library* getExternalLibrary(const std::string& name) = 0;
    virtual std::vector<Library*> getLibraries() = 0;
};

} // namespace ghidra
