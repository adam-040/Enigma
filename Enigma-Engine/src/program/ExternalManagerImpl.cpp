/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalManagerImpl.cpp
/// \brief Implementation of external manager
/// Translated from: ghidra.program.database.external.ExternalManagerDB

#include <ghidra/ExternalManagerImpl.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolTable.h>

namespace ghidra {

ExternalLocation* ExternalManagerImpl::addExternalLocation(const std::string& libraryName,
                                                            const std::string& label, Address addr) {
    auto loc = std::make_unique<ExternalLocation>(libraryName, label, addr);
    ExternalLocation* raw = loc.get();
    locations_.push_back(std::move(loc));
    locationsByName_[libraryName + "::" + label] = raw;
    libraryNames_.insert(libraryName);
    return raw;
}

ExternalLocation* ExternalManagerImpl::getExternalLocation(const std::string& libraryName,
                                                            const std::string& label) {
    auto it = locationsByName_.find(libraryName + "::" + label);
    return (it != locationsByName_.end()) ? it->second : nullptr;
}

ExternalLocation* ExternalManagerImpl::getExternalLocation(Symbol* s) {
    if (!s || !s->isExternal()) return nullptr;
    std::string libName = s->getParentNamespace() ? s->getParentNamespace()->getName() : "";
    return getExternalLocation(libName, s->getName());
}

std::vector<ExternalLocation*> ExternalManagerImpl::getExternalLocations() {
    std::vector<ExternalLocation*> result;
    for (const auto& loc : locations_) {
        result.push_back(loc.get());
    }
    return result;
}

std::vector<std::string> ExternalManagerImpl::getExternalLibraryNames() {
    return std::vector<std::string>(libraryNames_.begin(), libraryNames_.end());
}

Library* ExternalManagerImpl::getExternalLibrary(const std::string& name) {
    auto it = libraryMap_.find(name);
    if (it != libraryMap_.end()) {
        return it->second.get();
    }
    auto lib = std::make_unique<Library>(name);
    Library* raw = lib.get();
    libraryMap_[name] = std::move(lib);
    return raw;
}

std::vector<Library*> ExternalManagerImpl::getLibraries() {
    std::vector<Library*> result;
    for (auto& pair : libraryMap_) {
        result.push_back(pair.second.get());
    }
    for (const auto& libName : libraryNames_) {
        if (libraryMap_.find(libName) == libraryMap_.end()) {
            auto lib = std::make_unique<Library>(libName);
            Library* raw = lib.get();
            libraryMap_[libName] = std::move(lib);
            result.push_back(raw);
        }
    }
    return result;
}

} // namespace ghidra
