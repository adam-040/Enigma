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
    return addExternalLocation(libraryName, label, addr, -1, "", false);
}

ExternalLocation* ExternalManagerImpl::addExternalLocation(const std::string& libraryName,
                                                            const std::string& label, Address addr,
                                                            long symbolID,
                                                            const std::string& originalImportName,
                                                            bool isFunction) {
    ExternalLocation* existing = getExternalLocation(libraryName, label);
    if (existing) {
        // (library, label) is the DB's unique key: never duplicate it.  The
        // metadata-less 3-arg form (SQLite/snapshot restore) must not clobber
        // a richer entry, so only refresh when new info is actually supplied.
        if (symbolID < 0 && originalImportName.empty()) {
            return existing;
        }
        for (auto& loc : locations_) {
            if (loc.get() == existing) {
                loc = std::make_unique<ExternalLocation>(libraryName, label, addr, symbolID,
                                                         originalImportName, isFunction);
                ExternalLocation* raw = loc.get();
                locationsByName_[libraryName + "::" + label] = raw;
                return raw;
            }
        }
        return existing;
    }
    auto loc = std::make_unique<ExternalLocation>(libraryName, label, addr, symbolID,
                                                  originalImportName, isFunction);
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

ExternalLocation* ExternalManagerImpl::getExternalLocation(const Address& addr) {
    for (const auto& loc : locations_) {
        if (loc->getAddress() == addr) {
            return loc.get();
        }
    }
    return nullptr;
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

Library* ExternalManagerImpl::addExternalLibrary(const std::string& name,
                                                  const std::string& associatedPath) {
    Library* lib = getExternalLibrary(name);
    if (lib && !associatedPath.empty()) {
        lib->setAssociatedProgramPath(associatedPath);
    }
    libraryNames_.insert(name);
    return lib;
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
