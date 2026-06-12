/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NamespaceManager.cpp
/// \brief Manages namespaces in the program
/// Translated from: ghidra.program.database.symbol.NamespaceManager

#include <ghidra/NamespaceManager.h>

namespace ghidra {

Namespace* NamespaceManager::createNamespace(Namespace* parent, const std::string& name) {
    long id = nextID_++;
    auto ns = std::make_unique<Namespace>(name, parent ? parent : globalNamespace_.get(), id);
    Namespace* raw = ns.get();
    namespaces_[id] = std::move(ns);
    return raw;
}

std::vector<Namespace*> NamespaceManager::getAllNamespaces() const {
    std::vector<Namespace*> result;
    for (const auto& pair : namespaces_) {
        result.push_back(pair.second.get());
    }
    return result;
}

} // namespace ghidra
