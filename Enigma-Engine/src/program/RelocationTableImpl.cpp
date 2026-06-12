/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationTableImpl.cpp
/// \brief Implementation of relocation table
/// Translated from: ghidra.program.database.reloc.RelocationManager

#include <ghidra/RelocationTableImpl.h>
#include <ghidra/TaskMonitor.h>

namespace ghidra {

RelocationTableImpl::RelocationTableImpl(Program* program) : program_(program) {}

void RelocationTableImpl::setProgram(Program* program) { program_ = program; }
void RelocationTableImpl::programReady(int openMode, int currentRevision, TaskMonitor* monitor) {}
void RelocationTableImpl::clearCache(bool all) { if (all) { relocations_.clear(); relocationsByAddr_.clear(); } }
void RelocationTableImpl::deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) {}
void RelocationTableImpl::moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) {}
int RelocationTableImpl::getNumEntries() { return getRelocationCount(); }
int RelocationTableImpl::getRevision() { return revision_; }
void RelocationTableImpl::setRevision(int revision) { revision_ = revision; }
void RelocationTableImpl::invalidateCache(bool all) { clearCache(all); }
std::string RelocationTableImpl::getName() const { return "RelocationTable"; }
int RelocationTableImpl::getRelocationCount() { return static_cast<int>(relocations_.size()); }

std::vector<Relocation> RelocationTableImpl::getRelocations() {
    std::vector<Relocation> result;
    result.reserve(relocations_.size());
    for (const auto& r : relocations_) result.push_back(r);
    return result;
}

std::vector<Relocation> RelocationTableImpl::getRelocations(Address addr) {
    auto it = relocationsByAddr_.find(addr.toString());
    if (it == relocationsByAddr_.end()) return {};
    std::vector<Relocation> result;
    for (auto* r : it->second) result.push_back(*r);
    return result;
}

Relocation* RelocationTableImpl::addRelocation(Address addr, long type, const std::string& symbolName) {
    relocations_.emplace_back(addr, type, symbolName);
    auto& added = relocations_.back();
    relocationsByAddr_[addr.toString()].push_back(&added);
    return &added;
}

} // namespace ghidra
