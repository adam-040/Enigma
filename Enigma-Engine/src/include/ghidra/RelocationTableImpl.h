/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationTableImpl.h
/// \brief Implementation of relocation table
/// Translated from: ghidra.program.database.reloc.RelocationManager
#pragma once

#include <ghidra/RelocationTable.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <list>
#include <unordered_map>

namespace ghidra {

class Program;
class TaskMonitor;

class RelocationTableImpl : public RelocationTable, public ManagerDB {
public:
    RelocationTableImpl() = default;
    explicit RelocationTableImpl(Program* program);

    void setProgram(Program* program) override;
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override;
    void clearCache(bool all) override;
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override;
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override;
    int getNumEntries() override;
    int getRevision() override;
    void setRevision(int revision) override;
    void invalidateCache(bool all) override;
    std::string getName() const override;

    std::vector<Relocation> getRelocations() override;
    std::vector<Relocation> getRelocations(Address addr) override;
    int getRelocationCount() override;
    Relocation* addRelocation(Address addr, long type, const std::string& symbolName);
    Relocation* addRelocation(Address addr, Relocation::Status status, int type,
                              const std::vector<int64_t>& values,
                              const std::vector<uint8_t>& bytes,
                              const std::string& symbolName);

private:
    Program* program_ = nullptr;
    std::list<Relocation> relocations_;
    std::unordered_map<std::string, std::vector<Relocation*>> relocationsByAddr_;
    int revision_ = 0;
};

} // namespace ghidra
