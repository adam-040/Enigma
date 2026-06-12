/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalManagerImpl.h
/// \brief Implementation of external manager
/// Translated from: ghidra.program.database.external.ExternalManagerDB
#pragma once

#include <ghidra/ExternalManager.h>
#include <ghidra/Library.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;
class Symbol;

class ExternalManagerImpl : public ExternalManager, public ManagerDB {
public:
    ExternalManagerImpl() = default;
    explicit ExternalManagerImpl(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { locations_.clear(); locationsByName_.clear(); libraryNames_.clear(); libraryMap_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return getExternalLocationCount(); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "ExternalManager"; }

    ExternalLocation* addExternalLocation(const std::string& libraryName,
                                           const std::string& label, Address addr) override;

    ExternalLocation* getExternalLocation(const std::string& libraryName,
                                           const std::string& label) override;

    ExternalLocation* getExternalLocation(Symbol* s) override;

    std::vector<ExternalLocation*> getExternalLocations() override;

    std::vector<std::string> getExternalLibraryNames() override;

    int getExternalLocationCount() override { return static_cast<int>(locations_.size()); }

    Library* getExternalLibrary(const std::string& name) override;
    std::vector<Library*> getLibraries() override;

private:
    Program* program_ = nullptr;
    std::vector<std::unique_ptr<ExternalLocation>> locations_;
    std::unordered_map<std::string, ExternalLocation*> locationsByName_;
    std::unordered_set<std::string> libraryNames_;
    std::unordered_map<std::string, std::unique_ptr<Library>> libraryMap_;
    int revision_ = 0;
};

} // namespace ghidra
