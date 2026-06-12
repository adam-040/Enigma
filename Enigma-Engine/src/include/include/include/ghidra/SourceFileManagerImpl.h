/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceFileManagerImpl.h
/// \brief Implementation of source file manager
/// Translated from: ghidra.program.database.sourcemap.SourceFileManagerDB
#pragma once

#include <ghidra/SourceFileManager.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <unordered_map>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;

class SourceFileManagerImpl : public SourceFileManager, public ManagerDB {
public:
    SourceFileManagerImpl() = default;
    explicit SourceFileManagerImpl(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { 
        if (all) { 
            files_.clear(); 
            filesByPath_.clear(); 
            entries_.clear();
        } 
    }
    
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override;
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override;
    
    int getNumEntries() override { return getSourceFileCount(); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "SourceFileManager"; }

    // Legacy interface
    SourceFile* addSourceFile(const std::string& path, const std::string& compilerSpec) override;
    SourceFile* getSourceFile(const std::string& path) override;
    std::vector<SourceFile*> getSourceFiles() override;
    int getSourceFileCount() override { return static_cast<int>(files_.size()); }

    // Rich source mapping interface
    std::vector<SourceMapEntry> getSourceMapEntries(const Address& addr) override;
    SourceMapEntry addSourceMapEntry(SourceFile* sourceFile, int lineNumber, const Address& baseAddr, uint64_t length) override;
    bool intersectsSourceMapEntry(const AddressSetView& addrs) override;
    
    bool addSourceFile(SourceFile* sourceFile) override;
    bool removeSourceFile(SourceFile* sourceFile) override;
    bool containsSourceFile(SourceFile* sourceFile) override;
    
    std::vector<SourceFile*> getAllSourceFiles() override;
    std::vector<SourceFile*> getMappedSourceFiles() override;
    
    void transferSourceMapEntries(SourceFile* source, SourceFile* target) override;
    SourceMapEntryIterator getSourceMapEntryIterator(const Address& address, bool forward) override;
    
    std::vector<SourceMapEntry> getSourceMapEntries(SourceFile* sourceFile, int minLine, int maxLine) override;
    bool removeSourceMapEntry(const SourceMapEntry& entry) override;

    // Helper for SQLite round-trip
    const std::vector<SourceMapEntry>& getSourceMapEntriesDirect() const { return entries_; }
    void addSourceMapEntryDirect(const SourceMapEntry& entry) { entries_.push_back(entry); }

private:
    Program* program_ = nullptr;
    std::vector<std::unique_ptr<SourceFile>> files_;
    std::unordered_map<std::string, SourceFile*> filesByPath_;
    std::vector<SourceMapEntry> entries_;
    int revision_ = 0;
};

} // namespace ghidra
