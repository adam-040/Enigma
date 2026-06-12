/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NamespaceManager.h
/// \brief Manages namespaces in the program
/// Translated from: ghidra.program.database.symbol.NamespaceManager
#pragma once

#include <ghidra/Namespace.h>
#include <ghidra/ManagerDB.h>
#include <unordered_map>
#include <vector>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;

class NamespaceManager : public ManagerDB {
public:
    NamespaceManager() = default;

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override {}
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return static_cast<int>(namespaces_.size()); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override {}
    std::string getName() const override { return "NamespaceManager"; }

    Namespace* createNamespace(Namespace* parent, const std::string& name);

    Namespace* getNamespace(long id) const {
        auto it = namespaces_.find(id);
        return (it != namespaces_.end()) ? it->second.get() : nullptr;
    }

    Namespace* getGlobalNamespace() const { return globalNamespace_.get(); }
    void setGlobalNamespace(std::unique_ptr<Namespace> ns) { globalNamespace_ = std::move(ns); }

    std::vector<Namespace*> getAllNamespaces() const;

private:
    Program* program_ = nullptr;
    std::unordered_map<long, std::unique_ptr<Namespace>> namespaces_;
    std::unique_ptr<Namespace> globalNamespace_;
    long nextID_ = 1;
    int revision_ = 0;
};

} // namespace ghidra
