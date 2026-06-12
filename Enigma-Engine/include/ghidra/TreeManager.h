/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/ManagerDB.h>
#include <ghidra/ProgramModule.h>
#include <ghidra/ProgramFragment.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

namespace ghidra {

class ProgramDB;
class ModuleManager;

class TreeManager : public ManagerDB {
public:
    static constexpr const char* DEFAULT_TREE_NAME = "Program Tree";

    TreeManager() = default;
    explicit TreeManager(ProgramDB* program);
    ~TreeManager() override;

    // ManagerDB implementation
    void setProgram(Program* program) override;
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override;
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override;
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override;
    int getNumEntries() override;
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "TreeManager"; }

    // TreeManager specific API
    ProgramModule* createRootModule(const std::string& treeName);
    ProgramModule* getRootModule(const std::string& treeName);
    ProgramModule* getRootModule(long treeID);
    ProgramModule* getDefaultRootModule();

    std::vector<std::string> getTreeNames() const;
    void renameTree(const std::string& oldName, const std::string& newName);
    bool removeTree(const std::string& treeName);

    ProgramModule* getModule(const std::string& treeName, const std::string& name);
    ProgramFragment* getFragment(const std::string& treeName, const std::string& name);
    ProgramFragment* getFragment(const std::string& treeName, const Address& addr);

    void addMemoryBlock(const std::string& name, const AddressRange& range);

    // Internal getter for database serialization
    const std::unordered_map<std::string, std::unique_ptr<ModuleManager>>& getModules() const { return treeMap_; }
    std::unordered_map<std::string, std::unique_ptr<ModuleManager>>& getModulesMutable() { return treeMap_; }
    long getNextTreeID() const { return nextTreeID_; }
    void setNextTreeID(long nextID) { nextTreeID_ = nextID; }

private:
    void createDefaultTree();

    ProgramDB* program_ = nullptr;
    std::unordered_map<std::string, std::unique_ptr<ModuleManager>> treeMap_;
    int revision_ = 0;
    long nextTreeID_ = 1;
};

} // namespace ghidra
