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

#include <ghidra/ProgramModule.h>
#include <ghidra/ProgramFragment.h>
#include <ghidra/AddressRange.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>

namespace ghidra {

class TreeManager;
class ModuleDB;
class FragmentDB;
class ProgramDB;

class ModuleManager {
public:
    ModuleManager(TreeManager* treeMgr, long treeID, const std::string& treeName);
    ~ModuleManager();

    long getTreeID() const { return treeID_; }
    const std::string& getTreeName() const { return treeName_; }
    void setTreeName(const std::string& name) { treeName_ = name; }

    long getModificationNumber() const { return modificationNumber_; }
    void incrementModificationNumber() { modificationNumber_++; }
    void setModificationNumber(long val) { modificationNumber_ = val; }

    ProgramModule* getRootModule();

    ProgramModule* getModule(const std::string& name);
    ProgramFragment* getFragment(const std::string& name);
    ProgramFragment* getFragment(const Address& addr);

    void addMemoryBlock(const std::string& name, const AddressRange& range);
    void removeMemoryBlock(const Address& start, const Address& end);

    // Tree mutation helper functions called by ModuleDB/FragmentDB
    ModuleDB* createModuleDB(const std::string& name, ModuleDB* parent);
    FragmentDB* createFragmentDB(const std::string& name, ModuleDB* parent);
    bool checkNameExists(const std::string& name) const;
    void registerName(const std::string& name) { names_.insert(name); }
    void unregisterName(const std::string& name) { names_.erase(name); }

    // Relationship helpers
    void addRelationship(long parentID, long childID, int orderIdx = -1);
    void removeRelationship(long parentID, long childID);
    std::vector<long> getChildrenIDs(long parentID) const;
    std::vector<long> getParentIDs(long childID) const;
    void setChildOrder(long parentID, long childID, int newIdx);

    // Factories for database loading
    ModuleDB* loadModule(long id, const std::string& name, const std::string& comment);
    FragmentDB* loadFragment(long id, const std::string& name, const std::string& comment);
    void deleteGroup(long key);

    // Cache management
    const std::unordered_map<long, std::unique_ptr<ModuleDB>>& getModules() const { return modules_; }
    const std::unordered_map<long, std::unique_ptr<FragmentDB>>& getFragments() const { return fragments_; }
    const std::vector<std::pair<long, long>>& getRawRelationships() const { return relationships_; } // parent_id, child_id
    
private:
    TreeManager* treeMgr_ = nullptr;
    long treeID_ = 0;
    std::string treeName_;
    long modificationNumber_ = 0;
    long nextModuleID_ = 1;      // Positive values (starting at 1, root is 0)
    long nextFragmentID_ = -1;   // Negative values (starting at -1)

    std::unordered_map<long, std::unique_ptr<ModuleDB>> modules_;
    std::unordered_map<long, std::unique_ptr<FragmentDB>> fragments_;
    std::unordered_set<std::string> names_;

    // Parent-child relationships: pair represents (parentID, childID)
    std::vector<std::pair<long, long>> relationships_;

    void createRootModule();
};

} // namespace ghidra
