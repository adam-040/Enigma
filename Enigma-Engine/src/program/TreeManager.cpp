/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/TreeManager.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/DuplicateNameException.h>
#include <ghidra/AddressSet.h>
#include <algorithm>

namespace ghidra {

TreeManager::TreeManager(ProgramDB* program) : program_(program) {
    createDefaultTree();
}

TreeManager::~TreeManager() = default;

void TreeManager::setProgram(Program* program) {
    program_ = dynamic_cast<ProgramDB*>(program);
}

void TreeManager::clearCache(bool all) {
    if (all) {
        treeMap_.clear();
    }
}

void TreeManager::deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) {
    for (auto& pair : treeMap_) {
        pair.second->removeMemoryBlock(startAddr, endAddr);
    }
}

void TreeManager::moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) {
    if (length == 0) return;
    Address fromEnd = fromAddr.add(length - 1);
    for (auto& treePair : treeMap_) {
        for (auto& fragPair : treePair.second->getFragments()) {
            auto* frag = fragPair.second.get();
            if (!frag) continue;
            AddressSet intersection = frag->intersectRange(fromAddr, fromEnd);
            if (!intersection.isEmpty()) {
                frag->getAddressSetInternalMutable().subtract(intersection);
                int64_t diff = static_cast<int64_t>(toAddr.getOffset()) - static_cast<int64_t>(fromAddr.getOffset());
                AddressRangeIterator* iter = intersection.getAddressRanges();
                while (iter->hasNext()) {
                    AddressRange range = iter->next();
                    Address newMin(range.getMinAddress().getAddressSpace(), range.getMinAddress().getOffset() + diff);
                    Address newMax(range.getMaxAddress().getAddressSpace(), range.getMaxAddress().getOffset() + diff);
                    frag->addRange(newMin, newMax);
                }
                delete iter;
            }
        }
        treePair.second->incrementModificationNumber();
    }
}

int TreeManager::getNumEntries() {
    return static_cast<int>(treeMap_.size());
}

ProgramModule* TreeManager::createRootModule(const std::string& treeName) {
    if (treeMap_.find(treeName) != treeMap_.end()) {
        throw DuplicateNameException("Tree already exists: " + treeName);
    }
    long treeID = nextTreeID_++;
    auto mgr = std::make_unique<ModuleManager>(this, treeID, treeName);
    auto* root = mgr->getRootModule();
    treeMap_[treeName] = std::move(mgr);
    revision_++;
    return root;
}

ProgramModule* TreeManager::getRootModule(const std::string& treeName) {
    auto it = treeMap_.find(treeName);
    if (it != treeMap_.end()) {
        return it->second->getRootModule();
    }
    return nullptr;
}

ProgramModule* TreeManager::getRootModule(long treeID) {
    for (auto& pair : treeMap_) {
        if (pair.second->getTreeID() == treeID) {
            return pair.second->getRootModule();
        }
    }
    return nullptr;
}

ProgramModule* TreeManager::getDefaultRootModule() {
    return getRootModule(DEFAULT_TREE_NAME);
}

std::vector<std::string> TreeManager::getTreeNames() const {
    std::vector<std::string> names;
    for (const auto& pair : treeMap_) {
        names.push_back(pair.first);
    }
    std::sort(names.begin(), names.end());
    return names;
}

void TreeManager::renameTree(const std::string& oldName, const std::string& newName) {
    if (oldName == newName) return;
    auto it = treeMap_.find(oldName);
    if (it == treeMap_.end()) return;
    if (treeMap_.find(newName) != treeMap_.end()) {
        throw DuplicateNameException("Tree already exists: " + newName);
    }
    
    auto mgr = std::move(it->second);
    treeMap_.erase(it);
    
    mgr->setTreeName(newName);
    auto* root = dynamic_cast<ModuleDB*>(mgr->getRootModule());
    if (root) {
        mgr->unregisterName(root->getName());
        root->setName(newName);
    }
    
    treeMap_[newName] = std::move(mgr);
    revision_++;
}

bool TreeManager::removeTree(const std::string& treeName) {
    if (treeName == DEFAULT_TREE_NAME) return false;
    auto it = treeMap_.find(treeName);
    if (it != treeMap_.end()) {
        treeMap_.erase(it);
        revision_++;
        return true;
    }
    return false;
}

ProgramModule* TreeManager::getModule(const std::string& treeName, const std::string& name) {
    auto it = treeMap_.find(treeName);
    if (it != treeMap_.end()) {
        return it->second->getModule(name);
    }
    return nullptr;
}

ProgramFragment* TreeManager::getFragment(const std::string& treeName, const std::string& name) {
    auto it = treeMap_.find(treeName);
    if (it != treeMap_.end()) {
        return it->second->getFragment(name);
    }
    return nullptr;
}

ProgramFragment* TreeManager::getFragment(const std::string& treeName, const Address& addr) {
    auto it = treeMap_.find(treeName);
    if (it != treeMap_.end()) {
        return it->second->getFragment(addr);
    }
    return nullptr;
}

void TreeManager::addMemoryBlock(const std::string& name, const AddressRange& range) {
    for (auto& pair : treeMap_) {
        pair.second->addMemoryBlock(name, range);
    }
}

void TreeManager::createDefaultTree() {
    long treeID = nextTreeID_++;
    auto mgr = std::make_unique<ModuleManager>(this, treeID, DEFAULT_TREE_NAME);
    treeMap_[DEFAULT_TREE_NAME] = std::move(mgr);
}

} // namespace ghidra
