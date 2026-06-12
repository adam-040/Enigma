/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/TreeManager.h>
#include <algorithm>

namespace ghidra {

ModuleManager::ModuleManager(TreeManager* treeMgr, long treeID, const std::string& treeName)
    : treeMgr_(treeMgr), treeID_(treeID), treeName_(treeName) {
    createRootModule();
}

ModuleManager::~ModuleManager() = default;

ProgramModule* ModuleManager::getRootModule() {
    auto it = modules_.find(0);
    if (it != modules_.end()) {
        return it->second.get();
    }
    return nullptr;
}

ProgramModule* ModuleManager::getModule(const std::string& name) {
    for (const auto& pair : modules_) {
        if (pair.second->getName() == name) {
            return pair.second.get();
        }
    }
    return nullptr;
}

ProgramFragment* ModuleManager::getFragment(const std::string& name) {
    for (const auto& pair : fragments_) {
        if (pair.second->getName() == name) {
            return pair.second.get();
        }
    }
    return nullptr;
}

ProgramFragment* ModuleManager::getFragment(const Address& addr) {
    for (const auto& pair : fragments_) {
        if (pair.second->contains(addr)) {
            return pair.second.get();
        }
    }
    return nullptr;
}

void ModuleManager::addMemoryBlock(const std::string& name, const AddressRange& range) {
    ProgramFragment* frag = getFragment(name);
    if (!frag) {
        auto* root = getRootModule();
        frag = root->createFragment(name);
    }
    auto* fragDB = dynamic_cast<FragmentDB*>(frag);
    if (fragDB) {
        // Also remove this range from all other fragments to enforce single-fragment rule
        for (const auto& pair : fragments_) {
            if (pair.second.get() != fragDB) {
                pair.second->removeRange(range.getMinAddress(), range.getMaxAddress());
            }
        }
        fragDB->addRange(range);
    }
    incrementModificationNumber();
}

void ModuleManager::removeMemoryBlock(const Address& start, const Address& end) {
    for (auto& pair : fragments_) {
        if (pair.second) {
            pair.second->removeRange(start, end);
        }
    }
    incrementModificationNumber();
}

ModuleDB* ModuleManager::createModuleDB(const std::string& name, ModuleDB* parent) {
    long key = nextModuleID_++;
    auto mod = std::make_unique<ModuleDB>(this, key, name);
    auto* ptr = mod.get();
    modules_[key] = std::move(mod);
    names_.insert(name);
    if (parent) {
        addRelationship(parent->getKey(), key);
    }
    incrementModificationNumber();
    return ptr;
}

FragmentDB* ModuleManager::createFragmentDB(const std::string& name, ModuleDB* parent) {
    long key = nextFragmentID_--;
    auto frag = std::make_unique<FragmentDB>(this, key, name);
    auto* ptr = frag.get();
    fragments_[key] = std::move(frag);
    names_.insert(name);
    if (parent) {
        addRelationship(parent->getKey(), key);
    }
    incrementModificationNumber();
    return ptr;
}

bool ModuleManager::checkNameExists(const std::string& name) const {
    return names_.find(name) != names_.end();
}

void ModuleManager::addRelationship(long parentID, long childID, int orderIdx) {
    std::vector<size_t> childIndices;
    for (size_t i = 0; i < relationships_.size(); ++i) {
        if (relationships_[i].first == parentID) {
            childIndices.push_back(i);
        }
    }
    if (orderIdx < 0 || orderIdx >= static_cast<int>(childIndices.size())) {
        if (childIndices.empty()) {
            relationships_.push_back({parentID, childID});
        } else {
            relationships_.insert(relationships_.begin() + childIndices.back() + 1, {parentID, childID});
        }
    } else {
        relationships_.insert(relationships_.begin() + childIndices[orderIdx], {parentID, childID});
    }
}

void ModuleManager::removeRelationship(long parentID, long childID) {
    auto it = std::remove_if(relationships_.begin(), relationships_.end(),
        [parentID, childID](const std::pair<long, long>& rel) {
            return rel.first == parentID && rel.second == childID;
        });
    relationships_.erase(it, relationships_.end());
}

std::vector<long> ModuleManager::getChildrenIDs(long parentID) const {
    std::vector<long> children;
    for (const auto& rel : relationships_) {
        if (rel.first == parentID) {
            children.push_back(rel.second);
        }
    }
    return children;
}

std::vector<long> ModuleManager::getParentIDs(long childID) const {
    std::vector<long> parents;
    for (const auto& rel : relationships_) {
        if (rel.second == childID) {
            parents.push_back(rel.first);
        }
    }
    return parents;
}

void ModuleManager::setChildOrder(long parentID, long childID, int newIdx) {
    std::vector<size_t> childIndices;
    for (size_t i = 0; i < relationships_.size(); ++i) {
        if (relationships_[i].first == parentID) {
            childIndices.push_back(i);
        }
    }
    if (childIndices.empty()) return;
    
    int currentIdx = -1;
    for (size_t i = 0; i < childIndices.size(); ++i) {
        if (relationships_[childIndices[i]].second == childID) {
            currentIdx = static_cast<int>(i);
            break;
        }
    }
    if (currentIdx == -1) return;
    if (newIdx < 0) newIdx = 0;
    if (newIdx >= static_cast<int>(childIndices.size())) {
        newIdx = static_cast<int>(childIndices.size()) - 1;
    }
    if (currentIdx == newIdx) return;
    
    auto rel = relationships_[childIndices[currentIdx]];
    relationships_.erase(relationships_.begin() + childIndices[currentIdx]);
    
    childIndices.clear();
    for (size_t i = 0; i < relationships_.size(); ++i) {
        if (relationships_[i].first == parentID) {
            childIndices.push_back(i);
        }
    }
    if (childIndices.empty() || newIdx >= static_cast<int>(childIndices.size())) {
        relationships_.push_back(rel);
    } else {
        relationships_.insert(relationships_.begin() + childIndices[newIdx], rel);
    }
}

ModuleDB* ModuleManager::loadModule(long id, const std::string& name, const std::string& comment) {
    if (id == 0) {
        auto it = modules_.find(0);
        if (it != modules_.end()) {
            names_.erase(it->second->getName());
            it->second->setName(name);
            it->second->setComment(comment);
            names_.insert(name);
            return it->second.get();
        }
    }
    auto mod = std::make_unique<ModuleDB>(this, id, name);
    mod->setComment(comment);
    auto* ptr = mod.get();
    names_.erase(name);
    modules_[id] = std::move(mod);
    names_.insert(name);
    if (id >= nextModuleID_) {
        nextModuleID_ = id + 1;
    }
    return ptr;
}

FragmentDB* ModuleManager::loadFragment(long id, const std::string& name, const std::string& comment) {
    auto frag = std::make_unique<FragmentDB>(this, id, name);
    frag->setComment(comment);
    auto* ptr = frag.get();
    names_.erase(name);
    fragments_[id] = std::move(frag);
    names_.insert(name);
    if (id <= nextFragmentID_) {
        nextFragmentID_ = id - 1;
    }
    return ptr;
}

void ModuleManager::createRootModule() {
    auto root = std::make_unique<ModuleDB>(this, 0, treeName_);
    modules_[0] = std::move(root);
    names_.insert(treeName_);
}

void ModuleManager::deleteGroup(long key) {
    if (key < 0) {
        auto it = fragments_.find(key);
        if (it != fragments_.end()) {
            names_.erase(it->second->getName());
            fragments_.erase(it);
        }
        auto relIt = std::remove_if(relationships_.begin(), relationships_.end(),
            [key](const std::pair<long, long>& rel) {
                return rel.second == key;
            });
        relationships_.erase(relIt, relationships_.end());
    } else {
        auto it = modules_.find(key);
        if (it != modules_.end()) {
            names_.erase(it->second->getName());
            auto childIDs = getChildrenIDs(key);
            auto relIt = std::remove_if(relationships_.begin(), relationships_.end(),
                [key](const std::pair<long, long>& rel) {
                    return rel.first == key || rel.second == key;
                });
            relationships_.erase(relIt, relationships_.end());
            
            for (long cid : childIDs) {
                if (getParentIDs(cid).empty()) {
                    deleteGroup(cid);
                }
            }
            modules_.erase(it);
        }
    }
}

} // namespace ghidra
