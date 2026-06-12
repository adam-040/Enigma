/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/DuplicateNameException.h>
#include <ghidra/CircularDependencyException.h>
#include <ghidra/AddressSet.h>
#include <algorithm>

namespace ghidra {

ModuleDB::ModuleDB(ModuleManager* moduleMgr, long key, const std::string& name)
    : moduleMgr_(moduleMgr), key_(key), name_(name) {}

void ModuleDB::setName(const std::string& name) {
    if (name == name_) return;
    if (moduleMgr_->checkNameExists(name)) {
        throw DuplicateNameException("Name already exists: " + name);
    }
    moduleMgr_->unregisterName(name_);
    name_ = name;
    moduleMgr_->registerName(name_);
    if (key_ == 0) {
        moduleMgr_->setTreeName(name);
    }
    moduleMgr_->incrementModificationNumber();
}

bool ModuleDB::contains(CodeUnit* codeUnit) const {
    if (!codeUnit) return false;
    auto children = getChildren();
    for (auto* child : children) {
        if (child->contains(codeUnit)) {
            return true;
        }
    }
    return false;
}

int ModuleDB::getNumParents() const {
    return static_cast<int>(moduleMgr_->getParentIDs(key_).size());
}

std::vector<ProgramModule*> ModuleDB::getParents() const {
    std::vector<ProgramModule*> parents;
    auto parentIDs = moduleMgr_->getParentIDs(key_);
    for (long pid : parentIDs) {
        auto it = moduleMgr_->getModules().find(pid);
        if (it != moduleMgr_->getModules().end()) {
            parents.push_back(it->second.get());
        }
    }
    return parents;
}

std::vector<std::string> ModuleDB::getParentNames() const {
    std::vector<std::string> names;
    auto parents = getParents();
    for (auto* p : parents) {
        names.push_back(p->getName());
    }
    return names;
}

std::string ModuleDB::getTreeName() const {
    return moduleMgr_->getTreeName();
}

Address ModuleDB::getMinAddress() const {
    return getAddressSet()->getMinAddress();
}

Address ModuleDB::getMaxAddress() const {
    return getAddressSet()->getMaxAddress();
}

bool ModuleDB::contains(ProgramFragment* fragment) const {
    if (!fragment) return false;
    auto children = moduleMgr_->getChildrenIDs(key_);
    long targetKey = dynamic_cast<FragmentDB*>(fragment)->getKey();
    return std::find(children.begin(), children.end(), targetKey) != children.end();
}

bool ModuleDB::contains(ProgramModule* module) const {
    if (!module) return false;
    auto children = moduleMgr_->getChildrenIDs(key_);
    long targetKey = dynamic_cast<ModuleDB*>(module)->getKey();
    return std::find(children.begin(), children.end(), targetKey) != children.end();
}

int ModuleDB::getNumChildren() const {
    return static_cast<int>(moduleMgr_->getChildrenIDs(key_).size());
}

std::vector<Group*> ModuleDB::getChildren() const {
    std::vector<Group*> children;
    auto childIDs = moduleMgr_->getChildrenIDs(key_);
    for (long cid : childIDs) {
        if (cid >= 0) {
            auto it = moduleMgr_->getModules().find(cid);
            if (it != moduleMgr_->getModules().end()) {
                children.push_back(it->second.get());
            }
        } else {
            auto it = moduleMgr_->getFragments().find(cid);
            if (it != moduleMgr_->getFragments().end()) {
                children.push_back(it->second.get());
            }
        }
    }
    return children;
}

int ModuleDB::getIndex(const std::string& name) const {
    auto childList = getChildren();
    for (size_t i = 0; i < childList.size(); ++i) {
        if (childList[i]->getName() == name) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void ModuleDB::add(ProgramModule* module) {
    if (!module) return;
    auto* modDB = dynamic_cast<ModuleDB*>(module);
    if (!modDB) return;
    if (modDB == this || modDB->isDescendant(this)) {
        throw CircularDependencyException("Circular dependency");
    }
    moduleMgr_->addRelationship(key_, modDB->getKey());
    moduleMgr_->incrementModificationNumber();
}

void ModuleDB::add(ProgramFragment* fragment) {
    if (!fragment) return;
    auto* fragDB = dynamic_cast<FragmentDB*>(fragment);
    if (!fragDB) return;
    moduleMgr_->addRelationship(key_, fragDB->getKey());
    moduleMgr_->incrementModificationNumber();
}

ProgramModule* ModuleDB::createModule(const std::string& moduleName) {
    if (moduleMgr_->checkNameExists(moduleName)) {
        throw DuplicateNameException("Name already exists: " + moduleName);
    }
    return moduleMgr_->createModuleDB(moduleName, this);
}

ProgramFragment* ModuleDB::createFragment(const std::string& fragmentName) {
    if (moduleMgr_->checkNameExists(fragmentName)) {
        throw DuplicateNameException("Name already exists: " + fragmentName);
    }
    return moduleMgr_->createFragmentDB(fragmentName, this);
}

void ModuleDB::reparent(const std::string& name, ProgramModule* oldParent) {
    if (!oldParent) return;
    auto* oldParentDB = dynamic_cast<ModuleDB*>(oldParent);
    if (!oldParentDB) return;
    
    Group* child = nullptr;
    auto oldChildren = oldParentDB->getChildren();
    for (auto* c : oldChildren) {
        if (c->getName() == name) {
            child = c;
            break;
        }
    }
    if (!child) return;
    
    long childKey = 0;
    if (auto* childMod = dynamic_cast<ModuleDB*>(child)) {
        childKey = childMod->getKey();
        if (childMod == this || childMod->isDescendant(this)) {
            throw CircularDependencyException("Circular dependency");
        }
    } else if (auto* childFrag = dynamic_cast<FragmentDB*>(child)) {
        childKey = childFrag->getKey();
    } else {
        return;
    }
    
    moduleMgr_->removeRelationship(oldParentDB->getKey(), childKey);
    moduleMgr_->addRelationship(key_, childKey);
    moduleMgr_->incrementModificationNumber();
}

void ModuleDB::moveChild(const std::string& name, int index) {
    auto children = getChildren();
    long childKey = 0;
    bool found = false;
    for (auto* child : children) {
        if (child->getName() == name) {
            if (auto* childMod = dynamic_cast<ModuleDB*>(child)) {
                childKey = childMod->getKey();
                found = true;
            } else if (auto* childFrag = dynamic_cast<FragmentDB*>(child)) {
                childKey = childFrag->getKey();
                found = true;
            }
            break;
        }
    }
    if (!found) return;
    moduleMgr_->setChildOrder(key_, childKey, index);
    moduleMgr_->incrementModificationNumber();
}

bool ModuleDB::removeChild(const std::string& name) {
    auto children = getChildren();
    long childKey = 0;
    bool found = false;
    for (auto* child : children) {
        if (child->getName() == name) {
            if (auto* childMod = dynamic_cast<ModuleDB*>(child)) {
                childKey = childMod->getKey();
            } else if (auto* childFrag = dynamic_cast<FragmentDB*>(child)) {
                childKey = childFrag->getKey();
            }
            found = true;
            break;
        }
    }
    if (!found) return false;
    
    moduleMgr_->removeRelationship(key_, childKey);
    if (moduleMgr_->getParentIDs(childKey).empty()) {
        moduleMgr_->deleteGroup(childKey);
    }
    moduleMgr_->incrementModificationNumber();
    return true;
}

bool ModuleDB::isDescendant(ProgramModule* module) const {
    if (!module) return false;
    auto children = getChildren();
    for (auto* child : children) {
        auto* childMod = dynamic_cast<ModuleDB*>(child);
        if (childMod) {
            if (childMod == module || childMod->isDescendant(module)) {
                return true;
            }
        }
    }
    return false;
}

bool ModuleDB::isDescendant(ProgramFragment* fragment) const {
    if (!fragment) return false;
    auto children = getChildren();
    for (auto* child : children) {
        auto* childMod = dynamic_cast<ModuleDB*>(child);
        if (childMod) {
            if (childMod->isDescendant(fragment)) {
                return true;
            }
        } else {
            auto* childFrag = dynamic_cast<FragmentDB*>(child);
            if (childFrag && childFrag == fragment) {
                return true;
            }
        }
    }
    return false;
}

Address ModuleDB::getFirstAddress() const {
    return getMinAddress();
}

Address ModuleDB::getLastAddress() const {
    return getMaxAddress();
}

std::shared_ptr<AddressSetView> ModuleDB::getAddressSet() const {
    auto set = std::make_shared<AddressSet>();
    std::vector<const ModuleDB*> queue;
    queue.push_back(this);
    size_t idx = 0;
    while (idx < queue.size()) {
        const ModuleDB* curr = queue[idx++];
        auto children = curr->getChildren();
        for (auto* child : children) {
            if (auto* childMod = dynamic_cast<ModuleDB*>(child)) {
                queue.push_back(childMod);
            } else if (auto* childFrag = dynamic_cast<FragmentDB*>(child)) {
                set->add(childFrag->getAddressSetInternal());
            }
        }
    }
    return set;
}

long ModuleDB::getModificationNumber() const {
    return moduleMgr_->getModificationNumber();
}

long ModuleDB::getTreeID() const {
    return moduleMgr_->getTreeID();
}

} // namespace ghidra
