/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/FragmentDB.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/DuplicateNameException.h>

namespace ghidra {

FragmentDB::FragmentDB(ModuleManager* moduleMgr, long key, const std::string& name)
    : moduleMgr_(moduleMgr), key_(key), name_(name) {}

void FragmentDB::setName(const std::string& name) {
    if (name == name_) return;
    if (moduleMgr_->checkNameExists(name)) {
        throw DuplicateNameException("Name already exists: " + name);
    }
    moduleMgr_->unregisterName(name_);
    name_ = name;
    moduleMgr_->registerName(name_);
    moduleMgr_->incrementModificationNumber();
}

bool FragmentDB::contains(CodeUnit* codeUnit) const {
    if (!codeUnit) return false;
    return contains(codeUnit->getAddress());
}

int FragmentDB::getNumParents() const {
    return static_cast<int>(moduleMgr_->getParentIDs(key_).size());
}

std::vector<ProgramModule*> FragmentDB::getParents() const {
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

std::vector<std::string> FragmentDB::getParentNames() const {
    std::vector<std::string> names;
    auto parents = getParents();
    for (auto* p : parents) {
        names.push_back(p->getName());
    }
    return names;
}

std::string FragmentDB::getTreeName() const {
    return moduleMgr_->getTreeName();
}

void FragmentDB::move(const Address& min, const Address& max) {
    for (const auto& pair : moduleMgr_->getFragments()) {
        if (pair.first != key_ && pair.second) {
            pair.second->removeRange(min, max);
        }
    }
    addRange(min, max);
    moduleMgr_->incrementModificationNumber();
}

} // namespace ghidra
