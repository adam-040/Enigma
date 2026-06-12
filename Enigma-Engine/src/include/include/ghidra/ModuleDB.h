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
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class ModuleManager;

class ModuleDB : public ProgramModule {
public:
    ModuleDB(ModuleManager* moduleMgr, long key, const std::string& name);
    ~ModuleDB() override = default;

    // Group implementation
    std::string getComment() const override { return comment_; }
    void setComment(const std::string& comment) override { comment_ = comment; }

    std::string getName() const override { return name_; }
    void setName(const std::string& name) override;

    bool contains(CodeUnit* codeUnit) const override;

    int getNumParents() const override;
    std::vector<ProgramModule*> getParents() const override;
    std::vector<std::string> getParentNames() const override;

    std::string getTreeName() const override;
    bool isDeleted() const override { return deleted_; }
    void setDeleted(bool val) { deleted_ = val; }

    Address getMinAddress() const override;
    Address getMaxAddress() const override;

    // ProgramModule implementation
    bool contains(ProgramFragment* fragment) const override;
    bool contains(ProgramModule* module) const override;

    int getNumChildren() const override;
    std::vector<Group*> getChildren() const override;

    int getIndex(const std::string& name) const override;

    void add(ProgramModule* module) override;
    void add(ProgramFragment* fragment) override;

    ProgramModule* createModule(const std::string& moduleName) override;
    ProgramFragment* createFragment(const std::string& fragmentName) override;

    void reparent(const std::string& name, ProgramModule* oldParent) override;
    void moveChild(const std::string& name, int index) override;
    bool removeChild(const std::string& name) override;

    bool isDescendant(ProgramModule* module) const override;
    bool isDescendant(ProgramFragment* fragment) const override;

    Address getFirstAddress() const override;
    Address getLastAddress() const override;

    std::shared_ptr<AddressSetView> getAddressSet() const override;

    long getModificationNumber() const override;
    long getTreeID() const override;

    long getKey() const { return key_; }

private:
    ModuleManager* moduleMgr_ = nullptr;
    long key_ = 0;
    std::string name_;
    std::string comment_;
    bool deleted_ = false;
};

} // namespace ghidra
