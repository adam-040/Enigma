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

#include <ghidra/Group.h>
#include <ghidra/ProgramFragment.h>
#include <memory>
#include <vector>

namespace ghidra {

class ProgramModule : public virtual Group {
public:
    virtual ~ProgramModule() = default;

    using Group::contains;

    virtual bool contains(ProgramFragment* fragment) const = 0;
    virtual bool contains(ProgramModule* module) const = 0;

    virtual int getNumChildren() const = 0;
    virtual std::vector<Group*> getChildren() const = 0;

    virtual int getIndex(const std::string& name) const = 0;

    virtual void add(ProgramModule* module) = 0;
    virtual void add(ProgramFragment* fragment) = 0;

    virtual ProgramModule* createModule(const std::string& moduleName) = 0;
    virtual ProgramFragment* createFragment(const std::string& fragmentName) = 0;

    virtual void reparent(const std::string& name, ProgramModule* oldParent) = 0;
    virtual void moveChild(const std::string& name, int index) = 0;
    virtual bool removeChild(const std::string& name) = 0;

    virtual bool isDescendant(ProgramModule* module) const = 0;
    virtual bool isDescendant(ProgramFragment* fragment) const = 0;

    virtual Address getFirstAddress() const = 0;
    virtual Address getLastAddress() const = 0;

    virtual std::shared_ptr<AddressSetView> getAddressSet() const = 0;

    virtual long getModificationNumber() const = 0;
    virtual long getTreeID() const = 0;
};

} // namespace ghidra
