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

#include <ghidra/Address.h>
#include <string>
#include <vector>

namespace ghidra {

class ProgramModule;
class CodeUnit;

class Group {
public:
    virtual ~Group() = default;

    virtual std::string getComment() const = 0;
    virtual void setComment(const std::string& comment) = 0;

    virtual std::string getName() const = 0;
    virtual void setName(const std::string& name) = 0;

    virtual bool contains(CodeUnit* codeUnit) const = 0;

    virtual int getNumParents() const = 0;
    virtual std::vector<ProgramModule*> getParents() const = 0;
    virtual std::vector<std::string> getParentNames() const = 0;

    virtual std::string getTreeName() const = 0;
    virtual bool isDeleted() const = 0;

    virtual Address getMinAddress() const = 0;
    virtual Address getMaxAddress() const = 0;
};

} // namespace ghidra
