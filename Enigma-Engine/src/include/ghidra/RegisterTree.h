/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterTree.h
/// \brief Tree representing register parent-child relationships
/// Translated from: ghidra.program.model.lang.RegisterTree
#pragma once

#include <ghidra/Register.h>
#include <string>
#include <vector>

namespace ghidra {

class RegisterTree {
public:
    RegisterTree(Register* reg);
    RegisterTree(const std::string& name, const std::vector<Register*>& regs);
    RegisterTree(const std::string& name, RegisterTree* tree);

    const std::string& getName() const { return name_; }
    Register* getRegister() const { return register_; }
    RegisterTree* getParent() const { return parent_; }
    const std::vector<RegisterTree*>& getChildren() const { return children_; }

    void add(RegisterTree* tree);

    std::string getParentRegisterPath() const;
    std::string getRegisterPath() const;

    RegisterTree* getRegisterTree(Register* reg);
    void remove(Register* reg);

    int compareTo(const RegisterTree& other) const { return name_.compare(other.name_); }

    std::string toString() const;

private:
    static constexpr const char* SEPARATOR = ".";
    Register* register_ = nullptr;
    RegisterTree* parent_ = nullptr;
    std::vector<RegisterTree*> children_;
    std::string name_;
};

} // namespace ghidra
