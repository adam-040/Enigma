/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterBuilder.cpp
/// \brief Register builder implementation
#include <ghidra/RegisterBuilder.h>

namespace ghidra {

void RegisterBuilder::addRegister(const std::string& name, const std::string& description,
                                   Address address, int numBytes, bool bigEndian, int typeFlags) {
    addRegister(name, description, address, numBytes, 0, numBytes * 8, bigEndian, typeFlags);
}

void RegisterBuilder::addRegister(const std::string& name, const std::string& description,
                                   Address address, int numBytes, int leastSignificantBit,
                                   int bitLength, bool bigEndian, int typeFlags) {
    Register reg(name, description, address, numBytes, leastSignificantBit,
                 bitLength, bigEndian, typeFlags);
    addRegister(reg);
}

void RegisterBuilder::addRegister(const Register& reg) {
    const std::string& name = reg.getName();
    registerMap_[name] = registerList_.size();
    registerList_.push_back(reg);
}

void RegisterBuilder::addAlias(const std::string& aliasName, const std::string& originalName) {
    auto it = registerMap_.find(originalName);
    if (it != registerMap_.end()) {
        registerList_[it->second].addAlias(aliasName);
        registerMap_[aliasName] = it->second;
    }
}

std::vector<Register> RegisterBuilder::getRegisters() const { return registerList_; }

Register* RegisterBuilder::getRegister(const std::string& name) {
    auto it = registerMap_.find(name);
    if (it == registerMap_.end()) return nullptr;
    return &registerList_[it->second];
}

Register* RegisterBuilder::getRegister(const Address& addr, int size) {
    for (auto& reg : registerList_) {
        if (reg.getAddress() == addr && reg.getNumBytes() == size) return &reg;
    }
    return nullptr;
}

} // namespace ghidra
