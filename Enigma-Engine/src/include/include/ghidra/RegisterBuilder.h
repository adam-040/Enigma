/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterBuilder.h
/// \brief Register builder for constructing register sets
#pragma once

#include <ghidra/Register.h>
#include <ghidra/Address.h>
#include <vector>
#include <unordered_map>
#include <string>

namespace ghidra {

class RegisterBuilder {
public:
    RegisterBuilder() = default;

    void addRegister(const std::string& name, const std::string& description,
                     Address address, int numBytes, bool bigEndian, int typeFlags);
    void addRegister(const std::string& name, const std::string& description,
                     Address address, int numBytes, int leastSignificantBit,
                     int bitLength, bool bigEndian, int typeFlags);
    void addRegister(const Register& reg);
    void addAlias(const std::string& aliasName, const std::string& originalName);
    std::vector<Register> getRegisters() const;
    Register* getRegister(const std::string& name);
    Register* getRegister(const Address& addr, int size);
    void setContextAddress(Address addr) { contextAddress_ = addr; }
    Address getContextAddress() const { return contextAddress_; }

private:
    std::vector<Register> registerList_;
    std::unordered_map<std::string, size_t> registerMap_;
    Address contextAddress_;
};

} // namespace ghidra
