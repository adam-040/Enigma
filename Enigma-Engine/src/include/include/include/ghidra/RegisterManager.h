/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterManager.h
/// \brief Manages all processor registers — builds trees, maps names, handles lookups
/// Translated from: ghidra.program.model.lang.RegisterManager
#pragma once

#include <ghidra/Register.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSetViewAdapter.h>
#include <ghidra/AddressSpace.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

namespace ghidra {

class RegisterManager {
public:
    RegisterManager(const std::vector<Register*>& registers,
                    const std::unordered_map<std::string, Register*>& registerNameMap);

    Register* getContextBaseRegister() const { return contextBaseRegister_; }
    const std::vector<Register*>& getContextRegisters() const { return contextRegisters_; }
    const std::vector<std::string>& getRegisterNames() const { return registerNames_; }

    Register* getRegister(Address addr);
    Register* getRegister(Address addr, int size);
    Register* getRegister(const std::string& name);

    std::vector<Register*> getRegisters(Address addr);

    const std::vector<Register*>& getRegisters() const { return registers_; }
    const std::vector<Register*>& getSortedVectorRegisters();

    AddressSetView* getRegisterAddresses() { return &registerAddressesView_; }

private:
    struct RegisterSizeKey {
        Address address;
        int size;
        bool operator==(const RegisterSizeKey& other) const {
            return address == other.address && size == other.size;
        }
        bool operator<(const RegisterSizeKey& other) const {
            if (address == other.address) return size < other.size;
            return address < other.address;
        }
    };

    std::vector<Register*> registers_;
    std::unordered_map<std::string, Register*> registerNameMap_;
    std::vector<std::string> registerNames_;
    std::vector<Register*> contextRegisters_;
    Register* contextBaseRegister_ = nullptr;

    std::map<RegisterSizeKey, Register*> sizeMap_;
    std::unordered_map<Address, std::vector<Register*>> registerAddressMap_;
    AddressSet registerAddresses_;
    AddressSetViewAdapter registerAddressesView_;

    mutable std::vector<Register*> sortedVectorRegisters_;
    mutable bool sortedVectorRegistersValid_ = false;

    void initialize();
    void addRegisterAddresses(Register* reg);
    void populateSizeMapBigEndian(Register* reg);
    void populateSizeMapLittleEndian(Register* reg);
    static bool compareVectorRegisters(Register* reg1, Register* reg2);
};

} // namespace ghidra
