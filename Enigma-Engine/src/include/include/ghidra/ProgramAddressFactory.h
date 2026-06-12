/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramAddressFactory.h
/// \brief Address factory for programs with overlay support
/// Translated from: ghidra.program.database.ProgramAddressFactory
#pragma once

#include <ghidra/AddressFactory.h>
#include <ghidra/AddressMap.h>
#include <ghidra/AddressSetView.h>
#include <vector>
#include <string>
#include <functional>
#include <optional>

namespace ghidra {

class Language;
class CompilerSpec;

class ProgramAddressFactory : public AddressFactory {
public:
    ProgramAddressFactory() = default;
    ProgramAddressFactory(Language* language, CompilerSpec* compilerSpec)
        : language_(language), compilerSpec_(compilerSpec) {}

    std::optional<Address> getAddress(const std::string& addrStr) const override;

    std::vector<Address> getAllAddresses(const std::string& addrStr) const override;

    std::vector<Address> getAllAddresses(const std::string& addrStr, bool caseSensitive) const override;

    const AddressSpace* getDefaultAddressSpace() const override { return defaultSpace_; }

    std::vector<const AddressSpace*> getAddressSpaces() const override;

    std::vector<const AddressSpace*> getAllAddressSpaces() const override;

    const AddressSpace* getAddressSpace(const std::string& name) const override;

    const AddressSpace* getAddressSpace(int spaceID) const override;

    int getNumAddressSpaces() const override { return static_cast<int>(addressSpaces_.size()); }

    bool isValidAddress(const Address& addr) const override;

    uint64_t getIndex(const Address& addr) const override { return addr.getOffset(); }

    const AddressSpace* getPhysicalSpace(const AddressSpace* space) const override { return space; }

    std::vector<const AddressSpace*> getPhysicalSpaces() const override { return getAddressSpaces(); }

    Address getAddress(int spaceID, uint64_t offset) const override;

    const AddressSpace* getConstantSpace() const override { return constantSpace_; }
    void setConstantSpace(AddressSpace* space) { constantSpace_ = space; }

    const AddressSpace* getUniqueSpace() const override { return uniqueSpace_; }
    void setUniqueSpace(AddressSpace* space) { uniqueSpace_ = space; }

    const AddressSpace* getStackSpace() const override { return stackSpace_; }
    void setStackSpace(AddressSpace* space) { stackSpace_ = space; }

    const AddressSpace* getRegisterSpace() const override { return registerSpace_; }
    void setRegisterSpace(AddressSpace* space) { registerSpace_ = space; }

    Address getConstantAddress(uint64_t offset) const override;

    AddressSet getAddressSet(const Address& min, const Address& max) const;
    AddressSet getAddressSet() const;

    Address oldGetAddressFromLong(uint64_t value) const override {
        if (defaultSpace_) return Address(defaultSpace_, static_cast<long>(value));
        return Address();
    }

    bool hasMultipleMemorySpaces() const override;

    bool equals(const AddressFactory& other) const override;

    void addAddressSpace(AddressSpace* space) {
        addressSpaces_.push_back(space);
        if (!defaultSpace_) defaultSpace_ = space;
    }

    void removeAddressSpace(const std::string& name) {
        auto it = std::remove_if(addressSpaces_.begin(), addressSpaces_.end(),
            [&name](AddressSpace* s) { return s->getName() == name; });
        if (it != addressSpaces_.end()) {
            AddressSpace* removed = *it;
            addressSpaces_.erase(it, addressSpaces_.end());
            if (defaultSpace_ == removed) {
                defaultSpace_ = addressSpaces_.empty() ? nullptr : addressSpaces_[0];
            }
            if (constantSpace_ == removed) constantSpace_ = nullptr;
            if (uniqueSpace_ == removed) uniqueSpace_ = nullptr;
            if (registerSpace_ == removed) registerSpace_ = nullptr;
            if (stackSpace_ == removed) stackSpace_ = nullptr;
        }
    }

    void setDefaultSpace(AddressSpace* space) { defaultSpace_ = space; }

    Language* getLanguage() const { return language_; }
    CompilerSpec* getCompilerSpec() const { return compilerSpec_; }

private:
    Address parseAddressWithSpace(const std::string& addrStr, AddressSpace* space) const;

    Language* language_ = nullptr;
    CompilerSpec* compilerSpec_ = nullptr;
    std::vector<AddressSpace*> addressSpaces_;
    AddressSpace* defaultSpace_ = nullptr;
    AddressSpace* constantSpace_ = nullptr;
    AddressSpace* uniqueSpace_ = nullptr;
    AddressSpace* stackSpace_ = nullptr;
    AddressSpace* registerSpace_ = nullptr;
};

} // namespace ghidra
