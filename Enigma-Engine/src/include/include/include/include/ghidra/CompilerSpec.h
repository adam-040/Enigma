/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompilerSpec.h
/// \brief Compiler specification
/// Translated from: ghidra.program.model.lang.CompilerSpec
#pragma once

#include <ghidra/CompilerSpecID.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/DataOrganization.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace ghidra {

class Register;
class AddressSpace;
class Address;
class Language;
class CompilerSpecDescription;
class PcodeInjectLibrary;

class CompilerSpec {
public:
    CompilerSpec() = default;
    explicit CompilerSpec(CompilerSpecID id) : id_(id) {}

    CompilerSpecID getCompilerSpecID() const { return id_; }

    const std::string& getName() const { return name_; }
    void setName(const std::string& name) { name_ = name; }

    DataOrganization* getDataOrganization() const { return dataOrg_.get(); }
    void setDataOrganization(std::unique_ptr<DataOrganization> org) { dataOrg_ = std::move(org); }

    // Properties
    std::string getProperty(const std::string& key) const {
        auto it = properties_.find(key);
        return (it != properties_.end()) ? it->second : std::string();
    }
    std::string getProperty(const std::string& key, const std::string& defaultString) const {
        auto it = properties_.find(key);
        return (it != properties_.end()) ? it->second : defaultString;
    }
    bool hasProperty(const std::string& key) const {
        return properties_.find(key) != properties_.end();
    }
    void setProperty(const std::string& key, const std::string& value) {
        properties_[key] = value;
    }
    const std::unordered_map<std::string, std::string>& getProperties() const { return properties_; }

    // Calling conventions
    std::vector<std::string> getCallingConventionNames() const;

    PrototypeModel* getCallingConvention(const std::string& name) const {
        auto it = callingConventions_.find(name);
        return (it != callingConventions_.end()) ? it->second.get() : nullptr;
    }

    void addCallingConvention(const std::string& name, std::unique_ptr<PrototypeModel> model) {
        callingConventions_[name] = std::move(model);
    }

    PrototypeModel* getDefaultCallingConvention() const {
        if (defaultCallingConventionName_.empty()) return nullptr;
        return getCallingConvention(defaultCallingConventionName_);
    }

    void setDefaultCallingConvention(const std::string& name) {
        defaultCallingConventionName_ = name;
    }

    // Stack / register info
    Register* getStackPointer() const { return stackPointer_; }
    void setStackPointer(Register* reg) { stackPointer_ = reg; }

    Register* getProgramCounter() const { return programCounter_; }
    void setProgramCounter(Register* reg) { programCounter_ = reg; }

    AddressSpace* getStackSpace() const { return stackSpace_; }
    void setStackSpace(AddressSpace* space) { stackSpace_ = space; }

    bool isStackGrowsNegative() const { return stackGrowsNegative_; }
    void setStackGrowsNegative(bool v) { stackGrowsNegative_ = v; }

    bool isStackRightJustified() const { return stackRightJustified_; }
    void setStackRightJustified(bool v) { stackRightJustified_ = v; }

    int getAlignment() const { return alignment_; }
    void setAlignment(int align) { alignment_ = align; }

    bool isBigEndian() const { return bigEndian_; }
    void setBigEndian(bool be) { bigEndian_ = be; }

    // Decompiler integration
    PcodeInjectLibrary* getPcodeInjectLibrary() const { return injectLibrary_; }
    void setPcodeInjectLibrary(PcodeInjectLibrary* lib) { injectLibrary_ = lib; }

    // BasicCompilerSpec-like methods (with default stub returns)
    virtual std::vector<PrototypeModel*> getAllModels() const { return {}; }
    virtual std::vector<PrototypeModel*> getCallingConventions() const { return {}; }
    virtual PrototypeModel* matchConvention(const std::string& name) { return getDefaultCallingConvention(); }
    virtual bool isGlobal(const Address& addr) const { return false; }

private:
    CompilerSpecID id_;
    std::string name_;
    std::unique_ptr<DataOrganization> dataOrg_;
    std::unordered_map<std::string, std::string> properties_;
    std::unordered_map<std::string, std::unique_ptr<PrototypeModel>> callingConventions_;
    std::string defaultCallingConventionName_;
    Register* stackPointer_ = nullptr;
    Register* programCounter_ = nullptr;
    AddressSpace* stackSpace_ = nullptr;
    bool stackGrowsNegative_ = true;
    bool stackRightJustified_ = false;
    int alignment_ = 0;
    bool bigEndian_ = false;
    PcodeInjectLibrary* injectLibrary_ = nullptr;
};

} // namespace ghidra
