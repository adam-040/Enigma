/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BasicCompilerSpec.h
/// \brief Concrete CompilerSpec implementation.
/// Translated from: ghidra.program.model.lang.BasicCompilerSpec
#pragma once

#include <ghidra/CompilerSpec.h>
#include <ghidra/CompilerSpecDescription.h>
#include <ghidra/ContextSetting.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/AddressSet.h>
#include <vector>
#include <string>
#include <unordered_map>

namespace ghidra {

class Varnode;
class AddressSpace;

class BasicCompilerSpec : public CompilerSpec {
public:
    BasicCompilerSpec(CompilerSpecDescription* description, SleighLanguage* language);
    ~BasicCompilerSpec() = default;

    // Language integration
    Language* getLanguage() const { return language_; }
    CompilerSpecDescription* getCompilerSpecDescription() const { return description_; }

    std::vector<PrototypeModel*> getAllModels() const override { return allmodels_; }
    std::vector<PrototypeModel*> getCallingConventions() const override { return models_; }
    PrototypeModel* matchConvention(const std::string& name) override;

    // Context settings
    void addContextSetting(const ContextSetting& setting) { ctxSettings_.push_back(setting); }
    const std::vector<ContextSetting>& getContextSettings() const { return ctxSettings_; }

    // Global address check
    bool isGlobal(const Address& addr) const override;

    // Return address
    Varnode* getReturnAddress() const { return returnAddress_; }
    void setReturnAddress(Varnode* addr) { returnAddress_ = addr; }

    // Properties (from CompilerSpecDescription)
    const CompilerSpecDescription& getDescription() const { return *description_; }

    // XML skeleton
    void restoreXml(XmlPullParser& parser);

private:
    CompilerSpecDescription* description_;
    SleighLanguage* language_;
    std::vector<PrototypeModel*> allmodels_;
    std::vector<PrototypeModel*> models_;
    std::vector<ContextSetting> ctxSettings_;
    AddressSet globalSet_;
    Varnode* returnAddress_ = nullptr;
};

} // namespace ghidra
