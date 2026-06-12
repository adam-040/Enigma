/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionSignatureImpl.h
/// \brief Concrete implementation of FunctionSignature
/// Translated from: ghidra.program.model.listing.FunctionSignatureImpl
#pragma once

#include "ghidra/FunctionSignature.h"
#include "ghidra/ParameterDefinition.h"
#include "ghidra/DataType.h"
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class FunctionSignatureImpl : public FunctionSignature {
private:
    std::string name_;
    std::string comment_;
    std::string callingConventionName_;
    DataType* returnType_;
    std::vector<std::unique_ptr<ParameterDefinition>> arguments_;
    bool hasVarArgs_;
    bool hasNoReturn_;

public:
    FunctionSignatureImpl();
    explicit FunctionSignatureImpl(const std::string& name);

    std::string getName() const override;
    void setName(const std::string& name);

    std::string getPrototypeString() const override;
    std::string getPrototypeString(bool includeCallingConvention) const override;

    std::vector<ParameterDefinition*> getArguments() const override;
    void setArguments(const std::vector<ParameterDefinition*>& args);
    void addArgument(ParameterDefinition* arg);
    void clearArguments();

    DataType* getReturnType() const override;
    void setReturnType(DataType* type);

    std::string getComment() const override;
    void setComment(const std::string& comment);

    bool hasVarArgs() const override;
    void setHasVarArgs(bool varArgs);

    bool hasNoReturn() const override;
    void setHasNoReturn(bool noReturn);

    std::string getCallingConventionName() const override;
    void setCallingConventionName(const std::string& name);

    bool isEquivalentSignature(const FunctionSignature* signature) const override;

    FunctionSignatureImpl* clone() const;
};

} // namespace ghidra
