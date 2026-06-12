/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionDefinitionDataType.h
/// \brief Definition of a function for things like function pointers.
#pragma once

#include "GenericDataType.h"
#include "FunctionDefinition.h"
#include "ParameterDefinitionImpl.h"
#include "GenericCallingConvention.h"

namespace ghidra {

class FunctionDefinitionDataType : public GenericDataType, public virtual FunctionDefinition {
protected:
    DataType* returnType_;
    std::vector<ParameterDefinition*> params_;
    std::string comment_;
    bool hasVarArgs_;
    bool hasNoReturn_;
    bool ownsReturnType_;
    std::string callingConventionName_;

    static void deleteOwnedParameter(ParameterDefinition* param);

    void clearArguments();

    void assignReturnType(DataType* type, bool ownsReturnType);

    void copySignature(const FunctionSignature* sig);

public:
    FunctionDefinitionDataType(const std::string& name, DataTypeManager* dtm = nullptr);

    FunctionDefinitionDataType(const CategoryPath& path, const std::string& name, const FunctionSignature* sig = nullptr, DataTypeManager* dtm = nullptr);

    virtual ~FunctionDefinitionDataType();

    void setArguments(const std::vector<ParameterDefinition*>& args) override;

    void setReturnType(DataType* type) override;

    void setComment(const std::string& comment) override;

    void setVarArgs(bool hasVarArgs) override;

    void setNoReturn(bool hasNoReturn) override;

    void setCallingConvention(const std::string& conventionName) override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    std::string getMnemonic(Settings* settings) const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    std::string getPrototypeString() const override;

    std::string getPrototypeString(bool includeCallingConvention) const override;

    std::vector<ParameterDefinition*> getArguments() const override;

    DataType* getReturnType() const override;

    std::string getComment() const override;

    bool hasVarArgs() const override;

    bool hasNoReturn() const override;

    std::string getCallingConventionName() const override;

    bool isEquivalent(const DataType* dt) const override;

    bool isEquivalentSignature(const FunctionSignature* signature) const override;

    std::string getName() const override;
};

} // namespace ghidra
