/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionDefinition.h
/// \brief Defines a function signature for things like function pointers.
#pragma once

#include "DataType.h"
#include "FunctionSignature.h"

namespace ghidra {

/**
 * Defines a function signature for things like function pointers.
 * Translated from: ghidra.program.model.data.FunctionDefinition
 */
class FunctionDefinition : public virtual DataType, public virtual FunctionSignature {
public:
    virtual ~FunctionDefinition() = default;

    virtual void setArguments(const std::vector<ParameterDefinition*>& args) = 0;
    virtual void setReturnType(DataType* type) = 0;
    virtual void setComment(const std::string& comment) = 0;
    virtual void setVarArgs(bool hasVarArgs) = 0;
    virtual void setNoReturn(bool hasNoReturn) = 0;
    virtual void setCallingConvention(const std::string& conventionName) = 0;
};

} // namespace ghidra
