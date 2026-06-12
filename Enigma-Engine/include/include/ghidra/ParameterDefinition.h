/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParameterDefinition.h
/// \brief Specifies a parameter for a function definition.
#pragma once

#include "DataType.h"

namespace ghidra {

/**
 * ParameterDefinition specifies a parameter which can be
 * used to specify a function definition.
 * Translated from: ghidra.program.model.data.ParameterDefinition
 */
class ParameterDefinition {
public:
    virtual ~ParameterDefinition() = default;

    virtual int getOrdinal() const = 0;
    virtual DataType* getDataType() const = 0;
    virtual void setDataType(DataType* type) = 0;
    
    virtual std::string getName() const = 0;
    virtual int getLength() const = 0;
    virtual void setName(const std::string& name) = 0;
    
    virtual std::string getComment() const = 0;
    virtual void setComment(const std::string& comment) = 0;
    
    virtual bool isEquivalent(const ParameterDefinition* parm) const = 0;
};

} // namespace ghidra
