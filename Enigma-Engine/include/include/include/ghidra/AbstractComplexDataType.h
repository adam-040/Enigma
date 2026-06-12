/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractComplexDataType.h
/// \brief Base class for complex number data types.
#pragma once

#include "BuiltIn.h"
#include "AbstractFloatDataType.h"

namespace ghidra {

class AbstractComplexDataType : public BuiltIn {
protected:
    AbstractFloatDataType* floatType_;

    AbstractComplexDataType(const std::string& name, AbstractFloatDataType* floatType, DataTypeManager* dtm);

public:
    virtual ~AbstractComplexDataType();

    std::string getMnemonic(Settings* settings) const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getDescription() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
};

} // namespace ghidra
