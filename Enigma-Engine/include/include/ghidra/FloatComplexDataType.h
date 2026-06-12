/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatComplexDataType.h
/// \brief floatcomplex data type
#pragma once

#include "AbstractComplexDataType.h"
#include "FloatDataType.h"

namespace ghidra {

class FloatComplexDataType : public AbstractComplexDataType {
public:
    static FloatComplexDataType& dataType();

    explicit FloatComplexDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
