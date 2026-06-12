/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DoubleComplexDataType.h
/// \brief doublecomplex data type
#pragma once

#include "AbstractComplexDataType.h"
#include "DoubleDataType.h"

namespace ghidra {

class DoubleComplexDataType : public AbstractComplexDataType {
public:
    static DoubleComplexDataType& dataType();

    explicit DoubleComplexDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
