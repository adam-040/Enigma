/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongDoubleComplexDataType.h
/// \brief longdoublecomplex data type
#pragma once

#include "AbstractComplexDataType.h"
#include "LongDoubleDataType.h"

namespace ghidra {

class LongDoubleComplexDataType : public AbstractComplexDataType {
public:
    static LongDoubleComplexDataType& dataType();

    explicit LongDoubleComplexDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
