/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Complex8DataType.h
/// \brief complex8 data type
#pragma once

#include "AbstractComplexDataType.h"
#include "Float4DataType.h"

namespace ghidra {

class Complex8DataType : public AbstractComplexDataType {
public:
    static Complex8DataType& dataType();

    explicit Complex8DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
