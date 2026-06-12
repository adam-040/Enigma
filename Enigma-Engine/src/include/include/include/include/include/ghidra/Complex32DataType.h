/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Complex32DataType.h
/// \brief complex32 data type
#pragma once

#include "AbstractComplexDataType.h"
#include "Float16DataType.h"

namespace ghidra {

class Complex32DataType : public AbstractComplexDataType {
public:
    static Complex32DataType& dataType();

    explicit Complex32DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
