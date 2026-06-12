/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Complex16DataType.h
/// \brief complex16 data type
#pragma once

#include "AbstractComplexDataType.h"
#include "Float8DataType.h"

namespace ghidra {

class Complex16DataType : public AbstractComplexDataType {
public:
    static Complex16DataType& dataType();

    explicit Complex16DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
