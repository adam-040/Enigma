/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float4DataType.h
/// \brief Float4DataType - IEEE 754 4-byte float
#pragma once

#include "AbstractFloatDataType.h"

namespace ghidra {



class Float4DataType : public AbstractFloatDataType {
public:
    static Float4DataType& dataType();

    explicit Float4DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
