/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float10DataType.h
/// \brief Float10DataType - IEEE 754 10-byte float
#pragma once

#include "AbstractFloatDataType.h"

namespace ghidra {



class Float10DataType : public AbstractFloatDataType {
public:
    static Float10DataType& dataType();

    explicit Float10DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
