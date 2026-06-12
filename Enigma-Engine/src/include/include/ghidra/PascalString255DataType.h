/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PascalString255DataType.h
/// \brief String (Pascal 255)
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class PascalString255DataType : public AbstractStringDataType {
public:
    static PascalString255DataType& dataType();

    explicit PascalString255DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
