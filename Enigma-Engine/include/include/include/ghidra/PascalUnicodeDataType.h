/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PascalUnicodeDataType.h
/// \brief String (Pascal UTF-16 64k)
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class PascalUnicodeDataType : public AbstractStringDataType {
public:
    static PascalUnicodeDataType& dataType();

    explicit PascalUnicodeDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
