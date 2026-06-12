/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringDataType.h
/// \file StringDataType.h
/// \brief A fixed-length string DataType.
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class StringDataType : public AbstractStringDataType {
public:
    static StringDataType& dataType();

    explicit StringDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
