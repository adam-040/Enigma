/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnicodeDataType.h
/// \brief String (Fixed Length UTF-16 Unicode)
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class UnicodeDataType : public AbstractStringDataType {
public:
    static UnicodeDataType& dataType();

    explicit UnicodeDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
