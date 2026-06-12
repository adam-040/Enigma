/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Unicode32DataType.h
/// \brief String (Fixed Length UTF-32 Unicode)
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class Unicode32DataType : public AbstractStringDataType {
public:
    static Unicode32DataType& dataType();

    explicit Unicode32DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
