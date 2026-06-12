/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer8DataType.h
/// \brief Factory for generating 8-bit pointers.
#pragma once

#include "PointerDataType.h"

namespace ghidra {

class Pointer8DataType : public PointerDataType {
public:
    static Pointer8DataType& dataType();

    explicit Pointer8DataType(DataType* dt = nullptr, DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
