/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer3DataType.h
/// \brief Signed 3-Byte Integer
#pragma once

#include "AbstractSignedIntegerDataType.h"

namespace ghidra {

class UnsignedInteger3DataType;

class Integer3DataType : public AbstractSignedIntegerDataType {
public:
    static Integer3DataType& dataType();

    explicit Integer3DataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;
    int getLength() const override;
    AbstractIntegerDataType* getOppositeSignednessDataType() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
