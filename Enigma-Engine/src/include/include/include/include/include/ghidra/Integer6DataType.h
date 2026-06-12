/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer6DataType.h
/// \brief Signed 6-Byte Integer
#pragma once

#include "AbstractSignedIntegerDataType.h"

namespace ghidra {

class UnsignedInteger6DataType;

class Integer6DataType : public AbstractSignedIntegerDataType {
public:
    static Integer6DataType& dataType();

    explicit Integer6DataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;
    int getLength() const override;
    AbstractIntegerDataType* getOppositeSignednessDataType() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
