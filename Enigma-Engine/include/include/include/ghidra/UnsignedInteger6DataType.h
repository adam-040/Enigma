/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger6DataType.h
/// \brief Unsigned 6-Byte Integer
#pragma once

#include "AbstractUnsignedIntegerDataType.h"

namespace ghidra {

class Integer6DataType;

class UnsignedInteger6DataType : public AbstractUnsignedIntegerDataType {
public:
    static UnsignedInteger6DataType& dataType();

    explicit UnsignedInteger6DataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;
    int getLength() const override;
    AbstractIntegerDataType* getOppositeSignednessDataType() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
