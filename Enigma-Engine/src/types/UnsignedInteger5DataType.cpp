/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger5DataType.cpp
/// \brief Unsigned 5-Byte Integer
#include "ghidra/UnsignedInteger5DataType.h"
#include "ghidra/Integer5DataType.h"

namespace ghidra {

UnsignedInteger5DataType& UnsignedInteger5DataType::dataType() {
    static UnsignedInteger5DataType instance;
    return instance;
}

UnsignedInteger5DataType::UnsignedInteger5DataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint5", dtm) {}

std::string UnsignedInteger5DataType::getDescription() const {
    return "Unsigned 5-Byte Integer";
}

int UnsignedInteger5DataType::getLength() const {
    return 5;
}AbstractIntegerDataType* UnsignedInteger5DataType::getOppositeSignednessDataType() const {
    return new Integer5DataType(getDataTypeManager());
}

DataType* UnsignedInteger5DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedInteger5DataType*>(this);
    }
    return new UnsignedInteger5DataType(dtm);
}
} // namespace ghidra
