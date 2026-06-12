/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger3DataType.cpp
/// \brief Unsigned 3-Byte Integer
#include "ghidra/UnsignedInteger3DataType.h"
#include "ghidra/Integer3DataType.h"

namespace ghidra {

UnsignedInteger3DataType& UnsignedInteger3DataType::dataType() {
    static UnsignedInteger3DataType instance;
    return instance;
}

UnsignedInteger3DataType::UnsignedInteger3DataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint3", dtm) {}

std::string UnsignedInteger3DataType::getDescription() const {
    return "Unsigned 3-Byte Integer";
}

int UnsignedInteger3DataType::getLength() const {
    return 3;
}AbstractIntegerDataType* UnsignedInteger3DataType::getOppositeSignednessDataType() const {
    return new Integer3DataType(getDataTypeManager());
}

DataType* UnsignedInteger3DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedInteger3DataType*>(this);
    }
    return new UnsignedInteger3DataType(dtm);
}
} // namespace ghidra
