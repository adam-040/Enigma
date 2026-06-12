/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger6DataType.cpp
/// \brief Unsigned 6-Byte Integer
#include "ghidra/UnsignedInteger6DataType.h"
#include "ghidra/Integer6DataType.h"

namespace ghidra {

UnsignedInteger6DataType& UnsignedInteger6DataType::dataType() {
    static UnsignedInteger6DataType instance;
    return instance;
}

UnsignedInteger6DataType::UnsignedInteger6DataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint6", dtm) {}

std::string UnsignedInteger6DataType::getDescription() const {
    return "Unsigned 6-Byte Integer";
}

int UnsignedInteger6DataType::getLength() const {
    return 6;
}AbstractIntegerDataType* UnsignedInteger6DataType::getOppositeSignednessDataType() const {
    return new Integer6DataType(getDataTypeManager());
}

DataType* UnsignedInteger6DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedInteger6DataType*>(this);
    }
    return new UnsignedInteger6DataType(dtm);
}
} // namespace ghidra
