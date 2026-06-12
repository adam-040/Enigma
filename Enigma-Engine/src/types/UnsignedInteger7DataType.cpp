/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger7DataType.cpp
/// \brief Unsigned 7-Byte Integer
#include "ghidra/UnsignedInteger7DataType.h"
#include "ghidra/Integer7DataType.h"

namespace ghidra {

UnsignedInteger7DataType& UnsignedInteger7DataType::dataType() {
    static UnsignedInteger7DataType instance;
    return instance;
}

UnsignedInteger7DataType::UnsignedInteger7DataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint7", dtm) {}

std::string UnsignedInteger7DataType::getDescription() const {
    return "Unsigned 7-Byte Integer";
}

int UnsignedInteger7DataType::getLength() const {
    return 7;
}AbstractIntegerDataType* UnsignedInteger7DataType::getOppositeSignednessDataType() const {
    return new Integer7DataType(getDataTypeManager());
}

DataType* UnsignedInteger7DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedInteger7DataType*>(this);
    }
    return new UnsignedInteger7DataType(dtm);
}
} // namespace ghidra
