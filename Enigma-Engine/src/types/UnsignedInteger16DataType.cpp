/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedInteger16DataType.cpp
/// \brief Unsigned 16-Byte Integer
#include "ghidra/UnsignedInteger16DataType.h"
#include "ghidra/Integer16DataType.h"

namespace ghidra {

UnsignedInteger16DataType& UnsignedInteger16DataType::dataType() {
    static UnsignedInteger16DataType instance;
    return instance;
}

UnsignedInteger16DataType::UnsignedInteger16DataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint16", dtm) {}

std::string UnsignedInteger16DataType::getDescription() const {
    return "Unsigned 16-Byte Integer";
}

int UnsignedInteger16DataType::getLength() const {
    return 16;
}AbstractIntegerDataType* UnsignedInteger16DataType::getOppositeSignednessDataType() const {
    return new Integer16DataType(getDataTypeManager());
}

DataType* UnsignedInteger16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedInteger16DataType*>(this);
    }
    return new UnsignedInteger16DataType(dtm);
}
} // namespace ghidra
