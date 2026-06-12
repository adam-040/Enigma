/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedCharDataType.cpp
/// \brief Unsigned Character (ASCII)
#include "ghidra/UnsignedCharDataType.h"
#include "ghidra/SignedByteDataType.h"

namespace ghidra {

UnsignedCharDataType& UnsignedCharDataType::dataType() {
    static UnsignedCharDataType instance;
    return instance;
}

UnsignedCharDataType::UnsignedCharDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uchar", dtm) {}

std::string UnsignedCharDataType::getDescription() const {
    return "Unsigned Character (ASCII)";
}

int UnsignedCharDataType::getLength() const {
    return 1;
}

AbstractIntegerDataType* UnsignedCharDataType::getOppositeSignednessDataType() const {
    return new SignedByteDataType(getDataTypeManager());
}

DataType* UnsignedCharDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedCharDataType*>(this);
    }
    return new UnsignedCharDataType(dtm);
}
} // namespace ghidra
