/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer6DataType.cpp
/// \brief Signed 6-Byte Integer
#include "ghidra/Integer6DataType.h"
#include "ghidra/UnsignedInteger6DataType.h"

namespace ghidra {

Integer6DataType& Integer6DataType::dataType() {
    static Integer6DataType instance;
    return instance;
}

Integer6DataType::Integer6DataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int6", dtm) {}

std::string Integer6DataType::getDescription() const {
    return "Signed 6-Byte Integer";
}

int Integer6DataType::getLength() const {
    return 6;
}AbstractIntegerDataType* Integer6DataType::getOppositeSignednessDataType() const {
    return new UnsignedInteger6DataType(getDataTypeManager());
}

DataType* Integer6DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Integer6DataType*>(this);
    }
    return new Integer6DataType(dtm);
}
} // namespace ghidra
