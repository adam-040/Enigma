/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer5DataType.cpp
/// \brief Signed 5-Byte Integer
#include "ghidra/Integer5DataType.h"
#include "ghidra/UnsignedInteger5DataType.h"

namespace ghidra {

Integer5DataType& Integer5DataType::dataType() {
    static Integer5DataType instance;
    return instance;
}

Integer5DataType::Integer5DataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int5", dtm) {}

std::string Integer5DataType::getDescription() const {
    return "Signed 5-Byte Integer";
}

int Integer5DataType::getLength() const {
    return 5;
}AbstractIntegerDataType* Integer5DataType::getOppositeSignednessDataType() const {
    return new UnsignedInteger5DataType(getDataTypeManager());
}

DataType* Integer5DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Integer5DataType*>(this);
    }
    return new Integer5DataType(dtm);
}
} // namespace ghidra
