/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer7DataType.cpp
/// \brief Signed 7-Byte Integer
#include "ghidra/Integer7DataType.h"
#include "ghidra/UnsignedInteger7DataType.h"

namespace ghidra {

Integer7DataType& Integer7DataType::dataType() {
    static Integer7DataType instance;
    return instance;
}

Integer7DataType::Integer7DataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int7", dtm) {}

std::string Integer7DataType::getDescription() const {
    return "Signed 7-Byte Integer";
}

int Integer7DataType::getLength() const {
    return 7;
}AbstractIntegerDataType* Integer7DataType::getOppositeSignednessDataType() const {
    return new UnsignedInteger7DataType(getDataTypeManager());
}

DataType* Integer7DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Integer7DataType*>(this);
    }
    return new Integer7DataType(dtm);
}
} // namespace ghidra
