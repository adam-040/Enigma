/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer16DataType.cpp
/// \brief Signed 16-Byte Integer
#include "ghidra/Integer16DataType.h"
#include "ghidra/UnsignedInteger16DataType.h"

namespace ghidra {

Integer16DataType& Integer16DataType::dataType() {
    static Integer16DataType instance;
    return instance;
}

Integer16DataType::Integer16DataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int16", dtm) {}

std::string Integer16DataType::getDescription() const {
    return "Signed 16-Byte Integer";
}

int Integer16DataType::getLength() const {
    return 16;
}AbstractIntegerDataType* Integer16DataType::getOppositeSignednessDataType() const {
    return new UnsignedInteger16DataType(getDataTypeManager());
}

DataType* Integer16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Integer16DataType*>(this);
    }
    return new Integer16DataType(dtm);
}
} // namespace ghidra
