/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Integer3DataType.cpp
/// \brief Signed 3-Byte Integer
#include "ghidra/Integer3DataType.h"
#include "ghidra/UnsignedInteger3DataType.h"

namespace ghidra {

Integer3DataType& Integer3DataType::dataType() {
    static Integer3DataType instance;
    return instance;
}

Integer3DataType::Integer3DataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int3", dtm) {}

std::string Integer3DataType::getDescription() const {
    return "Signed 3-Byte Integer";
}

int Integer3DataType::getLength() const {
    return 3;
}AbstractIntegerDataType* Integer3DataType::getOppositeSignednessDataType() const {
    return new UnsignedInteger3DataType(getDataTypeManager());
}

DataType* Integer3DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Integer3DataType*>(this);
    }
    return new Integer3DataType(dtm);
}
} // namespace ghidra
