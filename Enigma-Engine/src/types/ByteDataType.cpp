/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ByteDataType.cpp
/// \file ByteDataType.cpp
/// \brief Unsigned Byte data type implementation
#include "ghidra/ByteDataType.h"
#include "ghidra/SignedByteDataType.h"

namespace ghidra {

ByteDataType& ByteDataType::dataType() {
    static ByteDataType instance;
    return instance;
}

ByteDataType::ByteDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("byte", dtm) {}

std::string ByteDataType::getDescription() const {
    return "Unsigned Byte (db)";
}

int ByteDataType::getLength() const {
    return 1;
}

std::string ByteDataType::getAssemblyMnemonic() const {
    return "db";
}

std::string ByteDataType::getDecompilerDisplayName() const {
    return name_;
}

AbstractIntegerDataType* ByteDataType::getOppositeSignednessDataType() const {
    return new SignedByteDataType(getDataTypeManager());
}

DataType* ByteDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<ByteDataType*>(this);
    }
    return new ByteDataType(dtm);
}

} // namespace ghidra
