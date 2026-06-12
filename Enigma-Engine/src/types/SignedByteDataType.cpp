/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SignedByteDataType.cpp
/// \brief Signed Byte data type implementation
#include "ghidra/SignedByteDataType.h"
#include "ghidra/ByteDataType.h"

namespace ghidra {

SignedByteDataType& SignedByteDataType::dataType() {
    static SignedByteDataType instance;
    return instance;
}

SignedByteDataType::SignedByteDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("char", dtm) {}

std::string SignedByteDataType::getDescription() const {
    return "Signed Byte (db)";
}

int SignedByteDataType::getLength() const {
    return 1;
}

std::string SignedByteDataType::getAssemblyMnemonic() const {
    return "db";
}

std::string SignedByteDataType::getDecompilerDisplayName() const {
    return name_;
}

AbstractIntegerDataType* SignedByteDataType::getOppositeSignednessDataType() const {
    return new ByteDataType(getDataTypeManager());
}

DataType* SignedByteDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedByteDataType*>(this);
    }
    return new SignedByteDataType(dtm);
}

} // namespace ghidra
