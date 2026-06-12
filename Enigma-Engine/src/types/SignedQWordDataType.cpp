/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SignedQWordDataType.cpp
/// \brief Signed Quad-Word (sdq, 8-bytes)
#include "ghidra/SignedQWordDataType.h"
#include "ghidra/QWordDataType.h"

namespace ghidra {

SignedQWordDataType& SignedQWordDataType::dataType() {
    static SignedQWordDataType instance;
    return instance;
}

SignedQWordDataType::SignedQWordDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("sqword", dtm) {}

std::string SignedQWordDataType::getDescription() const {
    return "Signed Quad-Word (sdq, 8-bytes)";
}

int SignedQWordDataType::getLength() const {
    return 8;
}
std::string SignedQWordDataType::getAssemblyMnemonic() const {
    return "sdq";
}AbstractIntegerDataType* SignedQWordDataType::getOppositeSignednessDataType() const {
    return new QWordDataType(getDataTypeManager());
}

DataType* SignedQWordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedQWordDataType*>(this);
    }
    return new SignedQWordDataType(dtm);
}
} // namespace ghidra
