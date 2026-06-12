/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SignedDWordDataType.cpp
/// \brief Signed Double-Word (sddw, 4-bytes)
#include "ghidra/SignedDWordDataType.h"
#include "ghidra/DWordDataType.h"

namespace ghidra {

SignedDWordDataType& SignedDWordDataType::dataType() {
    static SignedDWordDataType instance;
    return instance;
}

SignedDWordDataType::SignedDWordDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("sdword", dtm) {}

std::string SignedDWordDataType::getDescription() const {
    return "Signed Double-Word (sddw, 4-bytes)";
}

int SignedDWordDataType::getLength() const {
    return 4;
}
std::string SignedDWordDataType::getAssemblyMnemonic() const {
    return "sddw";
}AbstractIntegerDataType* SignedDWordDataType::getOppositeSignednessDataType() const {
    return new DWordDataType(getDataTypeManager());
}

DataType* SignedDWordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedDWordDataType*>(this);
    }
    return new SignedDWordDataType(dtm);
}
} // namespace ghidra
