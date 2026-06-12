/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SignedWordDataType.cpp
/// \brief Signed Word (sdw, 2-bytes)
#include "ghidra/SignedWordDataType.h"
#include "ghidra/WordDataType.h"

namespace ghidra {

SignedWordDataType& SignedWordDataType::dataType() {
    static SignedWordDataType instance;
    return instance;
}

SignedWordDataType::SignedWordDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("sword", dtm) {}

std::string SignedWordDataType::getDescription() const {
    return "Signed Word (sdw, 2-bytes)";
}

int SignedWordDataType::getLength() const {
    return 2;
}
std::string SignedWordDataType::getAssemblyMnemonic() const {
    return "sdw";
}AbstractIntegerDataType* SignedWordDataType::getOppositeSignednessDataType() const {
    return new WordDataType(getDataTypeManager());
}

DataType* SignedWordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedWordDataType*>(this);
    }
    return new SignedWordDataType(dtm);
}
} // namespace ghidra
