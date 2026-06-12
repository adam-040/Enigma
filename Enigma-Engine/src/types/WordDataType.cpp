/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WordDataType.cpp
/// \brief Unsigned Word (dw, 2-bytes)
#include "ghidra/WordDataType.h"
#include "ghidra/SignedWordDataType.h"

namespace ghidra {

WordDataType& WordDataType::dataType() {
    static WordDataType instance;
    return instance;
}

WordDataType::WordDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("word", dtm) {}

std::string WordDataType::getDescription() const {
    return "Unsigned Word (dw, 2-bytes)";
}

int WordDataType::getLength() const {
    return 2;
}
std::string WordDataType::getAssemblyMnemonic() const {
    return "dw";
}AbstractIntegerDataType* WordDataType::getOppositeSignednessDataType() const {
    return new SignedWordDataType(getDataTypeManager());
}

DataType* WordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<WordDataType*>(this);
    }
    return new WordDataType(dtm);
}
} // namespace ghidra
