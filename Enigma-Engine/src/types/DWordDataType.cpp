/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DWordDataType.cpp
/// \brief Unsigned Double-Word (ddw, 4-bytes)
#include "ghidra/DWordDataType.h"
#include "ghidra/SignedDWordDataType.h"

namespace ghidra {

DWordDataType& DWordDataType::dataType() {
    static DWordDataType instance;
    return instance;
}

DWordDataType::DWordDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("dword", dtm) {}

std::string DWordDataType::getDescription() const {
    return "Unsigned Double-Word (ddw, 4-bytes)";
}

int DWordDataType::getLength() const {
    return 4;
}
std::string DWordDataType::getAssemblyMnemonic() const {
    return "ddw";
}AbstractIntegerDataType* DWordDataType::getOppositeSignednessDataType() const {
    return new SignedDWordDataType(getDataTypeManager());
}

DataType* DWordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<DWordDataType*>(this);
    }
    return new DWordDataType(dtm);
}
} // namespace ghidra
