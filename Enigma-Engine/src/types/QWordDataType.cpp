/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file QWordDataType.cpp
/// \brief Unsigned Quad-Word (dq, 8-bytes)
#include "ghidra/QWordDataType.h"
#include "ghidra/SignedQWordDataType.h"

namespace ghidra {

QWordDataType& QWordDataType::dataType() {
    static QWordDataType instance;
    return instance;
}

QWordDataType::QWordDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("qword", dtm) {}

std::string QWordDataType::getDescription() const {
    return "Unsigned Quad-Word (dq, 8-bytes)";
}

int QWordDataType::getLength() const {
    return 8;
}
std::string QWordDataType::getAssemblyMnemonic() const {
    return "dq";
}AbstractIntegerDataType* QWordDataType::getOppositeSignednessDataType() const {
    return new SignedQWordDataType(getDataTypeManager());
}

DataType* QWordDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<QWordDataType*>(this);
    }
    return new QWordDataType(dtm);
}
} // namespace ghidra
