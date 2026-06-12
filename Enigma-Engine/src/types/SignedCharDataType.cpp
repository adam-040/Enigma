/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/SignedCharDataType.h"
#include "ghidra/UnsignedCharDataType.h"

namespace ghidra {

SignedCharDataType& SignedCharDataType::dataType() {
    static SignedCharDataType instance;
    return instance;
}

SignedCharDataType::SignedCharDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("schar", dtm) {}

std::string SignedCharDataType::getDescription() const {
    return "Signed Character (ASCII)";
}

int SignedCharDataType::getLength() const {
    return 1;
}

AbstractIntegerDataType* SignedCharDataType::getOppositeSignednessDataType() const {
    return new UnsignedCharDataType(getDataTypeManager());
}

DataType* SignedCharDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedCharDataType*>(this);
    }
    return new SignedCharDataType(dtm);
}

} // namespace ghidra
