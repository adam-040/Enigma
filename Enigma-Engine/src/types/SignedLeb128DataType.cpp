/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/SignedLeb128DataType.h>

namespace ghidra {

SignedLeb128DataType& SignedLeb128DataType::dataType() {
    static SignedLeb128DataType instance;
    return instance;
}

SignedLeb128DataType::SignedLeb128DataType(DataTypeManager* dtm)
    : AbstractLeb128DataType("sleb128", true, dtm) {}

DataType* SignedLeb128DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SignedLeb128DataType*>(this);
    }
    return new SignedLeb128DataType(dtm);
}

std::string SignedLeb128DataType::getDescription() const {
    return "Signed LEB128-Encoded Number";
}

} // namespace ghidra
