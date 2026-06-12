/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/UnsignedLeb128DataType.h>

namespace ghidra {

UnsignedLeb128DataType& UnsignedLeb128DataType::dataType() {
    static UnsignedLeb128DataType instance;
    return instance;
}

UnsignedLeb128DataType::UnsignedLeb128DataType(DataTypeManager* dtm)
    : AbstractLeb128DataType("uleb128", false, dtm) {}

DataType* UnsignedLeb128DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedLeb128DataType*>(this);
    }
    return new UnsignedLeb128DataType(dtm);
}

std::string UnsignedLeb128DataType::getDescription() const {
    return "Unsigned LEB128-Encoded Number";
}

} // namespace ghidra
