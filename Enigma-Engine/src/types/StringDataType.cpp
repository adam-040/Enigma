/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringDataType.cpp
/// \brief String data type implementation
#include "ghidra/StringDataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

StringDataType& StringDataType::dataType() {
    static StringDataType instance;
    return instance;
}

StringDataType::StringDataType(DataTypeManager* dtm)
    : AbstractStringDataType("string", "ds", "STRING", "STR", "s",
                             "String (fixed length)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::FIXED_LEN);
}

DataType* StringDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<StringDataType*>(this);
    }
    return new StringDataType(dtm);
}

} // namespace ghidra
