/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PascalStringDataType.cpp
/// \brief String (Pascal 64k)
#include "ghidra/PascalStringDataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

PascalStringDataType& PascalStringDataType::dataType() {
    static PascalStringDataType instance;
    return instance;
}

PascalStringDataType::PascalStringDataType(DataTypeManager* dtm)
    : AbstractStringDataType("PascalString", "p_string", "P_STRING", "P_STR", "p",
                             "String (Pascal 64k)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::PASCAL_64k);
}

DataType* PascalStringDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<PascalStringDataType*>(this);
    }
    return new PascalStringDataType(dtm);
}

} // namespace ghidra
