/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PascalUnicodeDataType.cpp
/// \brief String (Pascal UTF-16 64k)
#include "ghidra/PascalUnicodeDataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

PascalUnicodeDataType& PascalUnicodeDataType::dataType() {
    static PascalUnicodeDataType instance;
    return instance;
}

PascalUnicodeDataType::PascalUnicodeDataType(DataTypeManager* dtm)
    : AbstractStringDataType("PascalUnicode", "p_unicode", "P_UNICODE", "P_UNI", "pu",
                             "String (Pascal UTF-16 64k)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::PASCAL_64k);
}

DataType* PascalUnicodeDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<PascalUnicodeDataType*>(this);
    }
    return new PascalUnicodeDataType(dtm);
}

} // namespace ghidra
