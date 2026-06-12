/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringUTF8DataType.cpp
/// \brief String (Fixed Length UTF-8 Unicode)
#include "ghidra/StringUTF8DataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

StringUTF8DataType& StringUTF8DataType::dataType() {
    static StringUTF8DataType instance;
    return instance;
}

StringUTF8DataType::StringUTF8DataType(DataTypeManager* dtm)
    : AbstractStringDataType("string-utf8", "utf8", "STRING", "STR", "s",
                             "String (Fixed Length UTF-8 Unicode)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::FIXED_LEN);
}

DataType* StringUTF8DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<StringUTF8DataType*>(this);
    }
    return new StringUTF8DataType(dtm);
}

} // namespace ghidra
