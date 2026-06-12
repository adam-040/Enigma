/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnicodeDataType.cpp
/// \brief String (Fixed Length UTF-16 Unicode)
#include "ghidra/UnicodeDataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

UnicodeDataType& UnicodeDataType::dataType() {
    static UnicodeDataType instance;
    return instance;
}

UnicodeDataType::UnicodeDataType(DataTypeManager* dtm)
    : AbstractStringDataType("unicode", "unicode", "UNICODE", "UNI", "u",
                             "String (Fixed Length UTF-16 Unicode)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::FIXED_LEN);
}

DataType* UnicodeDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnicodeDataType*>(this);
    }
    return new UnicodeDataType(dtm);
}

} // namespace ghidra
