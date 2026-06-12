/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Unicode32DataType.cpp
/// \brief String (Fixed Length UTF-32 Unicode)
#include "ghidra/Unicode32DataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

Unicode32DataType& Unicode32DataType::dataType() {
    static Unicode32DataType instance;
    return instance;
}

Unicode32DataType::Unicode32DataType(DataTypeManager* dtm)
    : AbstractStringDataType("unicode32", "unicode32", "UNICODE32", "UNI32", "u",
                             "String (Fixed Length UTF-32 Unicode)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::FIXED_LEN);
}

DataType* Unicode32DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Unicode32DataType*>(this);
    }
    return new Unicode32DataType(dtm);
}

} // namespace ghidra
