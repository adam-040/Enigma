/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TerminatedUnicodeDataType.cpp
/// \brief String (Null Terminated UTF-16 Unicode)
#include "ghidra/TerminatedUnicodeDataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

TerminatedUnicodeDataType& TerminatedUnicodeDataType::dataType() {
    static TerminatedUnicodeDataType instance;
    return instance;
}

TerminatedUnicodeDataType::TerminatedUnicodeDataType(DataTypeManager* dtm)
    : AbstractStringDataType("TerminatedUnicode", "unicode", "UNICODE", "UNI", "u",
                             "String (Null Terminated UTF-16 Unicode)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::NULL_TERMINATED_UNBOUNDED);
}

DataType* TerminatedUnicodeDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<TerminatedUnicodeDataType*>(this);
    }
    return new TerminatedUnicodeDataType(dtm);
}

} // namespace ghidra
