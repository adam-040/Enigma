/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/TerminatedUnicode32DataType.h>
#include <ghidra/WideChar32DataType.h>
#include <ghidra/StringLayoutEnum.h>

namespace ghidra {

TerminatedUnicode32DataType& TerminatedUnicode32DataType::dataType() {
    static TerminatedUnicode32DataType instance;
    return instance;
}

TerminatedUnicode32DataType::TerminatedUnicode32DataType(DataTypeManager* dtm)
    : AbstractStringDataType("TerminatedUnicode32", "unicode32", "UNICODE", "UNI", "u",
                             "String (Null Terminated UTF-32 Unicode)",
                             &WideChar32DataType::dataType(), dtm) {
    setStringLayout(StringLayoutEnum::NULL_TERMINATED_UNBOUNDED);
}

DataType* TerminatedUnicode32DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<TerminatedUnicode32DataType*>(this);
    }
    return new TerminatedUnicode32DataType(dtm);
}

} // namespace ghidra
