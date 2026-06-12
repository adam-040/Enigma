/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/TerminatedStringDataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/StringLayoutEnum.h>

namespace ghidra {

TerminatedStringDataType& TerminatedStringDataType::dataType() {
    static TerminatedStringDataType instance;
    return instance;
}

TerminatedStringDataType::TerminatedStringDataType(DataTypeManager* dtm)
    : AbstractStringDataType("TerminatedCString", "ds", "STRING", "STR", "s",
                             "String (Null Terminated)", &CharDataType::dataType(), dtm) {
    setStringLayout(StringLayoutEnum::NULL_TERMINATED_UNBOUNDED);
}

DataType* TerminatedStringDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<TerminatedStringDataType*>(this);
    }
    return new TerminatedStringDataType(dtm);
}

} // namespace ghidra
