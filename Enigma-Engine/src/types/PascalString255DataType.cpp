/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PascalString255DataType.cpp
/// \brief String (Pascal 255)
#include "ghidra/PascalString255DataType.h"
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

PascalString255DataType& PascalString255DataType::dataType() {
    static PascalString255DataType instance;
    return instance;
}

PascalString255DataType::PascalString255DataType(DataTypeManager* dtm)
    : AbstractStringDataType("PascalString255", "p_string255", "PASCAL255", "P_STR", "p",
                             "String (Pascal 255)", nullptr, dtm) {
    setStringLayout(StringLayoutEnum::PASCAL_255);
}

DataType* PascalString255DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<PascalString255DataType*>(this);
    }
    return new PascalString255DataType(dtm);
}

} // namespace ghidra
