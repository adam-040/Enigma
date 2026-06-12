/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeSymbol.cpp
/// \brief A symbol representing a DataType.
#include "ghidra/DataTypeSymbol.h"
#include "ghidra/pcode/HighFunction.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/DynamicEntry.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {

DataTypeSymbol::DataTypeSymbol(int64_t uniqueId, const std::string& nm, TypeDef* type,
                               pcode::HighFunction* func, const Address& a, int64_t h)
    : HighSymbol(uniqueId, nm, type, func), dt(type), storageSize(0), addr(a), hash(h) {
    if (type != nullptr) {
        storageSize = type->getLength();
    }
}

int DataTypeSymbol::getSize() const {
    if (dt == nullptr) return 0;
    return dt->getLength();
}

void DataTypeSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encoder.writeUnsignedInteger(ATTRIB_ID, static_cast<uint64_t>(getId()));
    encoder.writeString(ATTRIB_NAME, name);
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

void DataTypeSymbol::decode(Decoder& decoder) {
    int symel = decoder.openElement(ELEM_SYMBOL);
    (void)symel;
    decodeHeader(decoder);
    decoder.closeElement(symel);
}

void DataTypeSymbol::saveXml(Encoder& /*encoder*/, int /*sourceType*/) const {
}

}  // namespace ghidra
