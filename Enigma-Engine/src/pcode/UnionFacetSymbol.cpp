/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnionFacetSymbol.cpp
/// \brief HighSymbol directing the decompiler to use a specific field of a union.
#include "ghidra/UnionFacetSymbol.h"
#include "ghidra/Union.h"
#include "ghidra/TypeDef.h"
#include "ghidra/Pointer.h"
#include "ghidra/Address.h"
#include <sstream>
#include <stdexcept>

namespace ghidra {

UnionFacetSymbol::UnionFacetSymbol(int64_t uniqueId, const std::string& nm, DataType* dt)
    : id(uniqueId), name(nm), type(dt), storageAddr(), fieldNumber(0), isAddrBased_(false) {
    fieldNumber = extractFieldNumber(nm);
    isAddrBased_ = extractAddressBased(nm);
}

int UnionFacetSymbol::getSize() const {
    return type ? type->getLength() : 0;
}

void UnionFacetSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_FACETSYMBOL);
    encoder.writeSignedInteger(ATTRIB_ID, id);
    encoder.writeString(ATTRIB_NAME, name);
    encoder.writeSignedInteger(ATTRIB_FIELD, fieldNumber);
    encoder.writeBool(ATTRIB_ADDRTIED, isAddrBased_);
    encoder.closeElement(ELEM_FACETSYMBOL);
}

std::string UnionFacetSymbol::buildSymbolName(int fldNum, const Address& addr, bool isAddr) {
    std::ostringstream buffer;
    buffer << BASENAME;
    if (isAddr) {
        buffer << 'a';
    }
    buffer << (fldNum + 1) << '_';
    buffer << std::hex << addr.getOffset();
    return buffer.str();
}

int UnionFacetSymbol::extractFieldNumber(const std::string& nm) {
    auto pos = nm.find(BASENAME);
    if (pos == std::string::npos) {
        return -1;
    }
    pos += BASENAME.length();
    if (nm.length() > pos && nm[pos] == 'a') {
        pos = pos + 1;
    }
    auto endpos = nm.find('_', pos);
    if (endpos == std::string::npos) {
        return -1;
    }
    try {
        return std::stoi(nm.substr(pos, endpos - pos), nullptr, 10) - 1;
    } catch (const std::exception&) {
        return -1;
    }
}

bool UnionFacetSymbol::extractAddressBased(const std::string& nm) {
    auto pos = nm.find(BASENAME);
    if (pos == std::string::npos || nm.length() <= pos + BASENAME.length()) {
        return false;
    }
    return nm[pos + BASENAME.length()] == 'a';
}

bool UnionFacetSymbol::isUnionType(const DataType* dt) {
    if (dt == nullptr) return false;
    if (const TypeDef* td = dynamic_cast<const TypeDef*>(dt)) {
        return isUnionType(td->getBaseDataType());
    }
    if (const Pointer* ptr = dynamic_cast<const Pointer*>(dt)) {
        const DataType* pointee = ptr->getDataType();
        if (pointee == nullptr) return false;
        if (const TypeDef* td = dynamic_cast<const TypeDef*>(pointee)) {
            return dynamic_cast<const Union*>(td->getBaseDataType()) != nullptr;
        }
        return dynamic_cast<const Union*>(pointee) != nullptr;
    }
    return dynamic_cast<const Union*>(dt) != nullptr;
}


} // namespace ghidra
