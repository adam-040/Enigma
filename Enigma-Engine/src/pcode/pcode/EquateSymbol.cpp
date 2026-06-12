/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateSymbol.cpp
/// \brief High-level equate symbol.
#include "ghidra/pcode/EquateSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/DynamicEntry.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {
namespace pcode {

EquateSymbol::EquateSymbol(HighFunction* func)
    : HighSymbol(func), value(0), convert(FORMAT_DEFAULT) {
    setCategory(1, -1);
}

EquateSymbol::EquateSymbol(int64_t uniqueId, const std::string& nm, int64_t val,
                           HighFunction* func, const Address& addr, int64_t hash)
    : HighSymbol(uniqueId, nm, nullptr, func), value(val), convert(FORMAT_DEFAULT) {
    setCategory(1, -1);
    addMapEntry(new DynamicEntry(this, addr, hash));
}

EquateSymbol::EquateSymbol(int64_t uniqueId, int conv, int64_t val,
                           HighFunction* func, const Address& addr, int64_t hash)
    : HighSymbol(uniqueId, std::string(), nullptr, func), value(val), convert(conv) {
    setCategory(1, -1);
    addMapEntry(new DynamicEntry(this, addr, hash));
}

void EquateSymbol::decode(Decoder& decoder) {
    int symel = decoder.openElement(ELEM_SYMBOL);
    (void)symel;
    decodeHeader(decoder);
    convert = FORMAT_DEFAULT;
    std::string formString;
    for (;;) {
        int attribId = decoder.getNextAttributeId();
        if (attribId == 0) break;
        if (attribId == ATTRIB_FORMAT.id) {
            formString = decoder.readString(ATTRIB_FORMAT);
        }
    }
    if (!formString.empty()) {
        convert = getFormatStringValue(formString);
    }
    int valel = decoder.openElement(ELEM_VALUE);
    (void)valel;
    value = static_cast<int64_t>(decoder.readUnsignedInteger(ATTRIB_CONTENT));
    decoder.closeElement(valel);
    decoder.closeElement(symel);
}

void EquateSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encodeHeader(encoder);
    if (convert != 0) {
        encoder.writeString(ATTRIB_FORMAT, getIntegerFormatString(convert));
    }
    encoder.openElement(ELEM_VALUE);
    encoder.writeUnsignedInteger(ATTRIB_CONTENT, static_cast<uint64_t>(value));
    encoder.closeElement(ELEM_VALUE);
    encoder.closeElement(ELEM_SYMBOL);
}

std::string EquateSymbol::getIntegerFormatString(int convert) {
    switch (convert) {
        case FORMAT_HEX: return "hex";
        case FORMAT_DEC: return "dec";
        case FORMAT_OCT: return "oct";
        case FORMAT_BIN: return "bin";
        case FORMAT_CHAR: return "char";
        case FORMAT_FLOAT: return "float";
        case FORMAT_DOUBLE: return "double";
    }
    return "_";
}

int EquateSymbol::getFormatStringValue(const std::string& format) {
    if (format == "hex") return FORMAT_HEX;
    if (format == "dec") return FORMAT_DEC;
    if (format == "oct") return FORMAT_OCT;
    if (format == "bin") return FORMAT_BIN;
    if (format == "char") return FORMAT_CHAR;
    if (format == "float") return FORMAT_FLOAT;
    if (format == "double") return FORMAT_DOUBLE;
    return FORMAT_DEFAULT;
}

int EquateSymbol::convertName(const std::string& nm, int64_t /*val*/) {
    if (nm.empty()) return FORMAT_DEFAULT;
    std::size_t pos = 0;
    char first = nm[pos++];
    if (first == '-') {
        if (nm.length() <= pos) return FORMAT_DEFAULT;
        first = nm[pos++];
    }
    switch (first) {
        case '\'':
        case '"':
            return FORMAT_CHAR;
        case '0':
            if (nm.length() >= pos + 1 && nm[pos] == 'x') return FORMAT_HEX;
            break;
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9':
            break;
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            if (nm.length() >= 3 && nm[2] == 'h') {
                char second = nm[1];
                if ((second >= '0' && second <= '9') || (second >= 'A' && second <= 'F')) {
                    return FORMAT_CHAR;
                }
            }
            return FORMAT_DEFAULT;
        default:
            return FORMAT_DEFAULT;
    }
    if (nm.empty()) return FORMAT_DEFAULT;
    switch (nm.back()) {
        case 'b': return FORMAT_BIN;
        case 'o': return FORMAT_OCT;
        case '\'':
        case '"':
        case 'h': return FORMAT_CHAR;
    }
    return FORMAT_DEC;
}

}  // namespace pcode
}  // namespace ghidra
