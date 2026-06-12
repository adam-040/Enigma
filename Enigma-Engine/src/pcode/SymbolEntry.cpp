/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolEntry.cpp
/// \brief Mapping from a HighSymbol to the storage that holds the symbol's value.
#include "ghidra/SymbolEntry.h"
#include "ghidra/AddressSpace.h"

namespace ghidra {

void SymbolEntry::decodeRangeList(Decoder& decoder) {
    int rangelistel = decoder.openElement(ELEM_RANGELIST);
    if (decoder.peekElement() != 0) {
        int rangeel = decoder.openElement(ELEM_RANGE);
        AddressSpace* spc = decoder.readSpace(ATTRIB_SPACE);
        uint64_t offset = decoder.readUnsignedInteger(ATTRIB_FIRST);
        pcaddr = spc ? spc->getAddress(static_cast<int64_t>(offset)) : Address();
        decoder.closeElement(rangeel);
    }
    decoder.closeElement(rangelistel);
}

void SymbolEntry::encodeRangelist(Encoder& encoder) const {
    encoder.openElement(ELEM_RANGELIST);
    if (pcaddr.isExternalAddress()) {
        encoder.closeElement(ELEM_RANGELIST);
        return;
    }
    AddressSpace* space = pcaddr.getAddressSpace();
    uint64_t off = pcaddr.getUnsignedOffset();
    encoder.openElement(ELEM_RANGE);
    encoder.writeSpace(ATTRIB_SPACE, space);
    encoder.writeUnsignedInteger(ATTRIB_FIRST, off);
    encoder.writeUnsignedInteger(ATTRIB_LAST, off);
    encoder.closeElement(ELEM_RANGE);
    encoder.closeElement(ELEM_RANGELIST);
}

} // namespace ghidra
