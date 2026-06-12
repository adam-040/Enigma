/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file JumpTable.cpp
/// \brief JumpTable implementation.
#include "ghidra/pcode/JumpTable.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {
namespace pcode {

void JumpTable::LoadTable::decode(::ghidra::Decoder& decoder) {
    int el = decoder.openElement(ELEM_LOADTABLE);
    size = static_cast<int>(decoder.readSignedInteger(ATTRIB_SIZE));
    num = static_cast<int>(decoder.readSignedInteger(ATTRIB_NUM));
    addr = Address::decodeFromAttributes(decoder);
    decoder.closeElement(el);
}

void JumpTable::BasicOverride::encode(::ghidra::Encoder& encoder) const {
    encoder.openElement(ELEM_BASICOVERRIDE);
    for (const Address& a : destlist) {
        encoder.openElement(ELEM_DEST);
        Address::encodeAttributes(encoder, a);
        encoder.closeElement(ELEM_DEST);
    }
    encoder.closeElement(ELEM_BASICOVERRIDE);
}

JumpTable::JumpTable()
    : opAddress(), override(nullptr), displayFormat(0) {}

JumpTable::JumpTable(const Address& addr, const std::vector<Address>& destlist,
                     bool useOverride, int format)
    : opAddress(addr), override(nullptr), displayFormat(format) {
    if (useOverride) {
        override = std::make_unique<BasicOverride>(destlist);
    } else {
        addressTable = destlist;
    }
}

void JumpTable::decode(::ghidra::Decoder& decoder) {
    int el = decoder.openElement(ELEM_JUMPTABLE);
    if (decoder.getNextAttributeId() == ATTRIB_FORMAT.id) {
        displayFormat = static_cast<int>(decoder.readUnsignedInteger());
    }
    if (decoder.peekElement() == 0) {
        decoder.closeElement(el);
        return;
    }
    std::vector<Address> aTable;
    std::vector<int> lTable;
    std::vector<LoadTable> ldTable;
    opAddress = Address::decodeFromAttributes(decoder);
    for (;;) {
        int subel = decoder.peekElement();
        if (subel == 0) break;
        if (subel == ELEM_DEST.id) {
            decoder.openElement();
            Address caseAddr = Address::decodeFromAttributes(decoder);
            aTable.push_back(caseAddr);
            decoder.rewindAttributes();
            for (;;) {
                int attribId = decoder.getNextAttributeId();
                if (attribId == 0) break;
                if (attribId == ATTRIB_LABEL.id) {
                    int label = static_cast<int>(decoder.readUnsignedInteger());
                    lTable.push_back(label);
                }
            }
            decoder.closeElement(subel);
        } else if (subel == ELEM_LOADTABLE.id) {
            LoadTable loadtable;
            loadtable.decode(decoder);
            ldTable.push_back(loadtable);
        } else {
            decoder.skipElement();
        }
    }
    addressTable = std::move(aTable);
    labelTable = std::move(lTable);
    loadTable = std::move(ldTable);
    decoder.closeElement(el);
}

void JumpTable::encode(::ghidra::Encoder& encoder) const {
    encoder.openElement(ELEM_JUMPTABLE);
    if (displayFormat != 0) {
        encoder.writeUnsignedInteger(ATTRIB_FORMAT, static_cast<uint64_t>(displayFormat));
    }
    Address::encode(encoder, opAddress);
    for (const Address& a : addressTable) {
        encoder.openElement(ELEM_DEST);
        Address::encodeAttributes(encoder, a);
        encoder.closeElement(ELEM_DEST);
    }
    if (override) {
        override->encode(encoder);
    }
    encoder.closeElement(ELEM_JUMPTABLE);
}

}  // namespace pcode
}  // namespace ghidra
