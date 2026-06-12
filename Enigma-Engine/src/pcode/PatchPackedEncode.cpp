/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PatchPackedEncode.cpp
/// \brief PackedEncode that supports in-place patching of integer attributes
/// Translated from: ghidra.program.model.pcode.PatchPackedEncode
#include "ghidra/PatchPackedEncode.h"
#include <ostream>
#include <sstream>

namespace ghidra {

void PatchPackedEncode::openElement(const ElementId& elemId) { PackedEncode::openElement(elemId); }
void PatchPackedEncode::closeElement(const ElementId& elemId) { PackedEncode::closeElement(elemId); }
void PatchPackedEncode::writeBool(const AttributeId& attribId, bool val) { PackedEncode::writeBool(attribId, val); }
void PatchPackedEncode::writeSignedInteger(const AttributeId& attribId, int64_t val) { PackedEncode::writeSignedInteger(attribId, val); }
void PatchPackedEncode::writeUnsignedInteger(const AttributeId& attribId, uint64_t val) { PackedEncode::writeUnsignedInteger(attribId, val); }
void PatchPackedEncode::writeString(const AttributeId& attribId, const std::string& val) { PackedEncode::writeString(attribId, val); }
void PatchPackedEncode::writeSpace(const AttributeId& attribId, const AddressSpace* spc) { PackedEncode::writeSpace(attribId, spc); }

int skipOpenHelper(PackedBytes& editStream, int pos) {
    int val = editStream.getByte(pos) & (PackedEncode::HEADER_MASK | PackedEncode::HEADEREXTEND_MASK);
    if (val == PackedEncode::ELEMENT_START) {
        return pos + 1;
    }
    if (val == (PackedEncode::ELEMENT_START | PackedEncode::HEADEREXTEND_MASK)) {
        return pos + 2;
    }
    return -1;
}

int64_t readIntegerHelper(PackedBytes& editStream, int pos, int len) {
    int64_t res = 0;
    while (len > 0) {
        res <<= PackedEncode::RAWDATA_BITSPERBYTE;
        res |= (editStream.getByte(pos) & PackedEncode::RAWDATA_MASK);
        pos += 1;
        len -= 1;
    }
    return res;
}

void PatchPackedEncode::writeSpaceId(const AttributeId& attribId, int64_t spaceId) {
    writeHeader(ATTRIBUTE, attribId.id);
    int uniqueId = (int)spaceId >> AddressSpace::ID_UNIQUE_SHIFT;
    writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), uniqueId);
}

bool PatchPackedEncode::patchIntegerAttribute(int pos, const AttributeId& attribId, int64_t val) {
    int typeByte;
    int length;

    pos = skipOpenHelper(outStream_, pos);
    if (pos < 0) {
        return false;
    }
    for (;;) {
        int header1 = outStream_.getByte(pos);
        if ((header1 & HEADER_MASK) != ATTRIBUTE) {
            return false;
        }
        pos += 1;
        int curid = header1 & ELEMENTID_MASK;
        if ((header1 & HEADEREXTEND_MASK) != 0) {
            curid <<= RAWDATA_BITSPERBYTE;
            curid |= outStream_.getByte(pos) & RAWDATA_MASK;
            pos += 1;
        }
        typeByte = outStream_.getByte(pos) & 0xff;
        pos += 1;
        int attribType = typeByte >> TYPECODE_SHIFT;
        if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE) {
            continue;
        }
        length = typeByte & LENGTHCODE_MASK;
        if (attribType == TYPECODE_STRING) {
            length = (int)readIntegerHelper(outStream_, pos, length);
        }
        if (attribId.id == curid) {
            break;
        }
        pos += length;
    }

    int newLenCode;
    int sa;
    if (val <= 0) {
        if (val == 0) {
            newLenCode = 0;
            sa = -1;
        } else {
            newLenCode = 10;
            sa = 9 * RAWDATA_BITSPERBYTE;
        }
    } else if (val < 0x800000000LL) {
        if (val < 0x200000LL) {
            if (val < 0x80LL) { newLenCode = 1; sa = 0; }
            else if (val < 0x4000LL) { newLenCode = 2; sa = RAWDATA_BITSPERBYTE; }
            else { newLenCode = 3; sa = 2 * RAWDATA_BITSPERBYTE; }
        } else if (val < 0x10000000LL) {
            newLenCode = 4; sa = 3 * RAWDATA_BITSPERBYTE;
        } else {
            newLenCode = 5; sa = 4 * RAWDATA_BITSPERBYTE;
        }
    } else if (val < 0x2000000000000LL) {
        if (val < 0x40000000000LL) { newLenCode = 6; sa = 5 * RAWDATA_BITSPERBYTE; }
        else { newLenCode = 7; sa = 6 * RAWDATA_BITSPERBYTE; }
    } else {
        if (val < 0x100000000000000LL) { newLenCode = 8; sa = 7 * RAWDATA_BITSPERBYTE; }
        else { newLenCode = 9; sa = 8 * RAWDATA_BITSPERBYTE; }
    }

    int oldBytesNeeded = length;
    int newBytesNeeded = newLenCode;
    if (newBytesNeeded < oldBytesNeeded) {
        for (int i = newBytesNeeded; i < oldBytesNeeded; i++) {
            if (pos + i < outStream_.size()) {
                outStream_.insertByte(pos + i, 0x80);
            }
        }
    } else if (newBytesNeeded > oldBytesNeeded) {
        for (int i = 0; i < (newBytesNeeded - oldBytesNeeded); i++) {
            outStream_.insertByte(pos + oldBytesNeeded, 0x80);
        }
    }
    if (newBytesNeeded == 0) {
        return true;
    }
    for (int shift = 9 * RAWDATA_BITSPERBYTE; shift >= 0; shift -= RAWDATA_BITSPERBYTE) {
        if (sa < 0) {
            outStream_.insertByte(pos, 0x80);
        } else {
            int64_t piece = (val >> sa) & RAWDATA_MASK;
            piece |= RAWDATA_MARKER;
            outStream_.insertByte(pos, (int)piece);
            sa -= RAWDATA_BITSPERBYTE;
        }
        pos += 1;
    }
    return true;
}

void PatchPackedEncode::clear() {
    outStream_ = PackedBytes(512);
}

bool PatchPackedEncode::isEmpty() const {
    return outStream_.size() == 0;
}

void PatchPackedEncode::writeTo(std::ostream& stream) {
    std::vector<uint8_t> bytes;
    outStream_.writeTo(bytes);
    stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

} // namespace ghidra
