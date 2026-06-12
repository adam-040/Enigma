/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/PackedEncode.h"
#include "ghidra/AddressSpace.h"
#include <algorithm>

namespace ghidra {

PackedEncode::PackedEncode() : outStream_(512) {}

void PackedEncode::writeHeader(int header, int id) {
    if (id > 0x1f) {
        header |= HEADEREXTEND_MASK;
        header |= (id >> RAWDATA_BITSPERBYTE);
        int extendByte = (id & RAWDATA_MASK) | RAWDATA_MARKER;
        outStream_.writeByte(header);
        outStream_.writeByte(extendByte);
    } else {
        header |= id;
        outStream_.writeByte(header);
    }
}

void PackedEncode::writeInteger(int typeByte, int64_t val) {
    int lenCode;
    int sa;
    if (val <= 0) {
        if (val == 0) {
            lenCode = 0;
            sa = -1;
        } else {
            lenCode = 10;
            sa = 9 * RAWDATA_BITSPERBYTE;
        }
    } else if (val < 0x800000000LL) {
        if (val < 0x200000LL) {
            if (val < 0x80LL) {
                lenCode = 1;
                sa = 0;
            } else if (val < 0x4000LL) {
                lenCode = 2;
                sa = RAWDATA_BITSPERBYTE;
            } else {
                lenCode = 3;
                sa = 2 * RAWDATA_BITSPERBYTE;
            }
        } else if (val < 0x10000000LL) {
            lenCode = 4;
            sa = 3 * RAWDATA_BITSPERBYTE;
        } else {
            lenCode = 5;
            sa = 4 * RAWDATA_BITSPERBYTE;
        }
    } else if (val < 0x2000000000000LL) {
        if (val < 0x40000000000LL) {
            lenCode = 6;
            sa = 5 * RAWDATA_BITSPERBYTE;
        } else {
            lenCode = 7;
            sa = 6 * RAWDATA_BITSPERBYTE;
        }
    } else {
        if (val < 0x100000000000000LL) {
            lenCode = 8;
            sa = 7 * RAWDATA_BITSPERBYTE;
        } else {
            lenCode = 9;
            sa = 8 * RAWDATA_BITSPERBYTE;
        }
    }
    typeByte |= lenCode;
    outStream_.writeByte(typeByte);
    for (; sa >= 0; sa -= RAWDATA_BITSPERBYTE) {
        int64_t piece = (val >> sa) & RAWDATA_MASK;
        piece |= RAWDATA_MARKER;
        outStream_.writeByte((int)piece);
    }
}

void PackedEncode::openElement(const ElementId& elemId) {
    writeHeader(ELEMENT_START, elemId.id);
}

void PackedEncode::closeElement(const ElementId& elemId) {
    writeHeader(ELEMENT_END, elemId.id);
}

void PackedEncode::writeBool(const AttributeId& attribId, bool val) {
    writeHeader(ATTRIBUTE, attribId.id);
    int typeByte = val ? 0x11 : 0x10;
    outStream_.writeByte(typeByte);
}

void PackedEncode::writeSignedInteger(const AttributeId& attribId, int64_t val) {
    writeHeader(ATTRIBUTE, attribId.id);
    int typeByte;
    int64_t num;
    if (val < 0) {
        typeByte = (TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT);
        num = -val;
    } else {
        typeByte = (TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT);
        num = val;
    }
    writeInteger(typeByte, num);
}

void PackedEncode::writeUnsignedInteger(const AttributeId& attribId, uint64_t val) {
    writeHeader(ATTRIBUTE, attribId.id);
    writeInteger((TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT), (int64_t)val);
}

void PackedEncode::writeString(const AttributeId& attribId, const std::string& val) {
    writeHeader(ATTRIBUTE, attribId.id);
    writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), (int64_t)val.size());
    for (size_t i = 0; i < val.size(); i++) {
        outStream_.writeByte((uint8_t)val[i]);
    }
}

void PackedEncode::writeStringIndexed(const AttributeId& attribId, int index, const std::string& val) {
    writeHeader(ATTRIBUTE, attribId.id + index);
    writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), (int64_t)val.size());
    for (size_t i = 0; i < val.size(); i++) {
        outStream_.writeByte((uint8_t)val[i]);
    }
}

void PackedEncode::writeSpace(const AttributeId& attribId, const AddressSpace* spc) {
    if (!spc) {
        outStream_.writeByte((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
        return;
    }
    writeHeader(ATTRIBUTE, attribId.id);
    int type = spc->getType();
    switch (type) {
        case AddressSpace::TYPE_CONSTANT:
        case AddressSpace::TYPE_RAM:
        case AddressSpace::TYPE_REGISTER:
        case AddressSpace::TYPE_UNIQUE:
        case AddressSpace::TYPE_OTHER:
            writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), (int64_t)spc->getUnique());
            break;
        case AddressSpace::TYPE_VARIABLE:
            outStream_.writeByte((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_JOIN);
            break;
        case AddressSpace::TYPE_STACK:
            outStream_.writeByte((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
            break;
        default:
            outStream_.writeByte((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
            break;
    }
}

void PackedEncode::writeSpace(const AttributeId& attribId, int index, const std::string& /*name*/) {
    writeHeader(ATTRIBUTE, attribId.id);
    writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), (int64_t)index);
}

void PackedEncode::getBytes(std::vector<uint8_t>& dst) const {
    outStream_.writeTo(dst);
}

void PackedEncode::clear() {
    outStream_ = PackedBytes(512);
}

} // namespace ghidra
