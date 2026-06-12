/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/PackedDecode.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/AddressSpace.h"
#include <ghidra/Decoder.h>
#include <ghidra/PcodeException.h>
#include <cstring>
#include <stdexcept>

namespace ghidra {

PackedDecode::PackedDecode() : addrFactory_(nullptr), spaces_(nullptr), spacesCount_(0),
    startPos_(0), curPos_(0), endPos_(0), bufSize_(0), attributeRead_(true) {}

PackedDecode::PackedDecode(AddressFactory* addrFactory) : addrFactory_(addrFactory),
    spaces_(nullptr), spacesCount_(0), startPos_(0), curPos_(0), endPos_(0), bufSize_(0),
    attributeRead_(true) {
    if (addrFactory_) {
        buildAddrSpaceArray();
    }
}

PackedDecode::~PackedDecode() {
    delete[] spaces_;
}

void PackedDecode::buildAddrSpaceArray() {
    if (!addrFactory_) {
        spaces_ = nullptr;
        spacesCount_ = 0;
        return;
    }
    int count = addrFactory_->getNumAddressSpaces();
    const AddressSpace** tmp = new const AddressSpace*[count];
    for (int i = 0; i < count; i++) tmp[i] = nullptr;
    std::vector<const AddressSpace*> all = addrFactory_->getAllAddressSpaces();
    int max = -1;
    for (size_t i = 0; i < all.size(); i++) {
        const AddressSpace* spc = all[i];
        if (!spc) continue;
        int type = spc->getType();
        if (type != AddressSpace::TYPE_CONSTANT && type != AddressSpace::TYPE_RAM &&
            type != AddressSpace::TYPE_REGISTER && type != AddressSpace::TYPE_UNIQUE &&
            type != AddressSpace::TYPE_OTHER) {
            continue;
        }
        int ind = spc->getUnique();
        if (ind < 0 || ind >= count) continue;
        tmp[ind] = spc;
        if (ind > max) max = ind;
    }
    spacesCount_ = max + 1;
    spaces_ = new const AddressSpace*[spacesCount_];
    for (int i = 0; i < spacesCount_; i++) spaces_[i] = tmp[i];
    delete[] tmp;
}

void PackedDecode::setAddressFactory(AddressFactory* addrFactory) {
    addrFactory_ = addrFactory;
    delete[] spaces_;
    spaces_ = nullptr;
    spacesCount_ = 0;
    if (addrFactory_) buildAddrSpaceArray();
}

void PackedDecode::ingest(const uint8_t* bytes, int len) {
    buf_.assign(bytes, bytes + len);
    bufSize_ = (int)buf_.size();
    startPos_ = 0;
    curPos_ = 0;
    endPos_ = 0;
    attributeRead_ = true;
}

void PackedDecode::ingest(const std::vector<uint8_t>& bytes) {
    buf_ = bytes;
    bufSize_ = (int)buf_.size();
    startPos_ = 0;
    curPos_ = 0;
    endPos_ = 0;
    attributeRead_ = true;
}

int PackedDecode::peekElement() {
    if (endPos_ >= bufSize_) return 0;
    int header1 = buf_[endPos_];
    if ((header1 & PackedDecode::HEADER_MASK) != PackedDecode::ELEMENT_START) return 0;
    int id = header1 & PackedDecode::ELEMENTID_MASK;
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (endPos_ + 1 >= bufSize_) return 0;
        id <<= PackedDecode::RAWDATA_BITSPERBYTE;
        id |= (buf_[endPos_ + 1] & PackedDecode::RAWDATA_MASK);
    }
    return id;
}

int PackedDecode::readHeaderId(int pos, int& outId) {
    if (pos >= bufSize_) return -1;
    int header1 = buf_[pos];
    outId = header1 & PackedDecode::ELEMENTID_MASK;
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (pos + 1 >= bufSize_) return -1;
        outId <<= PackedDecode::RAWDATA_BITSPERBYTE;
        outId |= (buf_[pos + 1] & PackedDecode::RAWDATA_MASK);
        return 2;
    }
    return 1;
}

int64_t PackedDecode::readIntegerBytes(int len) {
    int64_t res = 0;
    for (int i = 0; i < len; i++) {
        res <<= PackedDecode::RAWDATA_BITSPERBYTE;
        if (curPos_ < bufSize_) {
            res |= (buf_[curPos_++] & PackedDecode::RAWDATA_MASK);
        }
    }
    return res;
}

int PackedDecode::openElement() {
    if (endPos_ >= bufSize_) return 0;
    int header1 = buf_[endPos_];
    if ((header1 & PackedDecode::HEADER_MASK) != PackedDecode::ELEMENT_START) return 0;
    endPos_++;
    int id = header1 & PackedDecode::ELEMENTID_MASK;
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (endPos_ >= bufSize_) return 0;
        id <<= PackedDecode::RAWDATA_BITSPERBYTE;
        id |= (buf_[endPos_++] & PackedDecode::RAWDATA_MASK);
    }
    startPos_ = endPos_;
    curPos_ = endPos_;

    while (curPos_ < bufSize_) {
        int h = buf_[curPos_];
        if ((h & PackedDecode::HEADER_MASK) != PackedDecode::ATTRIBUTE) break;
        skipAttributeAt(curPos_);
    }
    endPos_ = curPos_;
    curPos_ = startPos_;
    attributeRead_ = true;
    return id;
}

int PackedDecode::openElement(const ElementId& elemId) {
    int id = openElement();
    if (id != elemId.id) {
        throw DecoderException("Element id mismatch");
    }
    return id;
}

void PackedDecode::closeElement() {
    if (endPos_ >= bufSize_) return;
    int header1 = buf_[endPos_++];
    if ((header1 & PackedDecode::HEADER_MASK) != PackedDecode::ELEMENT_END) {
        throw DecoderException("Expecting element close");
    }
}

void PackedDecode::closeElement(int /*id*/) {
    closeElement();
}

int PackedDecode::skipAttributeAt(int pos) {
    int p = pos;
    if (p >= bufSize_) return p - pos;
    int header1 = buf_[p++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (p >= bufSize_) return p - pos;
        p++;
    }
    if (p >= bufSize_) return p - pos;
    int typeByte = buf_[p++];
    int attribType = (typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT;
    if (attribType == PackedDecode::TYPECODE_BOOLEAN ||
        attribType == PackedDecode::TYPECODE_SPECIALSPACE) {
        curPos_ = p;
        return p - pos;
    }
    int length = typeByte & PackedDecode::LENGTHCODE_MASK;
    if (attribType == PackedDecode::TYPECODE_STRING) {
        int savedCur = curPos_;
        curPos_ = p;
        int64_t slen = readIntegerBytes(length);
        length = (int)slen;
        p = curPos_;
        curPos_ = savedCur;
    }
    p += length;
    curPos_ = p;
    return p - pos;
}

int PackedDecode::getNextAttributeId() {
    if (!attributeRead_) {
        skipAttributeAt(curPos_);
    }
    if (curPos_ >= bufSize_) return 0;
    int header1 = buf_[curPos_];
    if ((header1 & PackedDecode::HEADER_MASK) != PackedDecode::ATTRIBUTE) {
        attributeRead_ = true;
        return 0;
    }
    int id = header1 & PackedDecode::ELEMENTID_MASK;
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        int dummy;
        int consumed = readHeaderId(curPos_, dummy);
        (void)consumed;
    }
    attributeRead_ = false;
    return id;
}

bool PackedDecode::readBool() {
    if (curPos_ >= bufSize_) throw DecoderException("readBool underflow");
    int header1 = buf_[curPos_++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (curPos_ >= bufSize_) throw DecoderException("readBool underflow");
        curPos_++;
    }
    if (curPos_ >= bufSize_) throw DecoderException("readBool underflow");
    int typeByte = buf_[curPos_++];
    if (((typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT) != PackedDecode::TYPECODE_BOOLEAN) {
        throw DecoderException("Expecting boolean");
    }
    attributeRead_ = true;
    return ((typeByte & PackedDecode::LENGTHCODE_MASK) != 0);
}

bool PackedDecode::readBool(int /*id*/) {
    return readBool();
}

bool PackedDecode::readBool(AttributeId /*id*/) {
    return readBool();
}

int64_t PackedDecode::readSignedInteger() {
    if (curPos_ >= bufSize_) throw DecoderException("readSignedInteger underflow");
    int header1 = buf_[curPos_++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (curPos_ >= bufSize_) throw DecoderException("readSignedInteger underflow");
        curPos_++;
    }
    if (curPos_ >= bufSize_) throw DecoderException("readSignedInteger underflow");
    int typeByte = buf_[curPos_++];
    int typeCode = (typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT;
    int64_t res;
    if (typeCode == PackedDecode::TYPECODE_SIGNEDINT_POSITIVE) {
        res = readIntegerBytes(typeByte & PackedDecode::LENGTHCODE_MASK);
    } else if (typeCode == PackedDecode::TYPECODE_SIGNEDINT_NEGATIVE) {
        res = readIntegerBytes(typeByte & PackedDecode::LENGTHCODE_MASK);
        res = -res;
    } else {
        throw DecoderException("Expecting signed integer");
    }
    attributeRead_ = true;
    return res;
}

int64_t PackedDecode::readSignedInteger(int /*id*/) {
    return readSignedInteger();
}

int64_t PackedDecode::readSignedInteger(AttributeId /*id*/) {
    return readSignedInteger();
}

uint64_t PackedDecode::readUnsignedInteger() {
    if (curPos_ >= bufSize_) throw DecoderException("readUnsignedInteger underflow");
    int header1 = buf_[curPos_++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (curPos_ >= bufSize_) throw DecoderException("readUnsignedInteger underflow");
        curPos_++;
    }
    if (curPos_ >= bufSize_) throw DecoderException("readUnsignedInteger underflow");
    int typeByte = buf_[curPos_++];
    int typeCode = (typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT;
    uint64_t res;
    if (typeCode == PackedDecode::TYPECODE_UNSIGNEDINT) {
        res = (uint64_t)readIntegerBytes(typeByte & PackedDecode::LENGTHCODE_MASK);
    } else {
        throw DecoderException("Expecting unsigned integer");
    }
    attributeRead_ = true;
    return res;
}

uint64_t PackedDecode::readUnsignedInteger(int /*id*/) {
    return readUnsignedInteger();
}

uint64_t PackedDecode::readUnsignedInteger(AttributeId /*id*/) {
    return readUnsignedInteger();
}

std::string PackedDecode::readString() {
    if (curPos_ >= bufSize_) throw DecoderException("readString underflow");
    int header1 = buf_[curPos_++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (curPos_ >= bufSize_) throw DecoderException("readString underflow");
        curPos_++;
    }
    if (curPos_ >= bufSize_) throw DecoderException("readString underflow");
    int typeByte = buf_[curPos_++];
    int typeCode = (typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT;
    if (typeCode != PackedDecode::TYPECODE_STRING) {
        throw DecoderException("Expecting string");
    }
    int length = (int)readIntegerBytes(typeByte & PackedDecode::LENGTHCODE_MASK);
    if (curPos_ + length > bufSize_) {
        throw DecoderException("readString overflow");
    }
    std::string res((const char*)&buf_[curPos_], length);
    curPos_ += length;
    attributeRead_ = true;
    return res;
}

std::string PackedDecode::readString(int /*id*/) {
    return readString();
}

std::string PackedDecode::readString(AttributeId /*id*/) {
    return readString();
}

AddressSpace* PackedDecode::readSpace() {
    if (curPos_ >= bufSize_) throw DecoderException("readSpace underflow");
    int header1 = buf_[curPos_++];
    if ((header1 & PackedDecode::HEADEREXTEND_MASK) != 0) {
        if (curPos_ >= bufSize_) throw DecoderException("readSpace underflow");
        curPos_++;
    }
    if (curPos_ >= bufSize_) throw DecoderException("readSpace underflow");
    int typeByte = buf_[curPos_++];
    int typeCode = (typeByte & 0xFF) >> PackedDecode::TYPECODE_SHIFT;
    AddressSpace* spc = nullptr;
    if (typeCode == PackedDecode::TYPECODE_ADDRESSSPACE) {
        int64_t idx = readIntegerBytes(typeByte & PackedDecode::LENGTHCODE_MASK);
        if (idx >= 0 && idx < spacesCount_) {
            spc = const_cast<AddressSpace*>(spaces_[idx]);
        }
        if (spc == nullptr) throw DecoderException("Unknown address space");
    } else if (typeCode == PackedDecode::TYPECODE_SPECIALSPACE) {
        if (!addrFactory_) throw DecoderException("No address factory");
        int sc = typeByte & PackedDecode::LENGTHCODE_MASK;
        if (sc == PackedDecode::SPECIALSPACE_STACK) {
            spc = const_cast<AddressSpace*>(addrFactory_->getStackSpace());
        } else if (sc == PackedDecode::SPECIALSPACE_JOIN) {
            spc = nullptr;
        }
        if (spc == nullptr) throw DecoderException("Cannot marshal special space");
    } else {
        throw DecoderException("Expecting space attribute");
    }
    attributeRead_ = true;
    return spc;
}

AddressSpace* PackedDecode::readSpace(const AttributeId& /*attribId*/) {
    return readSpace();
}

AddressSpace* PackedDecode::readSpace(int /*id*/) {
    return readSpace();
}

void PackedDecode::skipElement() {
    int depth = 1;
    while (depth > 0 && curPos_ < bufSize_) {
        int tag = buf_[curPos_];
        if ((tag & 0x80) == 0) {
            int len = tag & 0x7f;
            curPos_ += 1 + len;
        } else if (tag == 0xFF) {
            depth--;
            curPos_++;
        } else if (tag == 0xFE) {
            depth++;
            curPos_++;
        } else {
            curPos_++;
        }
    }
    endPos_ = curPos_;
}

void PackedDecode::rewindAttributes() {
    curPos_ = startPos_;
    attributeRead_ = true;
}

uint8_t PackedDecode::readByte() {
    if (curPos_ >= bufSize_) throw DecoderException("readByte underflow");
    return buf_[curPos_++];
}

std::vector<uint8_t> PackedDecode::readBytes(int count) {
    if (curPos_ + count > bufSize_) throw DecoderException("readBytes overflow");
    std::vector<uint8_t> res(buf_.begin() + curPos_, buf_.begin() + curPos_ + count);
    curPos_ += count;
    return res;
}

} // namespace ghidra
