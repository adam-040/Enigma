#include "ghidra/GIFResource.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/InvalidDataTypeException.h"
#include <cstring>
#include <algorithm>

namespace ghidra {

bool GIFResource::isMagic(const uint8_t* data, int length) {
    if (length < 6) return false;
    static const uint8_t MAGIC_87[] = { 'G', 'I', 'F', '8', '7', 'a' };
    static const uint8_t MAGIC_89[] = { 'G', 'I', 'F', '8', '9', 'a' };
    bool match87 = true, match89 = true;
    for (int i = 0; i < 6; i++) {
        if (data[i] != MAGIC_87[i]) match87 = false;
        if (data[i] != MAGIC_89[i]) match89 = false;
    }
    return match87 || match89;
}

bool GIFResource::isMagic(const MemBuffer* buf) {
    try {
        uint8_t data[6];
        for (int i = 0; i < 6; i++) {
            data[i] = static_cast<uint8_t>(buf->getByte(i));
        }
        return isMagic(data, 6);
    } catch (...) {
        return false;
    }
}

GIFResource::GIFResource(MemBuffer* buf) {
    readHeader(buf);
    skipContents(buf);
}

void GIFResource::readHeader(MemBuffer* buf) {
    if (!isMagic(buf)) {
        throw InvalidDataTypeException("Invalid GIF Data");
    }
    length_ = 6;
    length_ += 2;
    length_ += 2;
    int flags = buf->getByte(length_) & 0xFF;
    length_ += 1;
    bool globalColorTableFlag = (flags & 0x80) != 0;
    int globalColorTableSize = 2 << (flags & 7);
    length_ += 1;
    length_ += 1;
    if (globalColorTableFlag) {
        length_ += 3 * globalColorTableSize;
    }
}

void GIFResource::skipContents(MemBuffer* buf) {
    int controlByte = buf->getByte(length_) & 0xFF;
    length_++;
    while (controlByte != 0x3B) {
        if (controlByte == 0x2C) {
            skipImage(buf, length_);
        } else if (controlByte == 0x21) {
            skipExtension(buf, length_);
        } else {
            throw InvalidDataTypeException("Invalid GIF Data");
        }
        controlByte = buf->getByte(length_) & 0xFF;
        length_++;
    }
}

void GIFResource::skipExtension(MemBuffer* buf, int& offset) {
    offset += 1;
    skipDataBlocks(buf, offset);
}

void GIFResource::skipDataBlocks(MemBuffer* buf, int& offset) {
    int blockSize = buf->getByte(offset) & 0xFF;
    offset += 1;
    while (blockSize > 0) {
        offset += blockSize;
        blockSize = buf->getByte(offset) & 0xFF;
        offset += 1;
    }
}

void GIFResource::skipImage(MemBuffer* buf, int& offset) {
    offset += 8;
    int flags = buf->getByte(offset) & 0xFF;
    offset += 1;
    bool localColorTableFlag = (flags & 0x80) != 0;
    int localColorTableSize = 2 << (flags & 7);
    if (localColorTableFlag) {
        offset += 3 * localColorTableSize;
    }
    offset += 1;
    skipDataBlocks(buf, offset);
}

} // namespace ghidra
