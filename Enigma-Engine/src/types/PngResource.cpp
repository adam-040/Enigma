#include "ghidra/PngResource.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/InvalidDataTypeException.h"
#include <cstring>

namespace ghidra {

bool PngResource::isMagic(const uint8_t* data, int length) {
    if (length < 8) return false;
    static const uint8_t MAGIC[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    for (int i = 0; i < 8; i++) {
        if (data[i] != MAGIC[i]) return false;
    }
    return true;
}

PngResource::PngResource(MemBuffer* buf) {
    int offset = 0;
    readHeader(buf, offset);
    scanContents(buf, offset);
    length_ = offset;
}

void PngResource::readHeader(MemBuffer* buf, int& offset) {
    long sig = readLong(buf, offset);
    if (sig != 0x89504E470D0A1A0ALL) {
        throw InvalidDataTypeException("Invalid PNG Data");
    }
}

void PngResource::scanContents(MemBuffer* buf, int& offset) {
    int chunkCount = 0;
    uint8_t type[4];
    int saveOffset = offset;
    static const uint8_t IEND[] = { 'I', 'E', 'N', 'D' };

    while (true) {
        int len = readInt(buf, offset);
        if (len < 0 || len > MAX_CHUNK_SIZE) {
            throw InvalidDataTypeException("Invalid PNG Data - too big");
        }
        for (int i = 0; i < 4; i++) {
            type[i] = static_cast<uint8_t>(buf->getByte(offset++));
        }
        for (int i = 0; i < len; i++) {
            buf->getByte(offset);
            offset++;
        }
        long crc = static_cast<long>(readInt(buf, offset)) & 0x00000000FFFFFFFFLL;
        saveOffset = offset;
        ++chunkCount;
        bool isIend = true;
        for (int i = 0; i < 4; i++) {
            if (type[i] != IEND[i]) { isIend = false; break; }
        }
        if (isIend) break;
    }
    offset = saveOffset;
    if (chunkCount == 0) {
        throw InvalidDataTypeException("Invalid PNG Data - no data");
    }
}

int PngResource::readInt(MemBuffer* buf, int& offset) {
    int val = 0;
    for (int i = 0; i < 4; i++) {
        val = (val << 8) | (buf->getByte(offset++) & 0xFF);
    }
    return val;
}

long PngResource::readLong(MemBuffer* buf, int& offset) {
    long val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | (buf->getByte(offset++) & 0xFF);
    }
    return val;
}

bool PngResource::verifyCRC(const uint8_t* type, const uint8_t* data, int dataLen, long crc) {
    return true;
}

} // namespace ghidra
