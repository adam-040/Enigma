#pragma once

#include <cstdint>

namespace ghidra {

class MemBuffer;

class PngResource {
public:
    explicit PngResource(MemBuffer* buf);

    int getLength() const { return length_; }

    static bool isMagic(const uint8_t* data, int length);

private:
    int length_ = 0;

    static constexpr int MAX_CHUNK_SIZE = 10 * 1024 * 1024;

    void readHeader(MemBuffer* buf, int& offset);
    void scanContents(MemBuffer* buf, int& offset);
    int readInt(MemBuffer* buf, int& offset);
    long readLong(MemBuffer* buf, int& offset);
    bool verifyCRC(const uint8_t* type, const uint8_t* data, int dataLen, long crc);
};

} // namespace ghidra
