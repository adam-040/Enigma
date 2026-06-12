#pragma once

#include <cstdint>

namespace ghidra {

class MemBuffer;

class GIFResource {
public:
    explicit GIFResource(MemBuffer* buf);

    int getLength() const { return length_; }

    static bool isMagic(const uint8_t* data, int length);
    static bool isMagic(const MemBuffer* buf);

private:
    int length_ = 0;

    void readHeader(MemBuffer* buf);
    void skipContents(MemBuffer* buf);
    void skipExtension(MemBuffer* buf, int& offset);
    void skipDataBlocks(MemBuffer* buf, int& offset);
    void skipImage(MemBuffer* buf, int& offset);
};

} // namespace ghidra
