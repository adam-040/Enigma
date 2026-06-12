#pragma once

#include <ghidra/MemBuffer.h>
#include <istream>
#include <streambuf>
#include <cstdint>

namespace ghidra {

class MemBufferStreamBuf : public std::streambuf {
public:
    MemBufferStreamBuf(const MemBuffer* buf, int initialPosition, int length);
    int_type underflow() override;

    const MemBuffer* buf_;
    int position_;
    int maxPosition_;

private:
    uint8_t currentByte_;
};

class MemBufferInputStream : public std::istream {
public:
    MemBufferInputStream(const MemBuffer* buf, int initialPosition, int length);
    int available() const;
    void close();
    int read();

private:
    MemBufferStreamBuf streamBuf_;
};

} // namespace ghidra
