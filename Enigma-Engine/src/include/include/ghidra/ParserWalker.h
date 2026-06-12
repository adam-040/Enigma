#pragma once

#include <ghidra/Address.h>
#include <ghidra/MemBuffer.h>
#include <vector>
#include <memory>

namespace ghidra {

class Constructor;
class SleighLanguage;

class ParserWalker {
public:
    ParserWalker() = default;
    ParserWalker(SleighLanguage* lang, MemBuffer* buf, Address addr)
        : language_(lang), buffer_(buf), address_(addr) {}

    Address getAddress() const { return address_; }
    MemBuffer* getBuffer() const { return buffer_; }
    SleighLanguage* getLanguage() const { return language_; }

    int getLength() const { return length_; }
    void setLength(int len) { length_ = len; }

    int getOffset() const { return offset_; }
    void setOffset(int off) { offset_ = off; }

    int getBit() const { return bit_; }
    void setBit(int b) { bit_ = b; }

private:
    SleighLanguage* language_ = nullptr;
    MemBuffer* buffer_ = nullptr;
    Address address_;
    int length_ = 0;
    int offset_ = 0;
    int bit_ = 0;
};

} // namespace ghidra
